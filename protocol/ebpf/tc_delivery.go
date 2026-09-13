//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

func (d *tcDataPlane) createTCDeliveryLink() (*tcDeliveryLink, error) {
	backend := d.backend
	priority := d.priority
	linkByName := d.linkByName()
	redirectName, deliveryName, err := nextTCVethNames()
	if err != nil {
		return nil, err
	}
	attributes := netlink.NewLinkAttrs()
	attributes.Name = redirectName
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: deliveryName}
	if err = netlink.LinkAdd(veth); err != nil {
		return nil, E.Cause(err, "create TC eBPF delivery link")
	}
	// The pair exists from here on, so it belongs to the delivery link before
	// anything else can fail. Close deletes whichever end it holds, and the one
	// LinkAdd was given is enough: it carries the name, which is what LinkDel
	// resolves the index from. Waiting for the lookup below to fill this in
	// would leave the pair behind if that lookup is what failed.
	delivery := &tcDeliveryLink{redirectName: redirectName, deliveryName: deliveryName, redirect: veth}
	cleanup := func(startErr error) (*tcDeliveryLink, error) {
		closeErr := delivery.Close()
		if !delivery.IsClosed() {
			return delivery, E.Errors(startErr, closeErr)
		}
		return nil, E.Errors(startErr, closeErr)
	}
	redirect, err := linkByName(redirectName)
	if err != nil {
		return cleanup(E.Cause(err, "find TC eBPF redirect link"))
	}
	delivery.redirect = redirect
	peer, err := linkByName(deliveryName)
	if err != nil {
		return cleanup(E.Cause(err, "find TC eBPF delivery peer"))
	}
	delivery.delivery = peer
	for _, link := range []netlink.Link{delivery.redirect, delivery.delivery} {
		if err = netlink.LinkSetUp(link); err != nil {
			return cleanup(E.Cause(err, "bring up TC eBPF delivery link ", link.Attrs().Name))
		}
	}
	for _, setting := range []struct {
		name  string
		value string
	}{
		{"rp_filter", "0"},
		{"accept_local", "1"},
	} {
		state, changed, settingErr := setTCInterfaceSysctl(deliveryName, setting.name, setting.value)
		if settingErr != nil {
			return cleanup(settingErr)
		}
		if changed {
			delivery.sysctls = appendTCSysctlStates(delivery.sysctls, []tcSysctlState{state})
		}
	}
	aggregateStates, err := clearTCAggregateRPFilter(deliveryName)
	delivery.globalSysctls = appendTCSysctlStates(delivery.globalSysctls, aggregateStates)
	if err != nil {
		return cleanup(err)
	}
	if err = ensureTCClsact(delivery.delivery); err != nil {
		return cleanup(err)
	}
	delivery.filter, err = attachTCFilter(
		delivery.delivery,
		netlink.HANDLE_MIN_INGRESS,
		backend.DeliveryIngressProgramFD(),
		"sb_tc_deliver",
		tcDeliveryFilterHandle,
		priority,
	)
	if err != nil {
		return cleanup(err)
	}
	deliveryHardwareAddress := delivery.delivery.Attrs().HardwareAddr
	if len(deliveryHardwareAddress) != len(commonEBPF.MACAddress{}) {
		return cleanup(E.New("TC eBPF delivery interface has invalid hardware address"))
	}
	var deliveryMAC commonEBPF.MACAddress
	copy(deliveryMAC[:], deliveryHardwareAddress)
	if err = backend.SetDeliveryInterface(uint32(delivery.redirect.Attrs().Index), deliveryMAC); err != nil {
		return cleanup(err)
	}
	return delivery, nil
}

func nextTCVethNames() (string, string, error) {
	for range 1024 {
		sequence := tcVethSequence.Add(1)
		suffix := fmt.Sprintf("%04x%04x", uint32(os.Getpid())&0xffff, sequence&0xffff)
		redirectName := "sbt" + suffix
		deliveryName := "sbd" + suffix
		if len(redirectName) > 15 || len(deliveryName) > 15 {
			return "", "", E.New("TC eBPF delivery link name exceeds Linux limit")
		}
		_, redirectErr := netlink.LinkByName(redirectName)
		_, deliveryErr := netlink.LinkByName(deliveryName)
		if tcLinkNotFound(redirectErr) && tcLinkNotFound(deliveryErr) {
			return redirectName, deliveryName, nil
		}
		if redirectErr != nil && !tcLinkNotFound(redirectErr) {
			return "", "", redirectErr
		}
		if deliveryErr != nil && !tcLinkNotFound(deliveryErr) {
			return "", "", deliveryErr
		}
	}
	return "", "", E.New("unable to allocate TC eBPF delivery link name")
}

func setTCInterfaceSysctl(interfaceName, setting, value string) (tcSysctlState, bool, error) {
	state, changed, err := setTCSysctl(tcInterfaceSysctlPath(interfaceName, setting), value)
	if err != nil {
		return state, changed, E.Cause(err, setting, " for ", interfaceName)
	}
	return state, changed, nil
}

// tcSysctlRoot is a variable so the reverse-path-filter composition logic can be
// exercised against a temporary directory in tests.
var tcSysctlRoot = "/proc/sys/net/ipv4/conf"

func tcInterfaceSysctlPath(interfaceName, setting string) string {
	return tcSysctlRoot + "/" + interfaceName + "/" + setting
}

func setTCSysctl(path, value string) (tcSysctlState, bool, error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return tcSysctlState{}, false, err
	}
	original := strings.TrimSpace(string(current))
	if original == value {
		return tcSysctlState{}, false, nil
	}
	if err = os.WriteFile(path, []byte(value), 0o644); err != nil {
		return tcSysctlState{}, false, err
	}
	return tcSysctlState{path: path, original: original, applied: value}, true, nil
}

// appendTCSysctlStates merges states into the restore list, one entry per path.
//
// Repair reasserts these settings on every netlink event, so appending
// unconditionally would grow the list without bound and shadow the value the
// setting had before sing-box touched it. The first original is therefore the
// one that is kept — but applied has to follow the most recent write, because a
// later round can write a different value than the first one did. An aggregate
// that goes from 1 to 2 between rounds makes repair pin an interface to 2 where
// it first pinned it to 1; leaving applied at 1 would make restore read 2, take
// it for someone else's change, and leave sing-box's own value behind.
func appendTCSysctlStates(states []tcSysctlState, added []tcSysctlState) []tcSysctlState {
	for _, state := range added {
		index := slices.IndexFunc(states, func(existing tcSysctlState) bool {
			return existing.path == state.path
		})
		if index < 0 {
			states = append(states, state)
			continue
		}
		states[index].applied = state.applied
	}
	return states
}

// restoreTCSysctlStates reverts the settings sing-box changed.
//
// A setting whose current value no longer matches what was written belongs to
// whoever changed it afterwards — an administrator or a network manager — so it
// is left alone rather than reverted to a value that is no longer theirs. This
// mirrors restoreSharedRewriteLocalnet, which already guards route_localnet the
// same way.
//
// Restores that raise a value run before restores that lower one, rather than
// simply walking the list backwards. Clearing conf.all.rp_filter is paid for by
// pinning the other interfaces up to the old aggregate, and those two halves do
// not stay adjacent: a repair round that pins an interface discovered later
// appends it after the aggregate entry already in the list, so reverse order
// alone would drop that interface's own filter while the aggregate is still 0
// and leave it briefly unprotected. Raising first makes the ordering hold no
// matter how the rounds interleaved.
func restoreTCSysctlStates(states []tcSysctlState) error {
	var restoreErr error
	for _, state := range tcSysctlRestoreOrder(states) {
		current, err := os.ReadFile(state.path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				restoreErr = E.Errors(restoreErr, err)
			}
			continue
		}
		if strings.TrimSpace(string(current)) != state.applied {
			continue
		}
		if err = os.WriteFile(state.path, []byte(state.original), 0o644); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			restoreErr = E.Errors(restoreErr, err)
		}
	}
	return restoreErr
}

// tcSysctlRestoreOrder sequences the restores so nothing is widened ahead of the
// entry that compensates for it: every raising restore first, then the rest,
// each in reverse order of when it was recorded.
func tcSysctlRestoreOrder(states []tcSysctlState) []tcSysctlState {
	ordered := make([]tcSysctlState, 0, len(states))
	for _, raising := range []bool{true, false} {
		for _, state := range slices.Backward(states) {
			if tcSysctlRestoreRaises(state) == raising {
				ordered = append(ordered, state)
			}
		}
	}
	return ordered
}

// tcSysctlRestoreRaises reports whether putting this setting back increases it.
// Non-numeric values are never treated as raising, so they restore in the second
// pass where they cannot widen anything ahead of a compensating entry.
func tcSysctlRestoreRaises(state tcSysctlState) bool {
	original, originalErr := strconv.Atoi(state.original)
	applied, appliedErr := strconv.Atoi(state.applied)
	if originalErr != nil || appliedErr != nil {
		return false
	}
	return original > applied
}

// clearTCAggregateRPFilter makes the delivery interface's own rp_filter=0 take
// effect.
//
// The kernel evaluates the reverse path filter as max(conf.all.rp_filter,
// conf.<device>.rp_filter) (IN_DEV_MAXCONF), so clearing it on the delivery
// interface alone is a no-op while the aggregate knob is set. Redirected packets
// keep the source address of the interface they were about to leave on, which
// never routes back through the delivery interface, so __fib_validate_source()
// drops them as martian source for any non-zero value — loose mode included,
// because an interface without an address takes the last_resort branch, which
// rejects whenever the filter is enabled at all.
//
// Lower the aggregate knob, but first pin every other interface to the previous
// aggregate value so their effective policy is unchanged.
func clearTCAggregateRPFilter(deliveryName string) ([]tcSysctlState, error) {
	aggregatePath := tcInterfaceSysctlPath("all", "rp_filter")
	current, err := os.ReadFile(aggregatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, E.Cause(err, "read aggregate rp_filter")
	}
	aggregate, err := strconv.Atoi(strings.TrimSpace(string(current)))
	if err != nil {
		// Reporting no work to do here would let startup succeed while the
		// delivery interface stays behind an aggregate filter nobody lowered,
		// which is the silent blackhole this whole mechanism exists to avoid.
		return nil, E.Cause(err, "parse aggregate rp_filter")
	}
	if aggregate == 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(tcSysctlRoot)
	if err != nil {
		return nil, E.Cause(err, "list rp_filter interfaces")
	}
	states := make([]tcSysctlState, 0, len(entries)+1)
	failed := func(cause error) ([]tcSysctlState, error) {
		restoreErr := restoreTCSysctlStatesOwned(&states)
		if len(states) == 0 {
			states = nil
		}
		return states, E.Errors(cause, restoreErr)
	}
	for _, entry := range entries {
		if entry.Name() == "all" || entry.Name() == deliveryName {
			continue
		}
		state, changed, pinErr := pinTCInterfaceRPFilter(entry.Name(), aggregate)
		if pinErr != nil {
			// Only a vanished interface is skipped; anything else, including a
			// value that could not be read, has to stop the aggregate knob from
			// being cleared underneath it.
			if errors.Is(pinErr, os.ErrNotExist) {
				continue
			}
			return failed(E.Cause(pinErr, "pin rp_filter for ", entry.Name()))
		}
		if changed {
			states = append(states, state)
		}
	}
	state, changed, err := setTCSysctl(aggregatePath, "0")
	if err != nil {
		return failed(E.Cause(err, "clear aggregate rp_filter"))
	}
	if changed {
		states = append(states, state)
	}
	return states, nil
}

// pinTCInterfaceRPFilter raises one interface to the aggregate value so that
// clearing the aggregate knob leaves its effective filter untouched.
//
// An unreadable value is an error rather than "nothing to do". Reporting no work
// here would let the caller go on to clear the aggregate knob, and this
// interface would silently drop from max(all, dev) to whatever dev happens to
// be — the one outcome of this function that weakens a filter instead of
// preserving it. The caller raises the error before the aggregate is cleared and
// puts back the interfaces it had already pinned.
func pinTCInterfaceRPFilter(interfaceName string, aggregate int) (tcSysctlState, bool, error) {
	path := tcInterfaceSysctlPath(interfaceName, "rp_filter")
	current, err := os.ReadFile(path)
	if err != nil {
		return tcSysctlState{}, false, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(current)))
	if err != nil {
		return tcSysctlState{}, false, E.Cause(err, "parse rp_filter")
	}
	if value >= aggregate {
		return tcSysctlState{}, false, nil
	}
	return setTCSysctl(path, strconv.Itoa(aggregate))
}

// handoffTCGlobalSysctls takes over the aggregate-rp_filter restore state of the
// delivery link this one replaces.
//
// A replacement is created while the link it replaces still holds the aggregate
// rp_filter at 0, so clearTCAggregateRPFilter finds nothing to do for the new
// delivery interface and records no restore state of its own. Closing the old
// link would then put the aggregate knob back and silently reinstate the
// martian-source drop on the new delivery interface. This only concerns
// globalSysctls: the per-interface settings in sysctls are always re-applied
// fresh under the new delivery interface's own name, and the old delivery
// interface is deleted (and its own sysctls restored, harmlessly, right before
// that) regardless of who replaced it, so there is nothing there to hand off.
func handoffTCGlobalSysctls(previous, next *tcDeliveryLink) {
	if previous == nil || next == nil {
		return
	}
	if len(next.globalSysctls) == 0 {
		next.globalSysctls = previous.globalSysctls
	}
	previous.globalSysctls = nil
}

func restoreTCSysctlStatesOwned(states *[]tcSysctlState) error {
	for _, state := range tcSysctlRestoreOrder(*states) {
		if err := restoreTCSysctlStates([]tcSysctlState{state}); err != nil {
			// Do not lower compensating settings after a failed raise.
			return err
		}
		*states = slices.DeleteFunc(*states, func(s tcSysctlState) bool { return s.path == state.path })
	}
	return nil
}

func (d *tcDeliveryLink) IsClosed() bool {
	return d == nil || d.filter == nil && d.redirect == nil && d.delivery == nil && len(d.sysctls) == 0 && len(d.globalSysctls) == 0
}

func (d *tcDeliveryLink) Close() error {
	if d == nil {
		return nil
	}
	if err := detachTCFilterOwned(&d.filter); err != nil {
		return err
	}
	if err := restoreTCSysctlStatesOwned(&d.sysctls); err != nil {
		return err
	}
	if err := restoreTCSysctlStatesOwned(&d.globalSysctls); err != nil {
		return err
	}
	owned := d.redirect
	if owned == nil {
		owned = d.delivery
	}
	if owned != nil {
		if err := netlink.LinkDel(owned); err != nil && !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
			return err
		}
		d.redirect, d.delivery = nil, nil
	}
	return nil
}
