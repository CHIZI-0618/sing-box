//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	tcLocalFilterHandle    = 0x5344
	tcSharedFilterHandle   = 0x5345
	tcDeliveryFilterHandle = 0x5346
)

var tcVethSequence atomic.Uint32
var tcxSupport atomic.Int32

const (
	tcxSupportUnknown int32 = iota
	tcxSupportAvailable
	tcxSupportUnavailable = -1
)

type tcInterfaceRole struct {
	local  bool
	shared bool
}

type tcInterfaceAttachment struct {
	interfaceName  string
	interfaceIndex int
	framing        commonEBPF.TCLinkFraming
	role           tcInterfaceRole
	lock           io.Closer
	lockOwned      bool
	localFilter    *netlink.BpfFilter
	sharedFilter   *netlink.BpfFilter
	localLink      link.Link
	sharedLink     link.Link
	attachmentType string
}

type tcDeliveryLink struct {
	redirectName  string
	deliveryName  string
	redirect      netlink.Link
	delivery      netlink.Link
	filter        *netlink.BpfFilter
	sysctls       []tcSysctlState
	globalSysctls []tcSysctlState
}

type tcSysctlState struct {
	path     string
	original string
	applied  string
}

type tcDataPlane struct {
	access                sync.Mutex
	backend               *commonEBPF.TCBackend
	routing               *tcPolicyRouting
	delivery              *tcDeliveryLink
	attachments           []*tcInterfaceAttachment
	localInterface        string
	sharedInterfaces      []string
	hostAddresses         []netip.Addr
	sharedSourceMACPolicy bool
	priority              uint16
}

func startTCDataPlane(
	backend *commonEBPF.TCBackend,
	localEnabled bool,
	enableIPv6 bool,
	localInterface string,
	sharedInterfaces []string,
	hostAddresses []netip.Addr,
	sharedSourceMACPolicy bool,
	priority uint16,
) (*tcDataPlane, error) {
	dataPlane := &tcDataPlane{backend: backend, sharedSourceMACPolicy: sharedSourceMACPolicy, priority: priority}
	cleanup := func(startErr error) (*tcDataPlane, error) {
		return nil, E.Errors(startErr, dataPlane.Close())
	}
	routing, err := startTCPolicyRouting(enableIPv6)
	if err != nil {
		return cleanup(err)
	}
	dataPlane.routing = routing
	if err = backend.SetRoutingMark(routing.mark); err != nil {
		return cleanup(E.Cause(err, "set TC eBPF routing mark"))
	}
	if localEnabled {
		delivery, err := createTCDeliveryLink(backend, priority)
		if err != nil {
			return cleanup(err)
		}
		dataPlane.delivery = delivery
	}
	attachments, err := attachTCInterfaces(backend, localInterface, sharedInterfaces, sharedSourceMACPolicy, priority)
	if err != nil {
		return cleanup(err)
	}
	dataPlane.attachments = attachments
	dataPlane.localInterface = localInterface
	dataPlane.sharedInterfaces = slices.Clone(sharedInterfaces)
	if err = backend.UpdateHostAddresses(hostAddresses); err != nil {
		return cleanup(err)
	}
	dataPlane.hostAddresses = slices.Clone(hostAddresses)
	return dataPlane, nil
}

func attachTCInterfaces(
	backend *commonEBPF.TCBackend,
	localInterface string,
	sharedInterfaces []string,
	sharedSourceMACPolicy bool,
	priority uint16,
) ([]*tcInterfaceAttachment, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	attachments := make([]*tcInterfaceAttachment, 0, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	for interfaceName, role := range roles {
		link, err := netlink.LinkByName(interfaceName)
		if err != nil && role.shared && !role.local && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "find TC eBPF interface ", interfaceName)
		}
		attachment, err := attachTCInterface(link, backend, role, sharedSourceMACPolicy, priority)
		if err != nil {
			for _, attachment := range slices.Backward(attachments) {
				_ = attachment.Close()
			}
			return nil, E.Cause(err, "attach TC eBPF interface ", interfaceName)
		}
		attachments = append(attachments, attachment)
	}
	return attachments, nil
}

func (d *tcDataPlane) deliveryName() string {
	if d == nil || d.delivery == nil {
		return ""
	}
	return d.delivery.deliveryName
}

func (d *tcDataPlane) reconcile(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil {
		return E.New("TC eBPF data plane is closed")
	}
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return err
	}
	current := make(map[string]*tcInterfaceAttachment, len(d.attachments))
	for _, attachment := range d.attachments {
		current[attachment.interfaceName] = attachment
	}
	names := make([]string, 0, len(desired))
	for interfaceName := range desired {
		names = append(names, interfaceName)
	}
	slices.Sort(names)
	attachments := make([]*tcInterfaceAttachment, 0, len(desired))
	created := make([]*tcInterfaceAttachment, 0)
	replaced := make(map[string]*tcInterfaceAttachment)
	reusedLocks := make(map[string]bool)
	previousRoles := make(map[string]tcInterfaceRole, len(d.attachments))
	for _, attachment := range d.attachments {
		previousRoles[attachment.interfaceName] = attachment.role
	}
	hostChanged := !slices.Equal(d.hostAddresses, hostAddresses)
	if hostChanged {
		if err = d.backend.UpdateHostAddresses(hostAddresses); err != nil {
			return err
		}
	}
	rollback := func(rollbackErr error) error {
		for _, attachment := range d.attachments {
			if role, loaded := previousRoles[attachment.interfaceName]; loaded && attachment.role != role {
				if resetErr := attachment.resetAttachment(); resetErr != nil {
					rollbackErr = E.Errors(rollbackErr, E.Cause(resetErr, "reset TC eBPF interface ", attachment.interfaceName))
				}
				if restoreErr := restoreTCInterfaceAttachment(netlink.LinkByName, d.backend, attachment, role, d.sharedSourceMACPolicy, d.priority); restoreErr != nil {
					rollbackErr = E.Errors(rollbackErr, E.Cause(restoreErr, "rollback TC eBPF interface ", attachment.interfaceName))
				}
			}
		}
		for _, createdAttachment := range slices.Backward(created) {
			rollbackErr = E.Errors(rollbackErr, createdAttachment.Close())
		}
		if hostChanged {
			rollbackErr = E.Errors(rollbackErr, d.backend.UpdateHostAddresses(d.hostAddresses))
		}
		return rollbackErr
	}
	for _, interfaceName := range names {
		state := desired[interfaceName]
		previous := current[interfaceName]
		if previous != nil && previous.interfaceIndex == state.index &&
			previous.framing == state.framing && previous.role == state.role {
			attached, checkErr := previous.filtersAttached(d.priority)
			if checkErr != nil {
				return rollback(E.Cause(checkErr, "inspect TC eBPF interface ", interfaceName))
			}
			if attached {
				attachments = append(attachments, previous)
				delete(current, interfaceName)
				continue
			}
			if err = previous.resetAttachment(); err != nil {
				return rollback(E.Cause(err, "reset TC eBPF interface ", interfaceName))
			}
		}
		if previous != nil && previous.interfaceIndex == state.index && previous.framing == state.framing {
			if err = updateTCInterfaceAttachment(
				netlink.LinkByName,
				d.backend,
				previous,
				state.role,
				d.sharedSourceMACPolicy,
				d.priority,
			); err != nil {
				updateErr := err
				if resetErr := previous.resetAttachment(); resetErr != nil {
					updateErr = E.Errors(updateErr, E.Cause(resetErr, "reset TC eBPF interface ", interfaceName))
				}
				if restoreErr := restoreTCInterfaceAttachment(
					netlink.LinkByName,
					d.backend,
					previous,
					previousRoles[interfaceName],
					d.sharedSourceMACPolicy,
					d.priority,
				); restoreErr != nil {
					updateErr = E.Errors(updateErr, E.Cause(restoreErr, "restore TC eBPF interface ", interfaceName))
				}
				return rollback(E.Cause(updateErr, "update TC eBPF interface ", interfaceName))
			}
			attachments = append(attachments, previous)
			delete(current, interfaceName)
			continue
		}
		var lock io.Closer
		lockOwned := false
		if previous != nil {
			replaced[interfaceName] = previous
			// The lock is an abstract socket named after the interface index, so
			// it only covers the index it was taken for. Reuse it when the index
			// is unchanged; a renumbered interface needs its own lock, and the
			// stale one is released with the attachment it belongs to.
			if previous.interfaceIndex == state.index {
				lock = previous.lock
				reusedLocks[interfaceName] = lock != nil
			}
		}
		if lock == nil {
			lock, err = acquireTCInterfaceLock(interfaceName, state.index)
			if err != nil {
				return rollback(E.Cause(err, "lock TC eBPF interface ", interfaceName))
			}
			lockOwned = true
		}
		attachment, attachErr := attachTCInterfaceWithLock(
			netlink.LinkByName,
			d.backend,
			interfaceName,
			state,
			d.sharedSourceMACPolicy,
			d.priority,
			lock,
			lockOwned,
		)
		if attachErr != nil {
			return rollback(E.Cause(attachErr, "attach TC eBPF interface ", interfaceName))
		}
		attachments = append(attachments, attachment)
		created = append(created, attachment)
		delete(current, interfaceName)
	}
	var closeErr error
	for _, previous := range current {
		closeErr = E.Errors(closeErr, previous.Close())
	}
	for interfaceName, previous := range replaced {
		lock := previous.lock
		if reusedLocks[interfaceName] && lock != nil {
			previous.lock = nil
			previous.lockOwned = false
		}
		closeErr = E.Errors(closeErr, previous.Close())
		if !reusedLocks[interfaceName] {
			continue
		}
		for _, attachment := range created {
			if attachment.interfaceName == interfaceName {
				if lock != nil {
					attachment.lock = lock
					attachment.lockOwned = true
				}
				break
			}
		}
	}
	for _, attachment := range created {
		if !reusedLocks[attachment.interfaceName] {
			attachment.lockOwned = true
		}
	}
	d.attachments = attachments
	if localInterface != "" {
		d.localInterface = localInterface
	}
	d.sharedInterfaces = slices.Clone(sharedInterfaces)
	d.hostAddresses = slices.Clone(hostAddresses)
	return closeErr
}

func (d *tcDataPlane) desiredAttachmentState(localInterface string, sharedInterfaces []string) (map[string]tcAttachmentState, error) {
	desired, err := desiredTCAttachmentState(localInterface, sharedInterfaces, netlink.LinkByName)
	if err != nil {
		return nil, err
	}
	// Keep the previous local attachment while the default interface monitor has
	// no result during a mobile-network handoff. A newly discovered interface is
	// attached before this retained attachment is removed.
	retainLocalAttachmentStates(localInterface, desired, d.attachments)
	return desired, nil
}

func retainLocalAttachmentStates(localInterface string, desired map[string]tcAttachmentState, attachments []*tcInterfaceAttachment) {
	if localInterface != "" {
		return
	}
	for _, attachment := range attachments {
		if !attachment.role.local {
			continue
		}
		state, loaded := desired[attachment.interfaceName]
		if !loaded {
			state = tcAttachmentState{
				index:   attachment.interfaceIndex,
				framing: attachment.framing,
				role:    attachment.role,
			}
		}
		state.role.local = true
		desired[attachment.interfaceName] = state
	}
}

func (a *tcInterfaceAttachment) filtersAttached(priority uint16) (bool, error) {
	if a == nil {
		return false, nil
	}
	link, err := netlink.LinkByName(a.interfaceName)
	if err != nil && tcLinkNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if link.Attrs().Index != a.interfaceIndex {
		return false, nil
	}
	if a.attachmentType == "tcx" {
		if a.role.local {
			attached, err := tcxLinkAttached(a.localLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress)
			if err != nil {
				return false, E.Cause(err, "inspect TCX local egress attachment on interface ", a.interfaceName)
			}
			if !attached {
				return false, nil
			}
		}
		if a.role.shared {
			attached, err := tcxLinkAttached(a.sharedLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
			if err != nil {
				return false, E.Cause(err, "inspect TCX shared ingress attachment on interface ", a.interfaceName)
			}
			if !attached {
				return false, nil
			}
		}
		return true, nil
	}
	if a.attachmentType != "clsact" {
		return false, nil
	}
	if a.role.local {
		attached, err := tcFilterAttached(
			link,
			netlink.HANDLE_MIN_EGRESS,
			"sb_tc_local",
			tcLocalFilterHandle,
			priority,
		)
		if err != nil {
			return false, E.Cause(err, "inspect TC local egress filter on interface ", a.interfaceName)
		}
		if !attached {
			return false, nil
		}
	}
	if a.role.shared {
		attached, err := tcFilterAttached(
			link,
			netlink.HANDLE_MIN_INGRESS,
			"sb_tc_shared",
			tcSharedFilterHandle,
			priority,
		)
		if err != nil {
			return false, E.Cause(err, "inspect TC shared ingress filter on interface ", a.interfaceName)
		}
		if !attached {
			return false, nil
		}
	}
	return true, nil
}

func tcxLinkAttached(current link.Link, interfaceIndex int, attachType CiliumEBPF.AttachType) (bool, error) {
	if current == nil {
		return false, nil
	}
	info, err := current.Info()
	if err != nil {
		if errors.Is(err, os.ErrClosed) || errors.Is(err, unix.EBADF) || tcLinkNotFound(err) {
			return false, nil
		}
		return false, err
	}
	tcx := info.TCX()
	return info.Type == link.TCXType && tcx != nil &&
		tcx.Ifindex == uint32(interfaceIndex) && uint32(tcx.AttachType) == uint32(attachType), nil
}

func (d *tcDataPlane) updateHostAddresses(hostAddresses []netip.Addr) error {
	d.access.Lock()
	defer d.access.Unlock()
	if slices.Equal(d.hostAddresses, hostAddresses) {
		return nil
	}
	if err := d.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return err
	}
	d.hostAddresses = slices.Clone(hostAddresses)
	return nil
}

func (d *tcDataPlane) repairInfrastructure() (bool, error) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil {
		return false, E.New("TC eBPF data plane is closed")
	}
	routingChanged, routingErr := d.routing.ensure()
	if d.delivery == nil {
		return routingChanged, routingErr
	}
	deliveryChanged, replaceDelivery, err := d.delivery.repair(d.backend, d.priority)
	if err != nil {
		return routingChanged || deliveryChanged, E.Errors(routingErr, err)
	}
	if !replaceDelivery {
		return routingChanged || deliveryChanged, routingErr
	}
	delivery, err := createTCDeliveryLink(d.backend, d.priority)
	if err != nil {
		return routingChanged || deliveryChanged, E.Errors(
			routingErr,
			E.Cause(err, "restore TC eBPF delivery link"),
		)
	}
	previousDelivery := d.delivery
	handoffTCGlobalSysctls(previousDelivery, delivery)
	d.delivery = delivery
	if err = previousDelivery.Close(); err != nil {
		return true, E.Errors(routingErr, E.Cause(err, "remove stale TC eBPF delivery link"))
	}
	return true, routingErr
}

func (d *tcDeliveryLink) repair(backend *commonEBPF.TCBackend, priority uint16) (bool, bool, error) {
	if d == nil || d.redirect == nil || d.delivery == nil || d.filter == nil {
		return false, true, nil
	}
	redirect, err := netlink.LinkByName(d.redirectName)
	if err != nil && tcLinkNotFound(err) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	delivery, err := netlink.LinkByName(d.deliveryName)
	if err != nil && tcLinkNotFound(err) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	if redirect.Attrs().Index != d.redirect.Attrs().Index ||
		delivery.Attrs().Index != d.delivery.Attrs().Index {
		return false, true, nil
	}
	d.redirect = redirect
	d.delivery = delivery
	changed := false
	for _, link := range []netlink.Link{redirect, delivery} {
		if link.Attrs().Flags&net.FlagUp != 0 {
			continue
		}
		if err = netlink.LinkSetUp(link); err != nil {
			return changed, false, E.Cause(err, "restore TC eBPF delivery link ", link.Attrs().Name)
		}
		changed = true
	}
	filterAttached, err := tcFilterAttached(
		delivery,
		netlink.HANDLE_MIN_INGRESS,
		"sb_tc_deliver",
		tcDeliveryFilterHandle,
		priority,
	)
	if err != nil {
		return changed, false, err
	}
	if !filterAttached {
		if err = ensureTCClsact(delivery); err != nil {
			return changed, false, err
		}
		d.filter, err = attachTCFilter(
			delivery,
			netlink.HANDLE_MIN_INGRESS,
			backend.DeliveryIngressProgramFD(),
			"sb_tc_deliver",
			tcDeliveryFilterHandle,
			priority,
		)
		if err != nil {
			return changed, false, err
		}
		changed = true
	}
	for _, setting := range []struct {
		name  string
		value string
	}{
		{"rp_filter", "0"},
		{"accept_local", "1"},
	} {
		state, settingChanged, settingErr := setTCInterfaceSysctl(d.deliveryName, setting.name, setting.value)
		if errors.Is(settingErr, os.ErrNotExist) {
			return changed, true, nil
		}
		if settingErr != nil {
			return changed, false, settingErr
		}
		if settingChanged {
			d.sysctls = appendTCSysctlStates(d.sysctls, []tcSysctlState{state})
			changed = true
		}
	}
	aggregateStates, err := clearTCAggregateRPFilter(d.deliveryName)
	if err != nil {
		return changed, false, err
	}
	if len(aggregateStates) > 0 {
		d.globalSysctls = appendTCSysctlStates(d.globalSysctls, aggregateStates)
		changed = true
	}
	return changed, false, nil
}

func closeTCInterfaceAttachments(attachments []*tcInterfaceAttachment) error {
	var closeErr error
	for _, attachment := range slices.Backward(attachments) {
		closeErr = E.Errors(closeErr, attachment.Close())
	}
	return closeErr
}

func (d *tcDataPlane) attachmentDescriptions() []string {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	descriptions := make([]string, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		roles := "local"
		if attachment.role.local && attachment.role.shared {
			roles = "local+shared"
		} else if attachment.role.shared {
			roles = "shared"
		}
		descriptions = append(
			descriptions,
			attachment.interfaceName+"("+roles+","+attachment.framing.String()+","+attachment.attachmentType+")",
		)
	}
	slices.Sort(descriptions)
	return descriptions
}

func (d *tcDataPlane) disable() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil {
		return nil
	}
	return d.backend.Disable()
}

func attachTCInterface(
	link netlink.Link,
	backend *commonEBPF.TCBackend,
	role tcInterfaceRole,
	sharedSourceMACPolicy bool,
	priority uint16,
) (*tcInterfaceAttachment, error) {
	framing, err := tcLinkFraming(link)
	if err != nil {
		return nil, err
	}
	interfaceLock, err := acquireTCInterfaceLock(link.Attrs().Name, link.Attrs().Index)
	if err != nil {
		return nil, err
	}
	return attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		link.Attrs().Name,
		tcAttachmentState{index: link.Attrs().Index, framing: framing, role: role},
		sharedSourceMACPolicy,
		priority,
		interfaceLock,
		true,
	)
}

func attachTCInterfaceWithLock(
	linkByName func(string) (netlink.Link, error),
	backend *commonEBPF.TCBackend,
	interfaceName string,
	state tcAttachmentState,
	sharedSourceMACPolicy bool,
	priority uint16,
	interfaceLock io.Closer,
	lockOwned bool,
) (*tcInterfaceAttachment, error) {
	link, err := linkByName(interfaceName)
	if err != nil {
		if lockOwned && interfaceLock != nil {
			_ = interfaceLock.Close()
		}
		return nil, err
	}
	if link.Attrs().Index != state.index {
		if lockOwned && interfaceLock != nil {
			_ = interfaceLock.Close()
		}
		return nil, E.New("TC eBPF interface ", interfaceName, " changed while attaching")
	}
	framing := state.framing
	if state.role.shared && sharedSourceMACPolicy && framing != commonEBPF.TCLinkFramingEthernet {
		if lockOwned && interfaceLock != nil {
			_ = interfaceLock.Close()
		}
		return nil, E.New("shared source MAC policy requires Ethernet framing on interface ", link.Attrs().Name)
	}
	attachment := &tcInterfaceAttachment{
		interfaceName:  link.Attrs().Name,
		interfaceIndex: link.Attrs().Index,
		framing:        framing,
		role:           state.role,
		lock:           interfaceLock,
		lockOwned:      lockOwned,
	}
	cleanup := func(startErr error) (*tcInterfaceAttachment, error) {
		return nil, E.Errors(startErr, attachment.Close())
	}
	if attachment.lock == nil {
		return nil, E.New("TC eBPF interface lock is unavailable")
	}
	// TCX links do not expose the numeric TC priority. Preserve the existing
	// tc_priority contract by using TCX only with the default priority.
	if priority == 1 {
		if tcxSupport.Load() != tcxSupportUnavailable {
			tcxAttachment, tcxErr := attachTCXInterface(link, backend, attachment)
			if tcxErr == nil && tcxAttachment {
				tcxSupport.Store(tcxSupportAvailable)
				attachment.attachmentType = "tcx"
				return attachment, nil
			}
			if tcxUnsupportedError(tcxErr) {
				tcxSupport.CompareAndSwap(tcxSupportUnknown, tcxSupportUnavailable)
			}
		}
	}
	if err = ensureTCClsact(link); err != nil {
		return cleanup(E.Cause(err, "ensure TC clsact on interface ", interfaceName))
	}
	attachment.attachmentType = "clsact"
	if state.role.local {
		attachment.localFilter, err = attachTCFilter(
			link,
			netlink.HANDLE_MIN_EGRESS,
			backend.LocalEgressProgramFD(framing),
			"sb_tc_local",
			tcLocalFilterHandle,
			priority,
		)
		if err != nil {
			return cleanup(E.Cause(err, "attach TC local egress filter on interface ", interfaceName))
		}
	}
	if state.role.shared {
		attachment.sharedFilter, err = attachTCFilter(
			link,
			netlink.HANDLE_MIN_INGRESS,
			backend.SharedIngressProgramFD(framing),
			"sb_tc_shared",
			tcSharedFilterHandle,
			priority,
		)
		if err != nil {
			return cleanup(E.Cause(err, "attach TC shared ingress filter on interface ", interfaceName))
		}
	}
	return attachment, nil
}

func tcxUnsupportedError(err error) bool {
	return err != nil && (errors.Is(err, CiliumEBPF.ErrNotSupported) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS))
}

func attachTCXInterface(linkDevice netlink.Link, backend *commonEBPF.TCBackend, attachment *tcInterfaceAttachment) (bool, error) {
	closeLinks := func(err error) (bool, error) {
		if attachment.localLink != nil {
			_ = attachment.localLink.Close()
			attachment.localLink = nil
		}
		if attachment.sharedLink != nil {
			_ = attachment.sharedLink.Close()
			attachment.sharedLink = nil
		}
		return false, err
	}
	if attachment.role.local {
		program := backend.LocalEgressProgram(attachment.framing)
		if program == nil {
			return closeLinks(E.New("TC eBPF local program is unavailable"))
		}
		attached, err := link.AttachTCX(link.TCXOptions{
			Interface: linkDevice.Attrs().Index,
			Program:   program,
			Attach:    CiliumEBPF.AttachTCXEgress,
		})
		if err != nil {
			return closeLinks(err)
		}
		attachment.localLink = attached
	}
	if attachment.role.shared {
		program := backend.SharedIngressProgram(attachment.framing)
		if program == nil {
			return closeLinks(E.New("TC eBPF shared program is unavailable"))
		}
		attached, err := link.AttachTCX(link.TCXOptions{
			Interface: linkDevice.Attrs().Index,
			Program:   program,
			Attach:    CiliumEBPF.AttachTCXIngress,
		})
		if err != nil {
			return closeLinks(err)
		}
		attachment.sharedLink = attached
	}
	return true, nil
}

func updateTCInterfaceAttachment(
	linkByName func(string) (netlink.Link, error),
	backend *commonEBPF.TCBackend,
	attachment *tcInterfaceAttachment,
	role tcInterfaceRole,
	sharedSourceMACPolicy bool,
	priority uint16,
) error {
	link, err := linkByName(attachment.interfaceName)
	if err != nil {
		return err
	}
	if link.Attrs().Index != attachment.interfaceIndex {
		return E.New("TC eBPF interface ", attachment.interfaceName, " changed while updating")
	}
	if role.shared && sharedSourceMACPolicy && attachment.framing != commonEBPF.TCLinkFramingEthernet {
		return E.New("shared source MAC policy requires Ethernet framing on interface ", link.Attrs().Name)
	}
	if attachment.attachmentType == "tcx" {
		return updateTCXInterfaceAttachment(link, backend, attachment, role)
	}
	if attachment.localLink != nil || attachment.sharedLink != nil {
		return E.New("TC eBPF interface has an inconsistent attachment type")
	}
	if err = ensureTCClsact(link); err != nil {
		return E.Cause(err, "ensure TC clsact on interface ", attachment.interfaceName)
	}
	attachment.attachmentType = "clsact"
	addedLocal := false
	addedShared := false
	if role.local && attachment.localFilter == nil {
		attachment.localFilter, err = attachTCFilter(
			link,
			netlink.HANDLE_MIN_EGRESS,
			backend.LocalEgressProgramFD(attachment.framing),
			"sb_tc_local",
			tcLocalFilterHandle,
			priority,
		)
		if err != nil {
			return E.Cause(err, "attach TC local egress filter on interface ", attachment.interfaceName)
		}
		addedLocal = true
	}
	if role.shared && attachment.sharedFilter == nil {
		attachment.sharedFilter, err = attachTCFilter(
			link,
			netlink.HANDLE_MIN_INGRESS,
			backend.SharedIngressProgramFD(attachment.framing),
			"sb_tc_shared",
			tcSharedFilterHandle,
			priority,
		)
		if err != nil {
			if addedLocal {
				_ = detachTCFilter(attachment.localFilter)
				attachment.localFilter = nil
			}
			return E.Cause(err, "attach TC shared ingress filter on interface ", attachment.interfaceName)
		}
		addedShared = true
	}
	if !role.shared && attachment.sharedFilter != nil {
		if err = detachTCFilter(attachment.sharedFilter); err != nil {
			if addedShared {
				_ = detachTCFilter(attachment.sharedFilter)
				attachment.sharedFilter = nil
			}
			if addedLocal {
				_ = detachTCFilter(attachment.localFilter)
				attachment.localFilter = nil
			}
			return E.Cause(err, "detach TC shared ingress filter from interface ", attachment.interfaceName)
		}
		attachment.sharedFilter = nil
	}
	if !role.local && attachment.localFilter != nil {
		if err = detachTCFilter(attachment.localFilter); err != nil {
			return E.Cause(err, "detach TC local egress filter from interface ", attachment.interfaceName)
		}
		attachment.localFilter = nil
	}
	attachment.role = role
	return nil
}

func updateTCXInterfaceAttachment(
	linkDevice netlink.Link,
	backend *commonEBPF.TCBackend,
	attachment *tcInterfaceAttachment,
	role tcInterfaceRole,
) error {
	if role == attachment.role {
		return nil
	}
	attach := func(local bool) error {
		program := backend.SharedIngressProgram(attachment.framing)
		attachType := CiliumEBPF.AttachTCXIngress
		if local {
			program = backend.LocalEgressProgram(attachment.framing)
			attachType = CiliumEBPF.AttachTCXEgress
		}
		if program == nil {
			if local {
				return E.New("TC eBPF local program is unavailable")
			}
			return E.New("TC eBPF shared program is unavailable")
		}
		attached, err := link.AttachTCX(link.TCXOptions{
			Interface: linkDevice.Attrs().Index,
			Program:   program,
			Attach:    attachType,
		})
		if err != nil {
			return err
		}
		if local {
			attachment.localLink = attached
		} else {
			attachment.sharedLink = attached
		}
		return nil
	}
	detach := func(local bool) error {
		attached := attachment.sharedLink
		if local {
			attached = attachment.localLink
		}
		if attached == nil {
			return nil
		}
		if err := attached.Close(); err != nil {
			return err
		}
		if local {
			attachment.localLink = nil
		} else {
			attachment.sharedLink = nil
		}
		return nil
	}
	if err := transitionTCXInterfaceRole(
		attachment.role,
		role,
		attachment.localLink != nil,
		attachment.sharedLink != nil,
		attach,
		detach,
	); err != nil {
		return E.Cause(err, "update TCX eBPF interface ", attachment.interfaceName)
	}
	attachment.role = role
	return nil
}

// transitionTCXInterfaceRole installs desired links before removing obsolete
// links. This keeps at least one interception direction active throughout a
// role change and rolls back links created by a failed update.
func transitionTCXInterfaceRole(
	current tcInterfaceRole,
	desired tcInterfaceRole,
	hasLocal bool,
	hasShared bool,
	attach func(local bool) error,
	detach func(local bool) error,
) error {
	if current == desired {
		return nil
	}
	created := make([]bool, 0, 2)
	rollback := func(startErr error) error {
		var rollbackErr error
		for index := len(created) - 1; index >= 0; index-- {
			rollbackErr = E.Errors(rollbackErr, detach(created[index]))
		}
		return E.Errors(startErr, rollbackErr)
	}
	if desired.local && !hasLocal {
		if err := attach(true); err != nil {
			return E.Cause(err, "attach TCX local egress")
		}
		hasLocal = true
		created = append(created, true)
	}
	if desired.shared && !hasShared {
		if err := attach(false); err != nil {
			return rollback(E.Cause(err, "attach TCX shared ingress"))
		}
		hasShared = true
		created = append(created, false)
	}
	if !desired.shared && hasShared {
		if err := detach(false); err != nil {
			return rollback(E.Cause(err, "detach TCX shared ingress"))
		}
		hasShared = false
	}
	if !desired.local && hasLocal {
		if err := detach(true); err != nil {
			return rollback(E.Cause(err, "detach TCX local egress"))
		}
	}
	return nil
}

func (a *tcInterfaceAttachment) resetAttachment() error {
	if a == nil {
		return nil
	}
	closeErr := E.Errors(a.closeFilters(), a.closeLinks())
	a.attachmentType = ""
	return closeErr
}

func restoreTCInterfaceAttachment(
	linkByName func(string) (netlink.Link, error),
	backend *commonEBPF.TCBackend,
	attachment *tcInterfaceAttachment,
	role tcInterfaceRole,
	sharedSourceMACPolicy bool,
	priority uint16,
) error {
	if attachment == nil {
		return nil
	}
	return updateTCInterfaceAttachment(linkByName, backend, attachment, role, sharedSourceMACPolicy, priority)
}

func (a *tcInterfaceAttachment) Close() error {
	if a == nil {
		return nil
	}
	closeErr := E.Errors(a.closeFilters(), a.closeLinks())
	if a.lockOwned && a.lock != nil {
		closeErr = E.Errors(closeErr, a.lock.Close())
	}
	a.lock = nil
	a.lockOwned = false
	return closeErr
}

func (a *tcInterfaceAttachment) closeFilters() error {
	if a == nil {
		return nil
	}
	closeErr := E.Errors(
		detachTCFilter(a.sharedFilter),
		detachTCFilter(a.localFilter),
	)
	a.sharedFilter = nil
	a.localFilter = nil
	return closeErr
}

func (a *tcInterfaceAttachment) closeLinks() error {
	if a == nil {
		return nil
	}
	var closeErr error
	if a.sharedLink != nil {
		closeErr = E.Errors(closeErr, a.sharedLink.Close())
		a.sharedLink = nil
	}
	if a.localLink != nil {
		closeErr = E.Errors(closeErr, a.localLink.Close())
		a.localLink = nil
	}
	return closeErr
}

func createTCDeliveryLink(backend *commonEBPF.TCBackend, priority uint16) (*tcDeliveryLink, error) {
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
	delivery := &tcDeliveryLink{redirectName: redirectName, deliveryName: deliveryName}
	cleanup := func(startErr error) (*tcDeliveryLink, error) {
		return nil, E.Errors(startErr, delivery.Close())
	}
	delivery.redirect, err = netlink.LinkByName(redirectName)
	if err != nil {
		return cleanup(E.Cause(err, "find TC eBPF redirect link"))
	}
	delivery.delivery, err = netlink.LinkByName(deliveryName)
	if err != nil {
		return cleanup(E.Cause(err, "find TC eBPF delivery peer"))
	}
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
	if err != nil {
		return cleanup(err)
	}
	delivery.globalSysctls = appendTCSysctlStates(delivery.globalSysctls, aggregateStates)
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
		return nil, E.Errors(cause, restoreTCSysctlStates(states))
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

func (d *tcDeliveryLink) Close() error {
	if d == nil {
		return nil
	}
	var closeErr error
	if d.filter != nil {
		closeErr = detachTCFilter(d.filter)
		d.filter = nil
	}
	closeErr = E.Errors(closeErr, restoreTCSysctlStates(d.sysctls))
	d.sysctls = nil
	closeErr = E.Errors(closeErr, restoreTCSysctlStates(d.globalSysctls))
	d.globalSysctls = nil
	if d.redirect != nil {
		if err := netlink.LinkDel(d.redirect); err != nil &&
			!errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
			closeErr = E.Errors(closeErr, err)
		}
		d.redirect = nil
		d.delivery = nil
	} else if d.delivery != nil {
		if err := netlink.LinkDel(d.delivery); err != nil &&
			!errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
			closeErr = E.Errors(closeErr, err)
		}
		d.delivery = nil
	}
	return closeErr
}

func (d *tcDataPlane) Close() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	var closeErr error
	if d.backend != nil {
		closeErr = d.backend.Disable()
	}
	for _, attachment := range slices.Backward(d.attachments) {
		closeErr = E.Errors(closeErr, attachment.Close())
	}
	d.attachments = nil
	closeErr = E.Errors(closeErr, d.routing.Close())
	d.routing = nil
	closeErr = E.Errors(closeErr, d.delivery.Close())
	d.delivery = nil
	if d.backend != nil {
		closeErr = E.Errors(closeErr, d.backend.Close())
		d.backend = nil
	}
	return closeErr
}
