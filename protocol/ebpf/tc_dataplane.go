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
	tcLocalFilterHandle           = 0x5344
	tcSharedFilterHandle          = 0x5345
	tcDeliveryFilterHandle        = 0x5346
	tcLocalICMPReplyFilterHandle  = 0x5347
	tcSharedICMPReplyFilterHandle = 0x5348
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

// tcxLinkInfo is the subset of cilium/ebpf's link.Link that tcxLinkAttached
// actually calls. Narrower than link.Link so the same health-check helper
// also accepts tcxAttachedLink below.
type tcxLinkInfo interface {
	Info() (*link.Info, error)
}

// tcxAttachedLink is the subset of link.Link the fakeip_icmp TCX link fields
// use: closing it, and inspecting whether it is still live. Narrower than
// link.Link (which cannot be implemented outside cilium/ebpf, so a test
// double could never satisfy it anyway) so a test double only needs these
// two methods.
type tcxAttachedLink interface {
	io.Closer
	tcxLinkInfo
}

type tcInterfaceAttachment struct {
	interfaceName  string
	interfaceIndex int
	framing        commonEBPF.TCLinkFraming
	role           tcInterfaceRole
	lock           io.Closer
	lockOwned      bool
	closing        bool
	localFilter    *netlink.BpfFilter
	sharedFilter   *netlink.BpfFilter
	localLink      link.Link
	sharedLink     link.Link
	attachmentType string
	// localICMPFilter/sharedICMPFilter/localICMPLink/sharedICMPLink are the
	// fakeip_icmp reply filters, attached alongside localFilter/sharedFilter
	// under the same role and only when backend.FakeIPICMPEnabled(); nil
	// whenever that feature is off, the same as every other field here is nil
	// whenever its own role/attachment-type does not apply.
	localICMPFilter  *netlink.BpfFilter
	sharedICMPFilter *netlink.BpfFilter
	localICMPLink    tcxAttachedLink
	sharedICMPLink   tcxAttachedLink
	// detachFilter is nil in production; tests inject detach failures per owner.
	detachFilter func(*netlink.BpfFilter) error
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
	retiredAttachments    []*tcInterfaceAttachment
	retiredDeliveries     []*tcDeliveryLink
	closing               bool
	localInterface        string
	sharedInterfaces      []string
	hostAddresses         []netip.Addr
	sharedSourceMACPolicy bool
	priority              uint16
	// hooks is nil in production. Tests set it to reconcile against synthetic
	// interfaces, which is the only way to reach the ordering between releasing
	// an attachment and taking the interface lock of the one that replaced it.
	hooks *tcDataPlaneHooks
}

type tcDataPlaneHooks struct {
	linkByName func(string) (netlink.Link, error)
	// attach returns any owner whose cleanup failed alongside the error.
	attach func(
		interfaceName string,
		state tcAttachmentState,
		lock io.Closer,
		lockOwned bool,
	) (*tcInterfaceAttachment, error)
}

func (d *tcDataPlane) linkByName() func(string) (netlink.Link, error) {
	if d.hooks != nil && d.hooks.linkByName != nil {
		return d.hooks.linkByName
	}
	return netlink.LinkByName
}

func (d *tcDataPlane) attachInterface(
	interfaceName string,
	state tcAttachmentState,
	lock io.Closer,
	lockOwned bool,
) (*tcInterfaceAttachment, error) {
	if d.hooks != nil && d.hooks.attach != nil {
		return d.hooks.attach(interfaceName, state, lock, lockOwned)
	}
	return attachTCInterfaceWithLock(
		d.linkByName(),
		d.backend,
		interfaceName,
		state,
		d.sharedSourceMACPolicy,
		d.priority,
		lock,
		lockOwned,
	)
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
		closeErr := dataPlane.Close()
		if !dataPlane.IsClosed() {
			return dataPlane, E.Errors(startErr, closeErr)
		}
		return nil, E.Errors(startErr, closeErr)
	}
	routing, err := startTCPolicyRouting(enableIPv6)
	dataPlane.routing = routing
	if err != nil {
		return cleanup(err)
	}
	if err = backend.SetRoutingMark(routing.mark); err != nil {
		return cleanup(E.Cause(err, "set TC eBPF routing mark"))
	}
	if localEnabled {
		delivery, err := dataPlane.createTCDeliveryLink()
		dataPlane.delivery = delivery
		if err != nil {
			return cleanup(err)
		}
	}
	attachments, err := dataPlane.attachTCInterfaces(localInterface, sharedInterfaces)
	dataPlane.attachments = attachments
	if err != nil {
		return cleanup(err)
	}
	dataPlane.localInterface = localInterface
	dataPlane.sharedInterfaces = slices.Clone(sharedInterfaces)
	if err = backend.UpdateHostAddresses(hostAddresses); err != nil {
		return cleanup(err)
	}
	dataPlane.hostAddresses = slices.Clone(hostAddresses)
	return dataPlane, nil
}

func (d *tcDataPlane) attachTCInterfaces(
	localInterface string,
	sharedInterfaces []string,
) ([]*tcInterfaceAttachment, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	names := make([]string, 0, len(roles))
	for interfaceName := range roles {
		names = append(names, interfaceName)
	}
	// reconcile walks its interfaces in this order too. Iterating the map
	// directly would leave it to chance which interfaces are already attached
	// when a later one fails, which is the situation the cleanup below covers.
	slices.Sort(names)
	attachments := make([]*tcInterfaceAttachment, 0, len(names))
	linkByName := d.linkByName()
	// Return unfinished owners even on failure, so startup cleanup can retry
	// without dropping their filters or releasing their interface locks early.
	cleanup := func(startErr error) ([]*tcInterfaceAttachment, error) {
		closeErr := closeTCInterfaceAttachments(attachments)
		return openTCAttachments(attachments), E.Errors(startErr, closeErr)
	}
	for _, interfaceName := range names {
		role := roles[interfaceName]
		link, err := linkByName(interfaceName)
		if err != nil && role.shared && !role.local && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return cleanup(E.Cause(err, "find TC eBPF interface ", interfaceName))
		}
		attachment, err := d.lockAndAttachInterface(interfaceName, link, role)
		if attachment != nil {
			attachments = append(attachments, attachment)
		}
		if err != nil {
			return cleanup(E.Cause(err, "attach TC eBPF interface ", interfaceName))
		}
	}
	return attachments, nil
}

// lockAndAttachInterface takes the interface lock and attaches through the same
// seam reconcile uses, so both paths agree on who owns the lock when the attach
// fails.
func (d *tcDataPlane) lockAndAttachInterface(
	interfaceName string,
	link netlink.Link,
	role tcInterfaceRole,
) (*tcInterfaceAttachment, error) {
	framing, err := tcLinkFraming(link)
	if err != nil {
		return nil, err
	}
	interfaceLock, err := acquireTCInterfaceLock(interfaceName, link.Attrs().Index)
	if err != nil {
		return nil, err
	}
	return d.attachInterface(
		interfaceName,
		tcAttachmentState{index: link.Attrs().Index, framing: framing, role: role},
		interfaceLock,
		true,
	)
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
	if d.backend == nil || d.closing {
		return E.New("TC eBPF data plane is closed")
	}
	if err := d.closeRetired(); err != nil {
		return err
	}
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return err
	}
	current := make(map[string]*tcInterfaceAttachment, len(d.attachments))
	for _, attachment := range d.attachments {
		current[attachment.interfaceName] = attachment
	}
	// Reconcile the selected local interface first. During an uplink handover
	// this adds the replacement local role before the previous interface loses
	// it, including when the replacement was already attached for shared
	// traffic.
	names := make([]string, 0, len(desired))
	sortStart := 0
	if _, loaded := desired[localInterface]; localInterface != "" && loaded {
		names = append(names, localInterface)
		sortStart = 1
	}
	for interfaceName := range desired {
		if interfaceName != localInterface {
			names = append(names, interfaceName)
		}
	}
	slices.Sort(names[sortStart:])
	attachments := make([]*tcInterfaceAttachment, 0, len(desired))
	created := make([]*tcInterfaceAttachment, 0)
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
	// Release stale attachments whose interface index is needed by a candidate
	// before the attach pass takes its lock. A working local attachment whose
	// index is not reused stays active until its replacement has been attached.
	if err = d.closeStaleTCAttachmentsLocked(current, desired); err != nil {
		if hostChanged {
			err = E.Errors(err, d.backend.UpdateHostAddresses(d.hostAddresses))
		}
		return err
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
			if !createdAttachment.IsClosed() {
				d.retiredAttachments = append(d.retiredAttachments, createdAttachment)
			}
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
			attached, checkErr := previous.filtersAttached(d.priority, d.backend)
			if checkErr != nil {
				return rollback(E.Cause(checkErr, "inspect TC eBPF interface ", interfaceName))
			}
			if attached {
				attachments = append(attachments, previous)
				delete(current, interfaceName)
				continue
			}
			// Deliberately not previous.resetAttachment() here: that would
			// tear down every filter and link this attachment holds,
			// including ones filtersAttached just confirmed are still
			// healthy, only to have updateTCInterfaceAttachment recreate
			// them from nothing a few lines below. updateTCInterfaceAttachment
			// (and updateTCXInterfaceAttachment underneath it) already skip
			// attaching whatever field is non-nil, so calling it directly on
			// the drifted-but-not-reset attachment repairs only the part
			// filtersAttached found missing — the surgical repair this
			// health check exists for, not a full detach-and-reattach that
			// would needlessly disturb an unrelated, still-working filter
			// (or, if the repair itself then failed, leave that unrelated
			// filter torn down too).
			//
			// That "skip attaching whatever field is non-nil" behavior is
			// exactly the gap clearStaleAttachments exists to close: an
			// externally removed filter or link (a `tc filter del` or
			// `bpftool link detach` run outside this process) is gone from
			// the kernel but its Go-side pointer is untouched by that,
			// so updateTCInterfaceAttachment would otherwise see a non-nil
			// field and skip it, "repairing" nothing while still returning
			// success. Clearing exactly the fields filtersAttached's own
			// per-field checks (mirrored here individually rather than
			// short-circuited) confirm are actually gone makes the repair
			// below re-attach them, and leaves every other, still-healthy
			// field's non-nil pointer alone.
			if err = previous.clearStaleAttachments(d.priority, d.backend); err != nil {
				return rollback(E.Cause(err, "inspect TC eBPF interface ", interfaceName, " for stale attachments"))
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
		lock, err := acquireTCInterfaceLock(interfaceName, state.index)
		if err != nil {
			return rollback(E.Cause(err, "lock TC eBPF interface ", interfaceName))
		}
		attachment, attachErr := d.attachInterface(interfaceName, state, lock, true)
		if attachErr != nil {
			if attachment != nil {
				created = append(created, attachment)
			}
			return rollback(E.Cause(attachErr, "attach TC eBPF interface ", interfaceName))
		}
		attachments = append(attachments, attachment)
		created = append(created, attachment)
		// A mismatched previous attachment may have been deliberately retained to
		// keep local interception active while this replacement was staged. Leave
		// it in current so the commit pass below closes it only after the new
		// attachment is live.
		if previous == nil {
			delete(current, interfaceName)
		}
	}
	var closeErr error
	for _, previous := range current {
		// Everything not wanted was released above and everything wanted was
		// taken out of this map by the attach pass, so this is a safety net.
		closeErr = E.Errors(closeErr, previous.Close())
		if !previous.IsClosed() {
			d.retiredAttachments = append(d.retiredAttachments, previous)
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
	desired, err := desiredTCAttachmentState(localInterface, sharedInterfaces, d.linkByName())
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
			// The interface could not be resolved, so this retains the index the
			// attachment was created with. That is only meaningful while the index
			// is still the attachment's to claim: if another interface reports it,
			// the one this attachment describes is gone, and retaining it would
			// hold the interface lock the other one needs.
			if tcAttachmentIndexClaimed(desired, attachment.interfaceName, attachment.interfaceIndex) {
				continue
			}
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

// tcAttachmentIndexClaimed reports whether an interface other than the named one
// is already known to carry this index.
func tcAttachmentIndexClaimed(desired map[string]tcAttachmentState, interfaceName string, index int) bool {
	for name, state := range desired {
		if name != interfaceName && state.index == index {
			return true
		}
	}
	return false
}

// filtersAttached reports whether this attachment's actual kernel state
// still matches everything its role and backend configuration says should be
// there. backend is consulted only for backend.FakeIPICMPEnabled(): when the
// feature is off, the ICMP-specific checks below are skipped entirely (a nil
// localICMPLink/sharedICMPLink/localICMPFilter/sharedICMPFilter is then
// correct, not a fault), and when it is on, the corresponding fakeip_icmp
// filter or link is required exactly like the ordinary one it rides
// alongside — its absence must fail this check the same way a missing
// sb_tc_local/sb_tc_shared would, so a reconcile pass actually notices and
// repairs it instead of a health check that can only see half of what it
// attached.
func (a *tcInterfaceAttachment) filtersAttached(priority uint16, backend *commonEBPF.TCBackend) (bool, error) {
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
	fakeIPICMPEnabled := backend.FakeIPICMPEnabled()
	if a.attachmentType == "tcx" {
		if a.role.local {
			attached, err := tcxLinkAttached(a.localLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress)
			if err != nil {
				return false, E.Cause(err, "inspect TCX local egress attachment on interface ", a.interfaceName)
			}
			if !attached {
				return false, nil
			}
			if fakeIPICMPEnabled {
				attached, err = tcxLinkAttached(a.localICMPLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress)
				if err != nil {
					return false, E.Cause(err, "inspect TCX local fakeip_icmp attachment on interface ", a.interfaceName)
				}
				if !attached {
					return false, nil
				}
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
			if fakeIPICMPEnabled {
				attached, err = tcxLinkAttached(a.sharedICMPLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
				if err != nil {
					return false, E.Cause(err, "inspect TCX shared fakeip_icmp attachment on interface ", a.interfaceName)
				}
				if !attached {
					return false, nil
				}
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
		if fakeIPICMPEnabled {
			attached, err = tcFilterAttached(
				link,
				netlink.HANDLE_MIN_EGRESS,
				"sb_icmp_local",
				tcLocalICMPReplyFilterHandle,
				priority,
			)
			if err != nil {
				return false, E.Cause(err, "inspect fakeip_icmp local egress filter on interface ", a.interfaceName)
			}
			if !attached {
				return false, nil
			}
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
		if fakeIPICMPEnabled {
			attached, err = tcFilterAttached(
				link,
				netlink.HANDLE_MIN_INGRESS,
				"sb_icmp_shared",
				tcSharedICMPReplyFilterHandle,
				priority,
			)
			if err != nil {
				return false, E.Cause(err, "inspect fakeip_icmp shared ingress filter on interface ", a.interfaceName)
			}
			if !attached {
				return false, nil
			}
		}
	}
	return true, nil
}

// clearStaleAttachments checks each of this attachment's kernel-side
// filters/links against its own role individually -- unlike filtersAttached,
// which short-circuits on the first miss and never mutates anything -- and
// discards the Go-side reference for any one that is no longer actually
// present in the kernel (a `tc filter del` or `bpftool link detach` run
// outside this process, for example).
//
// This exists because updateTCInterfaceAttachmentWithOps's own repair logic
// only re-attaches a field whose Go pointer is nil; an externally-removed
// filter or link leaves its Go-side reference non-nil (deleting a kernel
// object does not reach back into this process and clear the struct that
// described it), so that repair silently does nothing for it, and the
// reconcile pass that called it reports success having repaired nothing.
// reconcile() calls this, right before updateTCInterfaceAttachment, so that
// repair's nil-checks see the true state instead.
//
// A stale TCX link is also best-effort closed before being discarded, to
// release whatever local file descriptor it still holds -- the close error
// is deliberately ignored, since by construction the kernel-side attachment
// is already gone. A clsact filter's Go-side struct owns no such resource
// and is simply discarded once found stale.
func (a *tcInterfaceAttachment) clearStaleAttachments(priority uint16, backend *commonEBPF.TCBackend) error {
	link, err := netlink.LinkByName(a.interfaceName)
	if err != nil {
		if tcLinkNotFound(err) {
			return nil
		}
		return err
	}
	if link.Attrs().Index != a.interfaceIndex {
		return nil
	}
	fakeIPICMPEnabled := backend.FakeIPICMPEnabled()
	if a.attachmentType == "tcx" {
		if a.role.local {
			if err = clearStaleTCXRoleLink(a, true, CiliumEBPF.AttachTCXEgress); err != nil {
				return E.Cause(err, "inspect TCX local egress attachment on interface ", a.interfaceName)
			}
			if fakeIPICMPEnabled {
				if err = clearStaleTCXLink(&a.localICMPLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress); err != nil {
					return E.Cause(err, "inspect TCX local fakeip_icmp attachment on interface ", a.interfaceName)
				}
			}
		}
		if a.role.shared {
			if err = clearStaleTCXRoleLink(a, false, CiliumEBPF.AttachTCXIngress); err != nil {
				return E.Cause(err, "inspect TCX shared ingress attachment on interface ", a.interfaceName)
			}
			if fakeIPICMPEnabled {
				if err = clearStaleTCXLink(&a.sharedICMPLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress); err != nil {
					return E.Cause(err, "inspect TCX shared fakeip_icmp attachment on interface ", a.interfaceName)
				}
			}
		}
		return nil
	}
	if a.attachmentType != "clsact" {
		return nil
	}
	if a.role.local {
		if err = clearStaleTCFilter(link, netlink.HANDLE_MIN_EGRESS, "sb_tc_local", tcLocalFilterHandle, priority, &a.localFilter); err != nil {
			return E.Cause(err, "inspect TC local egress filter on interface ", a.interfaceName)
		}
		if fakeIPICMPEnabled {
			if err = clearStaleTCFilter(link, netlink.HANDLE_MIN_EGRESS, "sb_icmp_local", tcLocalICMPReplyFilterHandle, priority, &a.localICMPFilter); err != nil {
				return E.Cause(err, "inspect fakeip_icmp local egress filter on interface ", a.interfaceName)
			}
		}
	}
	if a.role.shared {
		if err = clearStaleTCFilter(link, netlink.HANDLE_MIN_INGRESS, "sb_tc_shared", tcSharedFilterHandle, priority, &a.sharedFilter); err != nil {
			return E.Cause(err, "inspect TC shared ingress filter on interface ", a.interfaceName)
		}
		if fakeIPICMPEnabled {
			if err = clearStaleTCFilter(link, netlink.HANDLE_MIN_INGRESS, "sb_icmp_shared", tcSharedICMPReplyFilterHandle, priority, &a.sharedICMPFilter); err != nil {
				return E.Cause(err, "inspect fakeip_icmp shared ingress filter on interface ", a.interfaceName)
			}
		}
	}
	return nil
}

// clearStaleTCFilter clears *filter if it is non-nil but the kernel no
// longer actually has a filter matching it -- a no-op both when *filter is
// already nil (the ordinary "not attached yet" case, which needs no kernel
// query) and when the kernel confirms it is still there.
func clearStaleTCFilter(link netlink.Link, parent uint32, filterName string, handle uint16, priority uint16, filter **netlink.BpfFilter) error {
	if *filter == nil {
		return nil
	}
	attached, err := tcFilterAttached(link, parent, filterName, handle, priority)
	if err != nil {
		return err
	}
	if !attached {
		*filter = nil
	}
	return nil
}

// clearStaleTCXLink is clearStaleTCFilter's TCX counterpart: also
// best-effort closes the stale link (ignoring the error) before discarding
// it, since a link.Link/tcxAttachedLink owns a local file descriptor a bare
// filter struct does not.
func clearStaleTCXLink(link *tcxAttachedLink, interfaceIndex int, attachType CiliumEBPF.AttachType) error {
	if *link == nil {
		return nil
	}
	attached, err := tcxLinkAttached(*link, interfaceIndex, attachType)
	if err != nil {
		return err
	}
	if !attached {
		_ = (*link).Close()
		*link = nil
	}
	return nil
}

// clearStaleTCXRoleLink is clearStaleTCXLink for attachment.localLink /
// attachment.sharedLink, which are typed link.Link rather than
// tcxAttachedLink (see closeTCXRoleLink, which has the same local/shared
// split for the same reason: assigning through a *link.Link is what needs
// distinguishing by field, not the check itself).
func clearStaleTCXRoleLink(attachment *tcInterfaceAttachment, local bool, attachType CiliumEBPF.AttachType) error {
	current := attachment.sharedLink
	if local {
		current = attachment.localLink
	}
	if current == nil {
		return nil
	}
	attached, err := tcxLinkAttached(current, attachment.interfaceIndex, attachType)
	if err != nil {
		return err
	}
	if attached {
		return nil
	}
	_ = current.Close()
	if local {
		attachment.localLink = nil
	} else {
		attachment.sharedLink = nil
	}
	return nil
}

func tcxLinkAttached(current tcxLinkInfo, interfaceIndex int, attachType CiliumEBPF.AttachType) (bool, error) {
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
	if d.backend == nil || d.closing {
		return false, E.New("TC eBPF data plane is closed")
	}
	if err := d.closeRetired(); err != nil {
		return false, err
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
	delivery, err := d.createTCDeliveryLink()
	if err != nil {
		if delivery != nil {
			d.retiredDeliveries = append(d.retiredDeliveries, delivery)
		}
		return routingChanged || deliveryChanged, E.Errors(
			routingErr,
			E.Cause(err, "restore TC eBPF delivery link"),
		)
	}
	previousDelivery := d.delivery
	handoffTCGlobalSysctls(previousDelivery, delivery)
	d.delivery = delivery
	if err = previousDelivery.Close(); err != nil {
		if !previousDelivery.IsClosed() {
			d.retiredDeliveries = append(d.retiredDeliveries, previousDelivery)
		}
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
	if len(aggregateStates) > 0 {
		d.globalSysctls = appendTCSysctlStates(d.globalSysctls, aggregateStates)
		changed = true
	}
	if err != nil {
		return changed, false, err
	}
	return changed, false, nil
}

// closeStaleTCAttachmentsLocked releases the attachments that no longer describe
// the interface they were created for, before the attach pass takes any lock.
//
// Being wanted by name is not enough to keep one. The interface lock is named
// after the interface index alone, so an attachment holds the lock for the index
// it was created at, and that index is only still its own while the interface
// still carries it. An attachment whose interface was renumbered is holding a
// lock for an index another interface may be given. Keeping such an attachment
// until the end of the reconciliation makes the interface that took the index
// fail to attach, whichever order the two are processed in.
//
// An attachment still sitting at its own index and framing is left alone: it may be healthy,
// and deciding that is the attach pass's job.
//
// The released attachments leave d.attachments straight away rather than at the
// end, so the state this data plane reports stays true even when the rest of the
// reconciliation fails: they are closed, and nothing that follows may treat them
// as live. Failed owners remain managed, and a partially closed attachment
// must finish closing even if the desired state changes back before the retry.
func (d *tcDataPlane) closeStaleTCAttachmentsLocked(
	current map[string]*tcInterfaceAttachment,
	desired map[string]tcAttachmentState,
) error {
	stale := make([]string, 0, len(current))
	for interfaceName, attachment := range current {
		state, wanted := desired[interfaceName]
		if attachment.closing ||
			((!wanted || state.index != attachment.interfaceIndex || state.framing != attachment.framing) &&
				!canStageTCLocalReplacement(attachment, desired)) {
			stale = append(stale, interfaceName)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	slices.Sort(stale)
	var closeErr error
	released := make(map[*tcInterfaceAttachment]bool, len(stale))
	for _, interfaceName := range stale {
		attachment := current[interfaceName]
		closeErr = E.Errors(closeErr, attachment.Close())
		if attachment.IsClosed() {
			released[attachment] = true
			delete(current, interfaceName)
		}
	}
	remaining := make([]*tcInterfaceAttachment, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		if !released[attachment] {
			remaining = append(remaining, attachment)
		}
	}
	d.attachments = remaining
	return closeErr
}

// canStageTCLocalReplacement reports whether attachment can keep intercepting
// local traffic while a replacement is attached. The old attachment cannot be
// retained when its index is needed by the replacement: interface locks are
// keyed by index and the old interface has already ceased to be a usable
// handover path in that case.
func canStageTCLocalReplacement(attachment *tcInterfaceAttachment, desired map[string]tcAttachmentState) bool {
	if attachment == nil || attachment.closing || !attachment.role.local {
		return false
	}
	for interfaceName, state := range desired {
		if !state.role.local {
			continue
		}
		if state.index == attachment.interfaceIndex {
			return false
		}
		return !tcAttachmentIndexClaimed(desired, interfaceName, attachment.interfaceIndex)
	}
	return false
}

func closeTCInterfaceAttachments(attachments []*tcInterfaceAttachment) error {
	var closeErr error
	for _, attachment := range slices.Backward(attachments) {
		closeErr = E.Errors(closeErr, attachment.Close())
	}
	return closeErr
}

// attachmentDiagnostics is attachmentDescriptions' structured sibling, for
// item 7's runtime status query: the same walk over d.attachments, but
// returning fields a JSON/text renderer can use directly instead of a
// pre-formatted log string.
func (d *tcDataPlane) attachmentDiagnostics() []EBPFAttachmentDiagnostics {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	diagnostics := make([]EBPFAttachmentDiagnostics, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		role := "local"
		if attachment.role.local && attachment.role.shared {
			role = "local+shared"
		} else if attachment.role.shared {
			role = "shared"
		}
		fakeIPICMP := attachment.localICMPFilter != nil || attachment.sharedICMPFilter != nil ||
			attachment.localICMPLink != nil || attachment.sharedICMPLink != nil
		diagnostics = append(diagnostics, EBPFAttachmentDiagnostics{
			InterfaceName:  attachment.interfaceName,
			InterfaceIndex: attachment.interfaceIndex,
			Role:           role,
			Framing:        attachment.framing.String(),
			Mechanism:      attachment.attachmentType,
			FakeIPICMP:     fakeIPICMP,
		})
	}
	slices.SortFunc(diagnostics, func(a, b EBPFAttachmentDiagnostics) int {
		return strings.Compare(a.InterfaceName, b.InterfaceName)
	})
	return diagnostics
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
	attachment := &tcInterfaceAttachment{
		interfaceName: interfaceName, interfaceIndex: state.index,
		framing: state.framing, role: state.role, lock: interfaceLock, lockOwned: lockOwned,
	}
	cleanup := func(startErr error) (*tcInterfaceAttachment, error) {
		closeErr := attachment.Close()
		if !attachment.IsClosed() {
			return attachment, E.Errors(startErr, closeErr)
		}
		return nil, E.Errors(startErr, closeErr)
	}
	link, err := linkByName(interfaceName)
	if err != nil {
		return cleanup(err)
	}
	if link.Attrs().Index != state.index {
		return cleanup(E.New("TC eBPF interface ", interfaceName, " changed while attaching"))
	}
	framing := state.framing
	if state.role.shared && sharedSourceMACPolicy && framing != commonEBPF.TCLinkFramingEthernet {
		return cleanup(E.New("shared source MAC policy requires Ethernet framing on interface ", interfaceName))
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
			if attachment.hasAttachedResources() {
				return cleanup(tcxErr)
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
		if backend.FakeIPICMPEnabled() {
			attachment.localICMPFilter, err = attachTCFilter(
				link,
				netlink.HANDLE_MIN_EGRESS,
				backend.FakeIPICMPLocalReplyProgramFD(framing),
				"sb_icmp_local",
				tcLocalICMPReplyFilterHandle,
				priority,
			)
			if err != nil {
				return cleanup(E.Cause(err, "attach fakeip_icmp local reply filter on interface ", interfaceName))
			}
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
		if backend.FakeIPICMPEnabled() {
			attachment.sharedICMPFilter, err = attachTCFilter(
				link,
				netlink.HANDLE_MIN_INGRESS,
				backend.FakeIPICMPSharedReplyProgramFD(framing),
				"sb_icmp_shared",
				tcSharedICMPReplyFilterHandle,
				priority,
			)
			if err != nil {
				return cleanup(E.Cause(err, "attach fakeip_icmp shared reply filter on interface ", interfaceName))
			}
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
		return false, E.Errors(err, attachment.closeLinks())
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
		if backend.FakeIPICMPEnabled() {
			icmpProgram := backend.FakeIPICMPLocalReplyProgram(attachment.framing)
			if icmpProgram == nil {
				return closeLinks(E.New("fakeip_icmp local reply program is unavailable"))
			}
			icmpAttached, err := link.AttachTCX(link.TCXOptions{
				Interface: linkDevice.Attrs().Index,
				Program:   icmpProgram,
				Attach:    CiliumEBPF.AttachTCXEgress,
			})
			if err != nil {
				return closeLinks(err)
			}
			attachment.localICMPLink = icmpAttached
		}
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
		if backend.FakeIPICMPEnabled() {
			icmpProgram := backend.FakeIPICMPSharedReplyProgram(attachment.framing)
			if icmpProgram == nil {
				return closeLinks(E.New("fakeip_icmp shared reply program is unavailable"))
			}
			icmpAttached, err := link.AttachTCX(link.TCXOptions{
				Interface: linkDevice.Attrs().Index,
				Program:   icmpProgram,
				Attach:    CiliumEBPF.AttachTCXIngress,
			})
			if err != nil {
				return closeLinks(err)
			}
			attachment.sharedICMPLink = icmpAttached
		}
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
	return updateTCInterfaceAttachmentWithOps(
		linkByName,
		backend,
		attachment,
		role,
		sharedSourceMACPolicy,
		priority,
		tcInterfaceAttachmentOps{
			ensureClsact: ensureTCClsact,
			attachFilter: attachTCFilter,
			detachFilter: detachTCFilter,
		},
	)
}

type tcInterfaceAttachmentOps struct {
	ensureClsact func(netlink.Link) error
	attachFilter func(netlink.Link, uint32, int, string, uint16, uint16) (*netlink.BpfFilter, error)
	detachFilter func(*netlink.BpfFilter) error
}

func updateTCInterfaceAttachmentWithOps(
	linkByName func(string) (netlink.Link, error),
	backend *commonEBPF.TCBackend,
	attachment *tcInterfaceAttachment,
	role tcInterfaceRole,
	sharedSourceMACPolicy bool,
	priority uint16,
	ops tcInterfaceAttachmentOps,
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
	if err = ops.ensureClsact(link); err != nil {
		return E.Cause(err, "ensure TC clsact on interface ", attachment.interfaceName)
	}
	attachment.attachmentType = "clsact"
	addedLocal := false
	addedLocalICMP := false
	addedShared := false
	addedSharedICMP := false
	rollbackAdded := func(startErr error) error {
		var rollbackErr error
		if addedSharedICMP {
			rollbackErr = E.Errors(rollbackErr, detachTCFilterOwnedWith(&attachment.sharedICMPFilter, ops.detachFilter))
		}
		if addedShared {
			rollbackErr = E.Errors(rollbackErr, detachTCFilterOwnedWith(&attachment.sharedFilter, ops.detachFilter))
		}
		if addedLocalICMP {
			rollbackErr = E.Errors(rollbackErr, detachTCFilterOwnedWith(&attachment.localICMPFilter, ops.detachFilter))
		}
		if addedLocal {
			rollbackErr = E.Errors(rollbackErr, detachTCFilterOwnedWith(&attachment.localFilter, ops.detachFilter))
		}
		return E.Errors(startErr, rollbackErr)
	}
	if role.local && attachment.localFilter == nil {
		attachment.localFilter, err = ops.attachFilter(
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
	if role.local && backend.FakeIPICMPEnabled() && attachment.localICMPFilter == nil {
		attachment.localICMPFilter, err = ops.attachFilter(
			link,
			netlink.HANDLE_MIN_EGRESS,
			backend.FakeIPICMPLocalReplyProgramFD(attachment.framing),
			"sb_icmp_local",
			tcLocalICMPReplyFilterHandle,
			priority,
		)
		if err != nil {
			return rollbackAdded(E.Cause(err, "attach fakeip_icmp local reply filter on interface ", attachment.interfaceName))
		}
		addedLocalICMP = true
	}
	if role.shared && attachment.sharedFilter == nil {
		attachment.sharedFilter, err = ops.attachFilter(
			link,
			netlink.HANDLE_MIN_INGRESS,
			backend.SharedIngressProgramFD(attachment.framing),
			"sb_tc_shared",
			tcSharedFilterHandle,
			priority,
		)
		if err != nil {
			return rollbackAdded(E.Cause(err, "attach TC shared ingress filter on interface ", attachment.interfaceName))
		}
		addedShared = true
	}
	if role.shared && backend.FakeIPICMPEnabled() && attachment.sharedICMPFilter == nil {
		attachment.sharedICMPFilter, err = ops.attachFilter(
			link,
			netlink.HANDLE_MIN_INGRESS,
			backend.FakeIPICMPSharedReplyProgramFD(attachment.framing),
			"sb_icmp_shared",
			tcSharedICMPReplyFilterHandle,
			priority,
		)
		if err != nil {
			return rollbackAdded(E.Cause(err, "attach fakeip_icmp shared reply filter on interface ", attachment.interfaceName))
		}
		addedSharedICMP = true
	}
	if !role.shared {
		if err = detachTCFilterOwnedWith(&attachment.sharedICMPFilter, ops.detachFilter); err != nil {
			return rollbackAdded(E.Cause(err, "detach fakeip_icmp shared reply filter from interface ", attachment.interfaceName))
		}
		if err = detachTCFilterOwnedWith(&attachment.sharedFilter, ops.detachFilter); err != nil {
			return rollbackAdded(E.Cause(err, "detach TC shared ingress filter from interface ", attachment.interfaceName))
		}
	}
	if !role.local {
		if err = detachTCFilterOwnedWith(&attachment.localICMPFilter, ops.detachFilter); err != nil {
			return rollbackAdded(E.Cause(err, "detach fakeip_icmp local reply filter from interface ", attachment.interfaceName))
		}
		if err = detachTCFilterOwnedWith(&attachment.localFilter, ops.detachFilter); err != nil {
			return rollbackAdded(E.Cause(err, "detach TC local egress filter from interface ", attachment.interfaceName))
		}
	}
	attachment.role = role
	return nil
}

// updateTCXInterfaceAttachment reconciles a TCX attachment toward role.
// There is deliberately no role == attachment.role fast return here: the
// hasLocal/hasShared computation transitionTCXInterfaceRole receives below
// folds fakeip_icmp link health into an unchanged role's own "is this role
// actually fully attached" state specifically so a health-check-driven
// repair (role never changes, only a link silently went missing) reaches
// transitionTCXInterfaceRole's attach/detach logic instead of being told
// there is nothing to do before that logic ever sees the gap.
func updateTCXInterfaceAttachment(
	linkDevice netlink.Link,
	backend *commonEBPF.TCBackend,
	attachment *tcInterfaceAttachment,
	role tcInterfaceRole,
) error {
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
		attached := attachment.sharedLink
		if local {
			attached = attachment.localLink
		}
		added := false
		if attached == nil {
			var err error
			attached, err = link.AttachTCX(link.TCXOptions{
				Interface: linkDevice.Attrs().Index,
				Program:   program,
				Attach:    attachType,
			})
			if err != nil {
				return err
			}
			added = true
			if local {
				attachment.localLink = attached
			} else {
				attachment.sharedLink = attached
			}
		}
		if backend.FakeIPICMPEnabled() {
			icmpExisting := attachment.sharedICMPLink
			if local {
				icmpExisting = attachment.localICMPLink
			}
			if icmpExisting != nil {
				return nil
			}
			icmpProgram := backend.FakeIPICMPSharedReplyProgram(attachment.framing)
			if local {
				icmpProgram = backend.FakeIPICMPLocalReplyProgram(attachment.framing)
			}
			if icmpProgram == nil {
				startErr := E.New("fakeip_icmp shared reply program is unavailable")
				if local {
					startErr = E.New("fakeip_icmp local reply program is unavailable")
				}
				if added {
					return E.Errors(startErr, closeTCXRoleLink(attachment, local))
				}
				return startErr
			}
			icmpAttached, err := link.AttachTCX(link.TCXOptions{
				Interface: linkDevice.Attrs().Index,
				Program:   icmpProgram,
				Attach:    attachType,
			})
			if err != nil {
				if added {
					return E.Errors(err, closeTCXRoleLink(attachment, local))
				}
				return err
			}
			if local {
				attachment.localICMPLink = icmpAttached
			} else {
				attachment.sharedICMPLink = icmpAttached
			}
		}
		return nil
	}
	detach := func(local bool) error {
		if local {
			if err := closeOwned(&attachment.localICMPLink); err != nil {
				return err
			}
			return closeTCXRoleLink(attachment, true)
		}
		if err := closeOwned(&attachment.sharedICMPLink); err != nil {
			return err
		}
		return closeTCXRoleLink(attachment, false)
	}
	if err := transitionTCXInterfaceRole(
		attachment.role,
		role,
		attachment.localLink != nil && (!backend.FakeIPICMPEnabled() || attachment.localICMPLink != nil),
		attachment.sharedLink != nil && (!backend.FakeIPICMPEnabled() || attachment.sharedICMPLink != nil),
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
//
// It reconciles the attachment's actual link state (hasLocal/hasShared)
// toward desired, attaching or detaching only what the two disagree on — or,
// when the role itself is unchanged but hasLocal/hasShared says a role's
// link is missing anyway (the caller folds fakeip_icmp link health into
// these two booleans specifically for this), repairing just that gap. There
// is deliberately no current == desired fast return before that: the four
// branches below already no-op on their own when hasLocal/hasShared already
// match what desired implies, so the only thing an early return before them
// could add is skipping a repair a caller asked for by passing
// hasLocal/hasShared false despite an unchanged role.
func transitionTCXInterfaceRole(
	current tcInterfaceRole,
	desired tcInterfaceRole,
	hasLocal bool,
	hasShared bool,
	attach func(local bool) error,
	detach func(local bool) error,
) error {
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
	if closeErr == nil {
		a.attachmentType = ""
	}
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

func (a *tcInterfaceAttachment) hasAttachedResources() bool {
	return a != nil && (a.localFilter != nil || a.sharedFilter != nil ||
		a.localICMPFilter != nil || a.sharedICMPFilter != nil ||
		a.localLink != nil || a.sharedLink != nil || a.localICMPLink != nil || a.sharedICMPLink != nil)
}

func (a *tcInterfaceAttachment) HasOwnedResources() bool {
	return a != nil && (a.hasAttachedResources() || a.lockOwned && a.lock != nil)
}

func (a *tcInterfaceAttachment) IsClosed() bool { return !a.HasOwnedResources() }

func (a *tcInterfaceAttachment) Close() error {
	if a == nil {
		return nil
	}
	a.closing = true
	closeErr := E.Errors(a.closeFilters(), a.closeLinks())
	if a.hasAttachedResources() {
		return closeErr
	}
	if a.lockOwned {
		if err := closeOwned(&a.lock); err != nil {
			return E.Errors(closeErr, err)
		}
	}
	a.lock = nil
	a.lockOwned = false
	a.attachmentType = ""
	return closeErr
}

func (a *tcInterfaceAttachment) closeFilters() error {
	if a == nil {
		return nil
	}
	detach := a.detachFilter
	if detach == nil {
		detach = detachTCFilter
	}
	return E.Errors(
		detachTCFilterOwnedWith(&a.sharedICMPFilter, detach),
		detachTCFilterOwnedWith(&a.sharedFilter, detach),
		detachTCFilterOwnedWith(&a.localICMPFilter, detach),
		detachTCFilterOwnedWith(&a.localFilter, detach),
	)
}

func (a *tcInterfaceAttachment) closeLinks() error {
	if a == nil {
		return nil
	}
	var closeErr error
	closeErr = E.Errors(closeErr, closeOwned(&a.sharedICMPLink))
	closeErr = E.Errors(closeErr, closeTCXRoleLink(a, false))
	closeErr = E.Errors(closeErr, closeOwned(&a.localICMPLink))
	closeErr = E.Errors(closeErr, closeTCXRoleLink(a, true))
	return closeErr
}

func detachTCFilterOwned(filter **netlink.BpfFilter) error {
	return detachTCFilterOwnedWith(filter, detachTCFilter)
}

func detachTCFilterOwnedWith(filter **netlink.BpfFilter, detach func(*netlink.BpfFilter) error) error {
	if filter == nil || *filter == nil {
		return nil
	}
	if err := detach(*filter); err != nil {
		return err
	}
	*filter = nil
	return nil
}

func closeOwned[T io.Closer](closer *T) error {
	if closer == nil || any(*closer) == nil {
		return nil
	}
	if err := (*closer).Close(); err != nil {
		return err
	}
	var zero T
	*closer = zero
	return nil
}

func closeTCXRoleLink(attachment *tcInterfaceAttachment, local bool) error {
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

func openTCAttachments(attachments []*tcInterfaceAttachment) []*tcInterfaceAttachment {
	attachments = slices.DeleteFunc(attachments, (*tcInterfaceAttachment).IsClosed)
	if len(attachments) == 0 {
		return nil
	}
	return attachments
}

func (d *tcDataPlane) closeRetired() error {
	closeErr := closeTCInterfaceAttachments(d.retiredAttachments)
	d.retiredAttachments = openTCAttachments(d.retiredAttachments)
	for _, delivery := range d.retiredDeliveries {
		closeErr = E.Errors(closeErr, delivery.Close())
	}
	d.retiredDeliveries = slices.DeleteFunc(d.retiredDeliveries, (*tcDeliveryLink).IsClosed)
	return closeErr
}

func (d *tcDataPlane) IsClosed() bool {
	if d == nil {
		return true
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.backend == nil && len(d.attachments) == 0 && len(d.retiredAttachments) == 0 &&
		d.routing == nil && d.delivery == nil && len(d.retiredDeliveries) == 0
}

func (d *tcDataPlane) Close() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	d.closing = true
	var closeErr error
	if d.backend != nil {
		closeErr = d.backend.Disable()
	}
	closeErr = E.Errors(closeErr, closeTCInterfaceAttachments(d.attachments), d.closeRetired())
	d.attachments = openTCAttachments(d.attachments)
	// Live filters still depend on the delivery path, routing and program maps.
	if len(d.attachments) != 0 || len(d.retiredAttachments) != 0 {
		return closeErr
	}
	closeErr = E.Errors(closeErr, d.routing.Close())
	if d.routing.IsClosed() {
		d.routing = nil
	}
	closeErr = E.Errors(closeErr, d.delivery.Close())
	if d.delivery.IsClosed() {
		d.delivery = nil
	}
	if d.routing != nil || d.delivery != nil || len(d.retiredDeliveries) != 0 {
		return closeErr
	}
	if d.backend != nil {
		if err := d.backend.Close(); err != nil {
			closeErr = E.Errors(closeErr, err)
		} else {
			d.backend = nil
		}
	}
	return closeErr
}
