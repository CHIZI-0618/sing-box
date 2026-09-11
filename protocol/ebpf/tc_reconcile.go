//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

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
