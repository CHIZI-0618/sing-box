//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"net/netip"
	"slices"
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
