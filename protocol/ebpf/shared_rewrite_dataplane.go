//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
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
)

const (
	sharedRewriteIngressFilterHandle = 0x5342
	sharedRewriteEgressFilterHandle  = 0x5343
)

var sharedRewriteAttachmentSequence atomic.Uint32

type sharedRewriteAttachmentOptions struct {
	skipLock  bool
	temporary bool
}

func temporarySharedRewriteAttachmentOptions() sharedRewriteAttachmentOptions {
	return sharedRewriteAttachmentOptions{temporary: true}
}

type sharedRewriteDataPlane struct {
	access        sync.Mutex
	owner         *sharedRewrite
	backend       *commonEBPF.SharedNetworkBackend
	attachments   map[string]*sharedRewriteAttachment
	hostAddresses []netip.Addr
	priority      uint16
	enabled       bool
	ready         bool
}

type sharedRewriteAttachment struct {
	interfaceName   string
	interfaceIndex  int
	lock            io.Closer
	ingressFilter   *netlink.BpfFilter
	egressFilter    *netlink.BpfFilter
	ingressName     string
	egressName      string
	ingressHandle   uint16
	egressHandle    uint16
	ingressLink     link.Link
	egressLink      link.Link
	restoreLocalnet bool
	attachmentType  string
}

func newSharedRewriteDataPlane(owner *sharedRewrite, priority uint16) *sharedRewriteDataPlane {
	return &sharedRewriteDataPlane{
		owner:       owner,
		attachments: make(map[string]*sharedRewriteAttachment),
		priority:    priority,
	}
}

func (d *sharedRewriteDataPlane) reconcile(interfaceNames []string, hostAddresses []netip.Addr) error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()

	desired := make(map[string]netlink.Link, len(interfaceNames))
	for _, interfaceName := range interfaceNames {
		device, err := netlink.LinkByName(interfaceName)
		if tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return E.Cause(err, "find shared packet-rewrite interface ", interfaceName)
		}
		framing, err := tcLinkFraming(device)
		if err != nil {
			return err
		}
		if framing != commonEBPF.TCLinkFramingEthernet {
			return E.New("shared packet-rewrite interface ", interfaceName, " must use Ethernet framing")
		}
		desired[interfaceName] = device
	}

	backend := d.backend
	newBackend := false
	if len(desired) > 0 && backend == nil {
		var err error
		backend, err = d.owner.prepareBackend()
		if err != nil {
			return E.Cause(err, "initialize shared packet-rewrite backend")
		}
		newBackend = true
	}
	hostChanged := backend != nil && !slices.Equal(d.hostAddresses, hostAddresses)
	if hostChanged {
		if err := backend.UpdateHostAddresses(hostAddresses); err != nil {
			if newBackend {
				return E.Errors(
					E.Cause(err, "update shared packet-rewrite host addresses"),
					discardSharedRewriteBackend(d.owner, backend),
				)
			}
			return E.Cause(err, "update shared packet-rewrite host addresses")
		}
	}

	current := make(map[string]*sharedRewriteAttachment, len(d.attachments))
	for name, attachment := range d.attachments {
		current[name] = attachment
	}
	candidate := make(map[string]*sharedRewriteAttachment, len(desired))
	created := make([]*sharedRewriteAttachment, 0, len(desired))
	retired := make([]*sharedRewriteAttachment, 0, len(d.attachments))
	changed := hostChanged
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	slices.Sort(names)

	cleanupCandidates := func(cause error) error {
		for _, attachment := range slices.Backward(created) {
			cause = E.Errors(cause, attachment.Close())
		}
		if hostChanged {
			rollbackErr := backend.UpdateHostAddresses(d.hostAddresses)
			if rollbackErr != nil {
				cause = E.Errors(cause, E.Cause(rollbackErr, "rollback shared packet-rewrite host addresses"))
			}
		}
		if newBackend {
			cause = E.Errors(cause, discardSharedRewriteBackend(d.owner, backend))
		}
		return cause
	}

	for _, name := range names {
		device := desired[name]
		previous := current[name]
		if previous != nil && device.Attrs().Index == previous.interfaceIndex {
			localnetChanged, err := ensureSharedRewriteLocalnet(name)
			if err != nil {
				return cleanupCandidates(E.Cause(err, "repair route_localnet for ", name))
			}
			if localnetChanged {
				previous.restoreLocalnet = true
			}
			healthy, err := previous.healthy(device, d.priority)
			if err != nil {
				return cleanupCandidates(E.Cause(err, "inspect shared packet-rewrite attachment on ", name))
			}
			if healthy {
				candidate[name] = previous
				delete(current, name)
				continue
			}
		}
		if previous != nil {
			retired = append(retired, previous)
		}
		options := sharedRewriteAttachmentOptions{}
		if previous != nil && device.Attrs().Index == previous.interfaceIndex {
			options = temporarySharedRewriteAttachmentOptions()
			options.skipLock = true
		} else if previous != nil {
			options = temporarySharedRewriteAttachmentOptions()
		}
		attachment, err := attachSharedRewriteInterfaceWithOptions(device, backend, d.priority, options)
		if err != nil {
			return cleanupCandidates(E.Cause(err, "attach shared packet-rewrite interface ", name))
		}
		candidate[name] = attachment
		created = append(created, attachment)
		changed = true
	}
	for _, previous := range current {
		retired = append(retired, previous)
		changed = true
	}

	wantEnabled := len(candidate) > 0
	if wantEnabled != d.enabled {
		var err error
		if wantEnabled {
			err = backend.Enable()
		} else if backend != nil {
			err = backend.Disable()
		}
		if err != nil {
			return cleanupCandidates(err)
		}
		changed = true
	}

	var closeErr error
	for _, previous := range retired {
		replacement := candidate[previous.interfaceName]
		if replacement != nil && replacement.interfaceIndex == previous.interfaceIndex {
			lock := previous.lock
			previous.lock = nil
			if previous.restoreLocalnet {
				replacement.restoreLocalnet = true
				previous.restoreLocalnet = false
			}
			if err := d.detachLocked(previous); err != nil {
				// The candidate is already active. Keep it as the committed state
				// and report the old attachment cleanup failure to the caller.
				closeErr = E.Errors(closeErr, E.Cause(err, "detach shared packet-rewrite interface ", previous.interfaceName))
				changed = true
				if replacement.lock == nil {
					replacement.lock = lock
				}
				continue
			}
			replacement.lock = lock
		} else {
			if err := d.detachLocked(previous); err != nil {
				// Continue committing the candidate topology so a stale attachment
				// cannot prevent a newly discovered interface from being used.
				closeErr = E.Errors(closeErr, E.Cause(err, "detach shared packet-rewrite interface ", previous.interfaceName))
				changed = true
			}
		}
	}

	d.backend = backend
	d.attachments = candidate
	d.hostAddresses = slices.Clone(hostAddresses)
	d.enabled = wantEnabled
	if changed {
		d.owner.udpNat.Purge()
	}
	if d.enabled && !d.ready {
		d.ready = true
		d.owner.sharedRewriteReadyLocked(d.attachmentDescriptionsLocked())
	}
	return closeErr
}

func discardSharedRewriteBackend(owner *sharedRewrite, backend *commonEBPF.SharedNetworkBackend) error {
	if backend == nil {
		return nil
	}
	if owner.sharedBackendInstance() == backend {
		owner.takeSharedBackend()
	}
	return backend.Close()
}

func (d *sharedRewriteDataPlane) detachLocked(attachment *sharedRewriteAttachment) error {
	if d.backend != nil {
		if _, _, err := d.backend.PurgeInterfaceFlows(uint32(attachment.interfaceIndex), d.backend.MapCapacity().Proxy); err != nil {
			d.owner.janitorWarnings.warn(d.owner.inbound.logger, "purge shared packet-rewrite state for ", attachment.interfaceName, ": ", err)
		}
	}
	return attachment.Close()
}

func (d *sharedRewriteDataPlane) isEnabled() bool {
	if d == nil {
		return false
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.enabled
}

func (d *sharedRewriteDataPlane) attachmentDescriptions() []string {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.attachmentDescriptionsLocked()
}

func (d *sharedRewriteDataPlane) attachmentDescriptionsLocked() []string {
	descriptions := make([]string, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		descriptions = append(descriptions, attachment.interfaceName+"("+attachment.attachmentType+")")
	}
	slices.Sort(descriptions)
	return descriptions
}

func (d *sharedRewriteDataPlane) Close() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	var closeErr error
	if d.enabled && d.backend != nil {
		closeErr = d.backend.Disable()
		d.enabled = false
	}
	for name, attachment := range d.attachments {
		closeErr = E.Errors(closeErr, d.detachLocked(attachment))
		delete(d.attachments, name)
	}
	return closeErr
}

func attachSharedRewriteInterface(
	device netlink.Link,
	backend *commonEBPF.SharedNetworkBackend,
	priority uint16,
) (*sharedRewriteAttachment, error) {
	return attachSharedRewriteInterfaceWithOptions(device, backend, priority, sharedRewriteAttachmentOptions{})
}

func attachSharedRewriteInterfaceWithOptions(
	device netlink.Link,
	backend *commonEBPF.SharedNetworkBackend,
	priority uint16,
	options sharedRewriteAttachmentOptions,
) (*sharedRewriteAttachment, error) {
	name := device.Attrs().Name
	attachment := &sharedRewriteAttachment{interfaceName: name, interfaceIndex: device.Attrs().Index}
	var err error
	cleanup := func(err error) (*sharedRewriteAttachment, error) {
		return nil, E.Errors(err, attachment.Close())
	}
	if !options.skipLock {
		interfaceLock, err := acquireTCInterfaceLock(name, device.Attrs().Index)
		if err != nil {
			return nil, err
		}
		attachment.lock = interfaceLock
	}
	attachment.ingressName = "sb_share_in"
	attachment.egressName = "sb_share_out"
	attachment.ingressHandle = sharedRewriteIngressFilterHandle
	attachment.egressHandle = sharedRewriteEgressFilterHandle
	if options.temporary {
		sequence := sharedRewriteAttachmentSequence.Add(1) & 0x0fff
		if sequence == 0 {
			sequence = 1
		}
		suffix := strconv.FormatUint(uint64(sequence), 16)
		attachment.ingressName = "sbi" + suffix
		attachment.egressName = "sbo" + suffix
		attachment.ingressHandle += uint16(sequence)
		attachment.egressHandle += uint16(sequence)
	}
	attachment.restoreLocalnet, err = enableSharedRewriteLocalnet(name)
	if err != nil {
		return cleanup(err)
	}
	if priority == defaultTCPriority && tcxSupport.Load() != tcxSupportUnavailable {
		attachment.egressLink, err = link.AttachTCX(link.TCXOptions{
			Interface: device.Attrs().Index,
			Program:   backend.EgressProgram(),
			Attach:    CiliumEBPF.AttachTCXEgress,
		})
		if err == nil {
			attachment.ingressLink, err = link.AttachTCX(link.TCXOptions{
				Interface: device.Attrs().Index,
				Program:   backend.IngressProgram(),
				Attach:    CiliumEBPF.AttachTCXIngress,
			})
		}
		if err == nil {
			tcxSupport.Store(tcxSupportAvailable)
			attachment.attachmentType = "tcx"
			return attachment, nil
		}
		_ = attachment.closeLinks()
		if !tcxUnsupportedError(err) {
			return cleanup(err)
		}
		tcxSupport.CompareAndSwap(tcxSupportUnknown, tcxSupportUnavailable)
	}
	if err = ensureTCClsact(device); err != nil {
		return cleanup(err)
	}
	attachment.egressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_EGRESS, backend.EgressProgramFD(), attachment.egressName, attachment.egressHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	attachment.ingressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_INGRESS, backend.IngressProgramFD(), attachment.ingressName, attachment.ingressHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	attachment.attachmentType = "clsact"
	return attachment, nil
}

func (a *sharedRewriteAttachment) healthy(device netlink.Link, priority uint16) (bool, error) {
	if a.ingressLink != nil || a.egressLink != nil {
		ingress, err := tcxLinkAttached(a.ingressLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
		if err != nil || !ingress {
			return false, err
		}
		return tcxLinkAttached(a.egressLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress)
	}
	ingress, err := tcFilterAttached(device, netlink.HANDLE_MIN_INGRESS, a.ingressName, a.ingressHandle, priority)
	if err != nil || !ingress {
		return false, err
	}
	return tcFilterAttached(device, netlink.HANDLE_MIN_EGRESS, a.egressName, a.egressHandle, priority)
}

func (a *sharedRewriteAttachment) closeLinks() error {
	var closeErr error
	if a.ingressLink != nil {
		closeErr = a.ingressLink.Close()
		a.ingressLink = nil
	}
	if a.egressLink != nil {
		closeErr = E.Errors(closeErr, a.egressLink.Close())
		a.egressLink = nil
	}
	return closeErr
}

func (a *sharedRewriteAttachment) Close() error {
	if a == nil {
		return nil
	}
	closeErr := E.Errors(a.closeLinks(), detachTCFilter(a.ingressFilter), detachTCFilter(a.egressFilter))
	a.ingressFilter = nil
	a.egressFilter = nil
	if a.restoreLocalnet {
		closeErr = E.Errors(closeErr, restoreSharedRewriteLocalnet(a.interfaceName))
		a.restoreLocalnet = false
	}
	if a.lock != nil {
		closeErr = E.Errors(closeErr, a.lock.Close())
		a.lock = nil
	}
	return closeErr
}

func sharedRewriteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func enableSharedRewriteLocalnet(interfaceName string) (bool, error) {
	return ensureSharedRewriteLocalnet(interfaceName)
}

func ensureSharedRewriteLocalnet(interfaceName string) (bool, error) {
	value, err := os.ReadFile(sharedRewriteLocalnetPath(interfaceName))
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	switch strings.TrimSpace(string(value)) {
	case "1":
		return false, nil
	case "0":
		if err = os.WriteFile(sharedRewriteLocalnetPath(interfaceName), []byte("1"), 0o644); err != nil {
			return false, E.Cause(err, "enable route_localnet for ", interfaceName)
		}
		return true, nil
	default:
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
}

func restoreSharedRewriteLocalnet(interfaceName string) error {
	path := sharedRewriteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}
