//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

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

type sharedRewriteDataPlane struct {
	access        sync.Mutex
	owner         *sharedRewrite
	backend       *commonEBPF.SharedNetworkBackend
	attachments   map[string]*sharedRewriteAttachment
	hostAddresses []netip.Addr
	priority      uint16
	enabled       bool
	ready         bool
	// flowsInvalidated records that the interception state a packet flow
	// depends on has been torn down — an attachment released, one attached, or
	// the backend toggled. detachLocked purges the kernel flows for an
	// interface, so the userspace NAT entries that pointed at them are stale
	// from that moment, whether or not the detach or anything after it
	// succeeded. Tracking it separately keeps every error exit from having to
	// re-derive it from whether an attachment happened to change.
	flowsInvalidated bool
	// hooks is nil in production. Tests set it to drive and observe the paths
	// that otherwise need a kernel.
	hooks *sharedRewriteDataPlaneHooks
}

type sharedRewriteDataPlaneHooks struct {
	attach      sharedRewriteAttachFunc
	setEnabled  func(enabled bool) error
	purgeUDPNat func()
}

type sharedRewriteAttachFunc func(
	device netlink.Link,
	backend *commonEBPF.SharedNetworkBackend,
	priority uint16,
) (*sharedRewriteAttachment, error)

type sharedRewriteAttachment struct {
	interfaceName   string
	interfaceIndex  int
	lock            io.Closer
	ingressFilter   *netlink.BpfFilter
	egressFilter    *netlink.BpfFilter
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
	// Runs before the unlock on every return, so no error exit can skip it.
	defer d.purgeInvalidatedFlowsLocked()

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

	if len(desired) > 0 && d.backend == nil {
		backend, err := d.owner.prepareBackend()
		if err != nil {
			return E.Cause(err, "initialize shared packet-rewrite backend")
		}
		d.backend = backend
	}
	if d.backend != nil && !slices.Equal(d.hostAddresses, hostAddresses) {
		if err := d.backend.UpdateHostAddresses(hostAddresses); err != nil {
			return E.Cause(err, "update shared packet-rewrite host addresses")
		}
		d.hostAddresses = slices.Clone(hostAddresses)
	}

	// Collect what has to go instead of detaching it here. An attachment that is
	// being replaced has to stay in place until its replacement exists: a filter
	// and its interface lock cannot coexist with a second copy, so detaching
	// first and failing to reattach leaves the interface completely unattached,
	// and nothing retries until the next netlink event.
	var stale []string
	for name, attachment := range d.attachments {
		device, keep := desired[name]
		if keep && device.Attrs().Index == attachment.interfaceIndex {
			localnetChanged, err := ensureSharedRewriteLocalnet(name)
			if err != nil {
				return E.Cause(err, "repair route_localnet for ", name)
			}
			if localnetChanged {
				attachment.restoreLocalnet = true
			}
			healthy, err := attachment.healthy(device, d.priority)
			if err != nil {
				return E.Cause(err, "inspect shared packet-rewrite attachment on ", name)
			}
			if healthy {
				delete(desired, name)
				continue
			}
		}
		stale = append(stale, name)
	}
	slices.Sort(stale)
	// Interfaces that are no longer wanted are released before the attach pass so
	// their locks and filters do not block a replacement elsewhere; interfaces
	// that are being reattached keep their current attachment for now.
	for _, name := range stale {
		if _, replacing := desired[name]; replacing {
			continue
		}
		if err := d.detachLocked(d.attachments[name]); err != nil {
			return E.Cause(err, "detach shared packet-rewrite interface ", name)
		}
		delete(d.attachments, name)
	}
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	slices.Sort(names)
	if err := d.applyAttachmentsLocked(names, desired); err != nil {
		return err
	}

	if err := d.syncEnabledLocked(); err != nil {
		return err
	}
	if d.enabled && !d.ready {
		d.ready = true
		d.owner.sharedRewriteReadyLocked(d.attachmentDescriptionsLocked())
	}
	return nil
}

// applyAttachmentsLocked attaches every wanted interface, replacing the ones
// whose current attachment is unusable.
//
// It is separated from reconcile so tests can drive the attach failure paths,
// which are not reachable through netlink. Flow invalidation and the enabled
// flag are recorded on the data plane, so reconcile cleans up after every
// exit here without this function having to report what it touched.
func (d *sharedRewriteDataPlane) applyAttachmentsLocked(
	names []string,
	desired map[string]netlink.Link,
) error {
	var added []string
	fail := func(name string, attachErr error, rollbackErr error) error {
		if rollbackErr != nil {
			rollbackErr = E.Cause(rollbackErr, "rollback new shared packet-rewrite attachments")
		}
		// The enabled flag still has to match what is actually attached before
		// giving up; the NAT purge is handled by reconcile for every exit.
		if enableErr := d.syncEnabledLocked(); enableErr != nil {
			rollbackErr = E.Errors(rollbackErr, enableErr)
		}
		return E.Errors(
			E.Cause(attachErr, "attach shared packet-rewrite interface ", name),
			rollbackErr,
		)
	}
	for _, name := range names {
		device := desired[name]
		replacing := d.attachments[name] != nil
		if replacing {
			// A replacement cannot be built alongside the attachment it replaces,
			// so release it here rather than in the pass above: the interface is
			// then unattached for one call instead of for the rest of the
			// reconcile, and an attach failure is repaired immediately below.
			if err := d.detachLocked(d.attachments[name]); err != nil {
				return fail(name, E.Cause(err, "detach existing attachment"), nil)
			}
			delete(d.attachments, name)
		}
		attachment, err := d.attachInterfaceLocked(device)
		if err != nil {
			rollbackErr := error(nil)
			if replacing {
				// This retries the call that just failed. It recovers a transient
				// failure and nothing more: a persistent one leaves the interface
				// unattached until the next netlink event, because there is no
				// backoff retry in this data plane.
				restored, restoreErr := d.attachInterfaceLocked(device)
				if restoreErr != nil {
					rollbackErr = E.Errors(rollbackErr, E.Cause(restoreErr, "restore shared packet-rewrite interface ", name))
				} else {
					d.attachments[name] = restored
				}
			}
			// Interfaces that were newly added this round are undone; interfaces
			// that were already attached on entry keep their fresh attachment,
			// because tearing those down would recreate the gap this rollback
			// exists to avoid.
			for index := len(added) - 1; index >= 0; index-- {
				addedName := added[index]
				rollbackErr = E.Errors(rollbackErr, d.detachLocked(d.attachments[addedName]))
				delete(d.attachments, addedName)
			}
			return fail(name, err, rollbackErr)
		}
		d.attachments[name] = attachment
		d.flowsInvalidated = true
		if !replacing {
			added = append(added, name)
		}
	}
	return nil
}

func (d *sharedRewriteDataPlane) attachInterfaceLocked(device netlink.Link) (*sharedRewriteAttachment, error) {
	if d.hooks != nil && d.hooks.attach != nil {
		return d.hooks.attach(device, d.backend, d.priority)
	}
	return attachSharedRewriteInterface(device, d.backend, d.priority)
}

// purgeInvalidatedFlowsLocked drops the userspace NAT entries whose kernel
// flows are gone. reconcile defers it so it runs on every exit, including the
// ones that give up after a detach already purged the kernel side.
func (d *sharedRewriteDataPlane) purgeInvalidatedFlowsLocked() {
	if !d.flowsInvalidated {
		return
	}
	d.flowsInvalidated = false
	if d.hooks != nil && d.hooks.purgeUDPNat != nil {
		d.hooks.purgeUDPNat()
		return
	}
	if d.owner == nil || d.owner.udpNat == nil {
		return
	}
	d.owner.udpNat.Purge()
}

// syncEnabledChangedLocked brings the backend's enabled state in line with the
// attachments that are actually in place, and reports whether it moved.
func (d *sharedRewriteDataPlane) syncEnabledChangedLocked() (bool, error) {
	wantEnabled := len(d.attachments) > 0 &&
		(d.backend != nil || (d.hooks != nil && d.hooks.setEnabled != nil))
	if wantEnabled == d.enabled {
		return false, nil
	}
	if err := d.setBackendEnabledLocked(wantEnabled); err != nil {
		return false, err
	}
	d.enabled = wantEnabled
	d.flowsInvalidated = true
	return true, nil
}

func (d *sharedRewriteDataPlane) setBackendEnabledLocked(enabled bool) error {
	if d.hooks != nil && d.hooks.setEnabled != nil {
		return d.hooks.setEnabled(enabled)
	}
	if d.backend == nil {
		return nil
	}
	if enabled {
		return d.backend.Enable()
	}
	return d.backend.Disable()
}

// syncEnabledLocked is the error-path form: a reconcile that gives up partway
// must not leave the backend enabled with nothing attached.
func (d *sharedRewriteDataPlane) syncEnabledLocked() error {
	_, err := d.syncEnabledChangedLocked()
	return err
}

func (d *sharedRewriteDataPlane) detachLocked(attachment *sharedRewriteAttachment) error {
	// Set before anything can fail: releasing an attachment invalidates the
	// flows through it regardless of how the rest of the teardown goes.
	d.flowsInvalidated = true
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
	name := device.Attrs().Name
	attachment := &sharedRewriteAttachment{interfaceName: name, interfaceIndex: device.Attrs().Index}
	cleanup := func(err error) (*sharedRewriteAttachment, error) {
		return nil, E.Errors(err, attachment.Close())
	}
	interfaceLock, err := acquireTCInterfaceLock(name, device.Attrs().Index)
	if err != nil {
		return nil, err
	}
	attachment.lock = interfaceLock
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
	attachment.egressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_EGRESS, backend.EgressProgramFD(), "sb_share_out", sharedRewriteEgressFilterHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	attachment.ingressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_INGRESS, backend.IngressProgramFD(), "sb_share_in", sharedRewriteIngressFilterHandle, priority)
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
	ingress, err := tcFilterAttached(device, netlink.HANDLE_MIN_INGRESS, "sb_share_in", sharedRewriteIngressFilterHandle, priority)
	if err != nil || !ingress {
		return false, err
	}
	return tcFilterAttached(device, netlink.HANDLE_MIN_EGRESS, "sb_share_out", sharedRewriteEgressFilterHandle, priority)
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
