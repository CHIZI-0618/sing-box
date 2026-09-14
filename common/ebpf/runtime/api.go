//go:build with_ebpf && (linux || android)

// Package runtime owns the Linux network resources that attach eBPF backends
// to interfaces and deliver selected traffic to userspace.
package runtime

import (
	"net/netip"

	"github.com/sagernet/netlink"
	core "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

const defaultTCPriority uint16 = 1

// AvailableLocalTCInterface returns the current local TC target, treating a
// missing interface as a transient no-target state.
func AvailableLocalTCInterface(enabled bool, interfaceName string) (string, error) {
	if !enabled || interfaceName == "" {
		return "", nil
	}
	_, err := netlink.LinkByName(interfaceName)
	if err != nil && tcLinkNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", E.Cause(err, "find local TC eBPF interface ", interfaceName)
	}
	return interfaceName, nil
}

// TCRuntime is the complete TC socket-assignment resource lifetime.
type TCRuntime interface {
	Backend() *core.TCBackend
	NetworkInfo() core.TCNetworkInfo
	Reconcile(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error
	RepairInfrastructure() (bool, error)
	AttachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error)
	AttachmentDescriptions() []string
	AttachmentDiagnostics() []core.AttachmentInfo
	UpdateHostAddresses(hostAddresses []netip.Addr) error
	Disable() error
	IsClosed() bool
	Close() error
}

// TCRuntimeConfig contains only mechanism-level startup state.
type TCRuntimeConfig struct {
	Backend               *core.TCBackend
	LocalEnabled          bool
	IPv6Enabled           bool
	LocalInterface        string
	SharedInterfaces      []string
	HostAddresses         []netip.Addr
	SharedSourceMACPolicy bool
	Priority              uint16
}

// NewTCRuntime starts and returns one complete TC resource owner.
func NewTCRuntime(config TCRuntimeConfig) (TCRuntime, error) {
	return startTCDataPlane(
		config.Backend,
		config.LocalEnabled,
		config.IPv6Enabled,
		config.LocalInterface,
		config.SharedInterfaces,
		config.HostAddresses,
		config.SharedSourceMACPolicy,
		config.Priority,
	)
}

// NewUnstartedTCRuntime transfers a prepared backend into a runtime owner so
// startup cleanup follows the same retryable lifetime as a started runtime.
func NewUnstartedTCRuntime(backend *core.TCBackend) TCRuntime {
	return &tcDataPlane{backend: backend}
}

func (d *tcDataPlane) Backend() *core.TCBackend {
	if d == nil {
		return nil
	}
	return d.backend
}

func (d *tcDataPlane) NetworkInfo() core.TCNetworkInfo {
	if d == nil {
		return core.TCNetworkInfo{}
	}
	d.access.Lock()
	defer d.access.Unlock()
	var info core.TCNetworkInfo
	if d.delivery != nil {
		info.DeliveryInterface = d.delivery.deliveryName
	}
	if d.routing != nil {
		info.RoutingMark = d.routing.mark
		info.RoutingTable = d.routing.table
		info.RoutingPriority = d.routing.priority
	}
	return info
}

func (d *tcDataPlane) Reconcile(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	return d.reconcile(localInterface, sharedInterfaces, hostAddresses)
}

func (d *tcDataPlane) RepairInfrastructure() (bool, error) {
	return d.repairInfrastructure()
}

func (d *tcDataPlane) AttachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	return d.attachmentStateChanged(localInterface, sharedInterfaces)
}

func (d *tcDataPlane) AttachmentDescriptions() []string {
	return d.attachmentDescriptions()
}

func (d *tcDataPlane) AttachmentDiagnostics() []core.AttachmentInfo {
	return d.attachmentDiagnostics()
}

func (d *tcDataPlane) UpdateHostAddresses(hostAddresses []netip.Addr) error {
	return d.updateHostAddresses(hostAddresses)
}

func (d *tcDataPlane) Disable() error { return d.disable() }

var _ TCRuntime = (*tcDataPlane)(nil)

// SharedPacketRewriteRuntime is the complete shared packet-rewrite resource
// lifetime. Retry scheduling remains an application concern.
type SharedPacketRewriteRuntime interface {
	Backend() *core.SharedNetworkBackend
	Reconcile(interfaceNames []string, hostAddresses []netip.Addr) error
	IsEnabled() bool
	AttachmentDescriptions() []string
	AttachmentDiagnostics() []core.AttachmentInfo
	BackendClosed() bool
	IsClosed() bool
	RequiresRebuild() bool
	Close() error
}

// SharedPacketRewriteHooks are the only application actions requested by the
// shared runtime. Callbacks must not call back into the same runtime directly.
type SharedPacketRewriteHooks struct {
	PrepareBackend     func() (*core.SharedNetworkBackend, error)
	PurgeUserspaceFlow func()
	Ready              func([]string)
	WarnFlowPurge      func(interfaceName string, err error)
}

type SharedPacketRewriteRuntimeConfig struct {
	Hooks    SharedPacketRewriteHooks
	Priority uint16
}

func NewSharedPacketRewriteRuntime(config SharedPacketRewriteRuntimeConfig) SharedPacketRewriteRuntime {
	return newSharedRewriteDataPlane(config.Hooks, config.Priority)
}

func (d *sharedRewriteDataPlane) Backend() *core.SharedNetworkBackend {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.backend
}

func (d *sharedRewriteDataPlane) Reconcile(interfaceNames []string, hostAddresses []netip.Addr) error {
	return d.reconcile(interfaceNames, hostAddresses)
}

func (d *sharedRewriteDataPlane) IsEnabled() bool { return d.isEnabled() }

func (d *sharedRewriteDataPlane) AttachmentDescriptions() []string {
	return d.attachmentDescriptions()
}

func (d *sharedRewriteDataPlane) AttachmentDiagnostics() []core.AttachmentInfo {
	return d.attachmentDiagnostics()
}

func (d *sharedRewriteDataPlane) IsClosed() bool {
	if d == nil {
		return true
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.backend == nil && len(d.attachments) == 0 && len(d.retiredAttachments) == 0
}

func (d *sharedRewriteDataPlane) BackendClosed() bool {
	if d == nil {
		return true
	}
	d.access.Lock()
	defer d.access.Unlock()
	closed, _ := d.backendStateLocked()
	return closed
}

func (d *sharedRewriteDataPlane) RequiresRebuild() bool {
	if d == nil {
		return false
	}
	d.access.Lock()
	defer d.access.Unlock()
	_, requiresRebuild := d.backendStateLocked()
	return requiresRebuild
}

var _ SharedPacketRewriteRuntime = (*sharedRewriteDataPlane)(nil)
