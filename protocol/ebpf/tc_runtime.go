//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

// tcRuntime is the complete kernel-resource lifetime consumed by the inbound.
// Its exported method set allows the implementation to move into the reusable
// mechanism package without making the adapter depend on concrete netlink,
// TCX, qdisc, route, veth, or sysctl types.
type tcRuntime interface {
	Backend() *commonEBPF.TCBackend
	NetworkInfo() commonEBPF.TCNetworkInfo
	Reconcile(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error
	RepairInfrastructure() (bool, error)
	AttachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error)
	AttachmentDescriptions() []string
	AttachmentDiagnostics() []commonEBPF.AttachmentInfo
	UpdateHostAddresses(hostAddresses []netip.Addr) error
	Disable() error
	IsClosed() bool
	Close() error
}

type tcRuntimeConfig struct {
	LocalEnabled          bool
	IPv6Enabled           bool
	LocalInterface        string
	SharedInterfaces      []string
	HostAddresses         []netip.Addr
	SharedSourceMACPolicy bool
	Priority              uint16
}

func newTCRuntime(backend *commonEBPF.TCBackend, config tcRuntimeConfig) (tcRuntime, error) {
	return startTCDataPlane(
		backend,
		config.LocalEnabled,
		config.IPv6Enabled,
		config.LocalInterface,
		config.SharedInterfaces,
		config.HostAddresses,
		config.SharedSourceMACPolicy,
		config.Priority,
	)
}

// newUnstartedTCRuntime transfers a prepared backend into the runtime owner
// when adapter setup fails before network resources can be created. Close then
// follows the same retryable ownership path as a fully started runtime.
func newUnstartedTCRuntime(backend *commonEBPF.TCBackend) tcRuntime {
	return &tcDataPlane{backend: backend}
}

func (d *tcDataPlane) Backend() *commonEBPF.TCBackend {
	if d == nil {
		return nil
	}
	return d.backend
}

func (d *tcDataPlane) NetworkInfo() commonEBPF.TCNetworkInfo {
	if d == nil {
		return commonEBPF.TCNetworkInfo{}
	}
	d.access.Lock()
	defer d.access.Unlock()
	var info commonEBPF.TCNetworkInfo
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

func (d *tcDataPlane) AttachmentDiagnostics() []commonEBPF.AttachmentInfo {
	return d.attachmentDiagnostics()
}

func (d *tcDataPlane) UpdateHostAddresses(hostAddresses []netip.Addr) error {
	return d.updateHostAddresses(hostAddresses)
}

func (d *tcDataPlane) Disable() error {
	return d.disable()
}

var _ tcRuntime = (*tcDataPlane)(nil)
