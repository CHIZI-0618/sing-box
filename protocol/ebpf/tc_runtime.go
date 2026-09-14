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

func (d *tcDataPlane) Backend() *commonEBPF.TCBackend {
	if d == nil {
		return nil
	}
	return d.backend
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
