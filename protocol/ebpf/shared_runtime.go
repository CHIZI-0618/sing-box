//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

// sharedKernelRuntime is the kernel attachment lifetime consumed by the
// shared packet-rewrite adapter. Its exported method set allows the concrete
// implementation to move into the reusable mechanism package without exposing
// netlink filters, TCX links, qdiscs, sysctls, or BPF object details.
//
// Retry classification deliberately stays outside this contract. Closed and
// RequiresRebuild are mechanism state; the adapter decides whether and how to
// retry them.
type sharedKernelRuntime interface {
	Reconcile(interfaceNames []string, hostAddresses []netip.Addr) error
	IsEnabled() bool
	AttachmentDescriptions() []string
	AttachmentDiagnostics() []commonEBPF.AttachmentInfo
	IsClosed() bool
	RequiresRebuild() bool
	Close() error
}

// sharedKernelRuntimeHooks are the only application actions the kernel
// runtime may request. Keeping these callbacks explicit prevents attachment
// code from retaining the protocol adapter and reaching into its listener,
// UDP-session, logger, or routing state.
type sharedKernelRuntimeHooks struct {
	PrepareBackend     func() (*commonEBPF.SharedNetworkBackend, error)
	DiscardBackend     func(*commonEBPF.SharedNetworkBackend) error
	PurgeUserspaceFlow func()
	Ready              func([]string)
	WarnFlowPurge      func(interfaceName string, err error)
}

func (s *sharedRewrite) kernelRuntimeHooks() sharedKernelRuntimeHooks {
	return sharedKernelRuntimeHooks{
		PrepareBackend: s.prepareBackend,
		DiscardBackend: func(backend *commonEBPF.SharedNetworkBackend) error {
			if s.sharedBackendInstance() == backend {
				s.takeSharedBackend()
			}
			return backend.Close()
		},
		PurgeUserspaceFlow: s.udpNat.Purge,
		Ready:              s.sharedRewriteReadyLocked,
		WarnFlowPurge: func(interfaceName string, err error) {
			s.janitorWarnings.warn(s.inbound.logger, "purge shared packet-rewrite state for ", interfaceName, ": ", err)
		},
	}
}

func (d *sharedRewriteDataPlane) Reconcile(interfaceNames []string, hostAddresses []netip.Addr) error {
	return d.reconcile(interfaceNames, hostAddresses)
}

func (d *sharedRewriteDataPlane) IsEnabled() bool {
	return d.isEnabled()
}

func (d *sharedRewriteDataPlane) AttachmentDescriptions() []string {
	return d.attachmentDescriptions()
}

func (d *sharedRewriteDataPlane) AttachmentDiagnostics() []commonEBPF.AttachmentInfo {
	return d.attachmentDiagnostics()
}

func (d *sharedRewriteDataPlane) IsClosed() bool {
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

var _ sharedKernelRuntime = (*sharedRewriteDataPlane)(nil)
