//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

type CgroupBackend struct{}

func PrepareCgroup(CgroupConfig) (*CgroupBackend, error) {
	return nil, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) LoadPrograms(uint16) error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) Attach() error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) Close() error {
	return nil
}

func (b *CgroupBackend) IsClosed() bool {
	return true
}

func (b *CgroupBackend) UpdateBypassCIDR([]netip.Prefix) (bool, error) {
	return false, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) BypassCIDRCount() (int, int) {
	return 0, 0
}

func (b *CgroupBackend) CgroupPath() string {
	return ""
}

func (b *CgroupBackend) AttachedPrograms() []string {
	return nil
}

func (b *CgroupBackend) UsesSocketRelease() bool {
	return false
}

func (b *CgroupBackend) UpdateIPv6Available(bool) (bool, error) {
	return false, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) SelfBypassMode() string {
	return ""
}

func (b *CgroupBackend) SocketProtectFunc() control.Func {
	return nil
}

func (b *CgroupBackend) LookupOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) TakeOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) RedirectMapUsage(uint8) (MapUsage, error) {
	return MapUsage{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) LookupAndDeleteMode() string {
	return "unavailable"
}

func (b *CgroupBackend) SweepStaleTCPRedirects(time.Duration) (CgroupTCPRedirectSweepResult, error) {
	return CgroupTCPRedirectSweepResult{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) DeleteRedirect(uint8, netip.AddrPort) error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) RedirectReservationFailures(uint8) (uint64, error) {
	return 0, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}
