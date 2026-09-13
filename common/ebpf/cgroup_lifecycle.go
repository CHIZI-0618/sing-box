//go:build with_ebpf && (linux || android)

package ebpf

import E "github.com/sagernet/sing/common/exceptions"

func (b *CgroupBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	if err := b.detachProgramsLocked(); err != nil {
		return E.Cause(err, "detach eBPF inbound")
	}
	closeErr := closeObjectResources(b.runtime.programs, b.runtime.maps)
	if b.runtime.cgroupFile != nil {
		closeErr = E.Errors(closeErr, b.runtime.cgroupFile.Close())
	}
	b.runtime = nil
	b.tcpRedirectMapFD = -1
	b.udpRedirectMapFD = -1
	b.udpRecoveryMapFD = -1
	b.udpFlowMapFD = -1
	b.socketBypassMapFD = -1
	b.bypassIPv4CIDRMapFD = -1
	b.bypassIPv6CIDRMapFD = -1
	b.hostIPv4MapFD = -1
	b.hostIPv6MapFD = -1
	b.bypassIPv4CIDR = nil
	b.bypassIPv6CIDR = nil
	b.hostIPv4 = nil
	b.hostIPv6 = nil
	b.listenerPort = 0
	return closeErr
}

func (b *CgroupBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}

// RequiresRebuild reports whether a previous operation's internal rollback
// itself failed, leaving this backend's maps and control flags no longer
// agreeing with each other and with no known-good state left to compute the
// next incremental update from -- the health.invalidate call at that
// operation's own site already disabled the data path when this happened.
// Every operation on it fails from then on, so a caller retrying one can
// stop instead of repeating work that cannot succeed. Mirrors
// SharedNetworkBackend.RequiresRebuild / TCBackend.RequiresRebuild.
func (b *CgroupBackend) RequiresRebuild() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.health.rebuildRequired != nil
}
