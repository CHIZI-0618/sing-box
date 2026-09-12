//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// ResetNetworkState drops redirect state which is tied to sockets and peers
// from the previous network generation. Host policy maps are deliberately not
// touched here; they are refreshed by the interface reconciliation itself.
func (b *CgroupBackend) ResetNetworkState() error {
	if b == nil {
		return errBackendClosed
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}

	maps := []struct {
		name string
		fn   func(*CiliumEBPF.Map) error
	}{
		{"cgroup_tcp_redirect", purgeCgroupMap[listenerLookupKey, originalDestinationValue]},
		{"cgroup_udp_redirect", purgeCgroupMap[listenerLookupKey, originalDestinationValue]},
		{"cgroup_udp_recovery", purgeCgroupMap[listenerLookupKey, originalDestinationValue]},
		{"cgroup_udp_token", purgeCgroupMap[uint64, listenerLookupKey]},
		{"cgroup_udp_peer", purgeCgroupMap[udpPeerKey, udpPeerValue]},
		{"cgroup_udp_flow", purgeCgroupMap[udpFlowKey, udpFlowValue]},
	}
	for _, entry := range maps {
		if err := entry.fn(b.runtime.maps[entry.name]); err != nil {
			return E.Cause(err, "reset cgroup network state in ", entry.name)
		}
	}
	b.connectedUDPTokenKeys = b.connectedUDPTokenKeys[:0]
	b.connectedUDPTokenValues = b.connectedUDPTokenValues[:0]
	b.udpReplyTokenSequence.Store(0)
	return nil
}

func purgeCgroupMap[K any, V any](mapInstance *CiliumEBPF.Map) error {
	if mapInstance == nil {
		return nil
	}
	keys := make([]K, 0)
	iterator := mapInstance.Iterate()
	var key K
	var value V
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
		key = *new(K)
		value = *new(V)
	}
	if err := iterator.Err(); err != nil {
		return err
	}
	for index := range keys {
		if err := deleteMap(mapInstance.FD(), unsafe.Pointer(&keys[index])); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}
