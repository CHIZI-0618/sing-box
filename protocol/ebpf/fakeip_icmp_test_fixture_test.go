//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func newRealFakeIPICMPBackend(t *testing.T) *commonEBPF.TCBackend {
	return newRealFakeIPICMPBackendFor(t, false)
}

func newRealFakeIPICMPBackendWithIPv6(t *testing.T) *commonEBPF.TCBackend {
	return newRealFakeIPICMPBackendFor(t, true)
}

func newRealFakeIPICMPBackendFor(t *testing.T, enableIPv6 bool) *commonEBPF.TCBackend {
	t.Helper()
	policyConfig := commonEBPF.PolicyConfig{
		EnableTCP:  true,
		FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15"),
	}
	if enableIPv6 {
		policyConfig.FakeIPIPv6 = netip.MustParsePrefix("fc00::/18")
	}
	policy, err := commonEBPF.CompilePolicy(policyConfig)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort:     23456,
		EnableLocal:      true,
		EnableShared:     true,
		EnableIPv4:       true,
		EnableLocalIPv6:  enableIPv6,
		EnableSharedIPv6: enableIPv6,
		EnableTCP:        true,
		Policy:           policy,
		FakeIPICMPReply:  true,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	return backend
}

func newRealFakeIPICMPSharedNetworkBackend(t *testing.T) *commonEBPF.SharedNetworkBackend {
	return newRealFakeIPICMPSharedNetworkBackendFor(t, false)
}

func newRealFakeIPICMPSharedNetworkBackendWithIPv6(t *testing.T) *commonEBPF.SharedNetworkBackend {
	return newRealFakeIPICMPSharedNetworkBackendFor(t, true)
}

func newRealFakeIPICMPSharedNetworkBackendFor(t *testing.T, enableIPv6 bool) *commonEBPF.SharedNetworkBackend {
	t.Helper()
	policyConfig := commonEBPF.PolicyConfig{
		EnableTCP:  true,
		FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15"),
	}
	config := commonEBPF.SharedNetworkConfig{
		ListenerPort:    23458,
		EnableTCP:       true,
		RedirectIPv4:    netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:     commonEBPF.DefaultSharedNetworkMapCapacities(),
		UDPTimeout:      5 * time.Minute,
		FakeIPICMPReply: true,
	}
	if enableIPv6 {
		policyConfig.FakeIPIPv6 = netip.MustParsePrefix("fc00::/18")
		config.RedirectIPv6 = netip.MustParsePrefix("fd53:696e:672d:626f::/64")
	}
	policy, err := commonEBPF.CompilePolicy(policyConfig)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	config.Policy = policy
	backend, err := commonEBPF.PrepareSharedNetwork(nil, config)
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	return backend
}

func attachFakeIPICMPOrSkip(
	t *testing.T,
	backend *commonEBPF.TCBackend,
	interfaceName string,
	index int,
	role tcInterfaceRole,
	priority uint16,
) *tcInterfaceAttachment {
	t.Helper()
	lock, err := acquireTCInterfaceLock(interfaceName, index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		interfaceName,
		tcAttachmentState{index: index, framing: commonEBPF.TCLinkFramingEthernet, role: role},
		false,
		priority,
		lock,
		true,
	)
	if err != nil {
		t.Fatalf("attach the interface: %v", err)
	}
	if priority == defaultTCPriority && attachment.attachmentType != "tcx" {
		_ = attachment.Close()
		requireOrSkipTCX(t, attachment.attachmentType)
	}
	return attachment
}

func attachSharedRewriteOrSkip(
	t *testing.T,
	device netlink.Link,
	backend *commonEBPF.SharedNetworkBackend,
	priority uint16,
) *sharedRewriteAttachment {
	t.Helper()
	attachment, err := attachSharedRewriteInterface(device, backend, priority)
	if err != nil {
		t.Fatalf("attach the shared packet-rewrite interface: %v", err)
	}
	if priority == defaultTCPriority && attachment.attachmentType != "tcx" {
		_ = attachment.Close()
		requireOrSkipTCX(t, attachment.attachmentType)
	}
	return attachment
}

type fakeIPICMPReplyCounter interface {
	FakeIPICMPReplyCount() (uint64, error)
}

func fakeIPICMPReplyCount(t *testing.T, counter fakeIPICMPReplyCounter) uint64 {
	t.Helper()
	count, err := counter.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount: %v", err)
	}
	return count
}

func requireOneFakeIPICMPReply(t *testing.T, counter fakeIPICMPReplyCounter, before uint64) {
	t.Helper()
	after := fakeIPICMPReplyCount(t, counter)
	if after != before+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", after, before+1)
	}
}
