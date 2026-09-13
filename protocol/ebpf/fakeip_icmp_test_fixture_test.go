//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/sys/unix"
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

type fakeIPSharedDataPlane uint8

const (
	fakeIPSharedSocketAssign fakeIPSharedDataPlane = iota
	fakeIPSharedPacketRewrite
)

type fakeIPSharedReplyCase struct {
	dataPlane  fakeIPSharedDataPlane
	ipv6       bool
	priority   uint16
	selfName   string
	peerName   string
	client     string
	identifier uint16
	sequence   uint16
}

func runFakeIPSharedReplyCase(t *testing.T, testCase fakeIPSharedReplyCase) {
	t.Helper()
	enterTestNetworkNamespace(t)
	self, peer := createTestVethPair(t, testCase.selfName, testCase.peerName)

	var counter fakeIPICMPReplyCounter
	switch testCase.dataPlane {
	case fakeIPSharedSocketAssign:
		backend := newRealFakeIPICMPBackendFor(t, testCase.ipv6)
		t.Cleanup(func() { _ = backend.Close() })
		counter = backend
		attachment := attachFakeIPICMPOrSkip(
			t, backend, testCase.selfName, self.Attrs().Index, tcInterfaceRole{shared: true}, testCase.priority,
		)
		t.Cleanup(func() { _ = attachment.Close() })
		if testCase.priority == defaultTCPriority && attachment.sharedICMPLink == nil {
			t.Fatal("the FakeIP ICMP TCX link was not attached")
		}
		if testCase.priority != defaultTCPriority && attachment.sharedICMPFilter == nil {
			t.Fatal("the FakeIP ICMP clsact filter was not attached")
		}
	case fakeIPSharedPacketRewrite:
		backend := newRealFakeIPICMPSharedNetworkBackendFor(t, testCase.ipv6)
		t.Cleanup(func() { _ = backend.Close() })
		counter = backend
		attachment := attachSharedRewriteOrSkip(t, self, backend, testCase.priority)
		t.Cleanup(func() { _ = attachment.Close() })
		if testCase.priority == defaultTCPriority && attachment.icmpLink == nil {
			t.Fatal("the FakeIP ICMP TCX link was not attached")
		}
		if testCase.priority != defaultTCPriority && attachment.icmpFilter == nil {
			t.Fatal("the FakeIP ICMP clsact filter was not attached")
		}
	default:
		t.Fatalf("unknown shared data plane %d", testCase.dataPlane)
	}

	before := fakeIPICMPReplyCount(t, counter)
	fakeIPTarget := "198.18.0.1"
	etherType := uint16(unix.ETH_P_IP)
	requestType, replyType := uint8(8), uint8(0)
	parse := parseEthernetIPv4ICMP
	build := buildEthernetIPv4EchoRequest
	checkIPChecksum := true
	if testCase.ipv6 {
		fakeIPTarget = "fc00::1"
		etherType = unix.ETH_P_IPV6
		requestType, replyType = 128, 129
		parse = parseEthernetIPv6ICMP
		build = buildEthernetIPv6EchoRequest
		checkIPChecksum = false
	}
	payload := []byte(t.Name())
	request := build(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(testCase.client), net.ParseIP(fakeIPTarget),
		testCase.identifier, testCase.sequence, payload,
	)
	socket := openRawLinkLayerSocket(t, peer.Attrs().Index, etherType, 5*time.Second)
	if _, err := unix.Write(socket, request); err != nil {
		t.Fatalf("transmit the echo request: %v", err)
	}
	reply, replyLength := readFakeIPICMPReplyFrame(t, socket, requestType, parse)
	assertFakeIPICMPReply(
		t, reply, replyLength, len(request), replyType,
		testCase.identifier, testCase.sequence, payload, fakeIPTarget, testCase.client,
		peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr, checkIPChecksum,
	)
	requireOneFakeIPICMPReply(t, counter, before)
}

func runFakeIPLocalTCXReplyCase(t *testing.T, ipv6 bool, selfName, peerName string) {
	t.Helper()
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackendFor(t, ipv6)
	t.Cleanup(func() { _ = backend.Close() })
	var self netlink.Link
	var ping func(*testing.T, string, time.Duration) error
	fakeIPTarget := "198.18.0.1"
	if ipv6 {
		fakeIPTarget = "fc00::1"
		self = setupFakeIPICMPPingVethIPv6(t, selfName, peerName, fakeIPTarget)
		ping = pingFakeIPICMPTargetV6
	} else {
		self = setupFakeIPICMPPingVeth(t, selfName, peerName, fakeIPTarget)
		ping = pingFakeIPICMPTarget
	}
	attachment := attachFakeIPICMPOrSkip(
		t, backend, selfName, self.Attrs().Index, tcInterfaceRole{local: true}, defaultTCPriority,
	)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.localICMPLink == nil {
		t.Fatal("the FakeIP ICMP TCX link was not attached")
	}
	if err := ping(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("read a reply: %v", err)
	}
}
