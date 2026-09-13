//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// buildEthernetIPv4UDPPacket hand-builds a complete, correctly-checksummed
// Ethernet+IPv4+UDP frame, for the coexistence proof: fakeip_icmp must leave
// non-ICMP traffic to the same destination alone.
func buildEthernetIPv4UDPPacket(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	const ethernetLength = 14
	const ipv4Length = 20
	const udpLength = 8
	frame := make([]byte, ethernetLength+ipv4Length+udpLength+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IP)

	ip := frame[ethernetLength:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipv4Length+udpLength+len(payload)))
	ip[8] = 64
	ip[9] = unix.IPPROTO_UDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:ipv4Length], 10))

	udp := ip[ipv4Length:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLength+len(payload)))
	copy(udp[8:], payload)
	// UDP checksum is optional over IPv4; left zero (disabled) rather than
	// computing the pseudo-header sum, since this frame is only inspected
	// for whether fakeip_icmp mistakenly answers it, not consumed by any
	// real UDP stack.

	return frame
}

func TestSharedRewriteClsactReplacementPreservesFakeIPICMPFilter(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbrwreplace0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbrwreplace1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	device, err := netlink.LinkByName(attributes.Name)
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(device); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}

	const priority = 2 // force clsact so filter identity, rather than TCX link identity, is exercised.
	current, err := attachSharedRewriteInterface(device, backend, priority)
	if err != nil {
		t.Fatalf("attach current shared rewrite programs: %v", err)
	}
	t.Cleanup(func() { _ = current.Close() })

	candidate, err := attachSharedRewriteInterfaceWithOptions(
		device,
		backend,
		priority,
		sharedRewriteAttachmentOptions{skipLock: true, temporary: true},
	)
	if err != nil {
		t.Fatalf("stage replacement shared rewrite programs: %v", err)
	}
	t.Cleanup(func() { _ = candidate.Close() })

	if err = current.Close(); err != nil {
		t.Fatalf("retire current shared rewrite programs: %v", err)
	}
	healthy, err := candidate.healthy(device, priority, true)
	if err != nil {
		t.Fatalf("inspect replacement shared rewrite programs: %v", err)
	}
	if !healthy {
		t.Fatal("retiring the old clsact attachment removed a staged FakeIP ICMP filter")
	}
}

// TestFakeIPICMPSharedRewriteAnswersARealClientPing verifies the
// packet-rewrite attachment with a real link-layer request and reply.
func TestFakeIPICMPSharedRewriteAnswersARealClientPing(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackend(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore := fakeIPICMPReplyCount(t, backend)

	self, peer := createTestVethPair(t, "sbrwicmpw0", "sbrwicmpw1")

	const priority = 2 // force clsact; TCX is covered by attachSharedRewriteInterface's own existing coverage.
	attachment, err := attachSharedRewriteInterface(self, backend, priority)
	if err != nil {
		t.Fatalf("attach the shared packet-rewrite interface: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.icmpFilter == nil {
		t.Fatal("the fakeip_icmp shared filter was not attached alongside packet_rewrite's own ingress/egress filters")
	}
	if attachment.ingressFilter == nil || attachment.egressFilter == nil {
		t.Fatal("packet_rewrite's own ingress/egress filters are missing -- fakeip_icmp must not replace them")
	}

	const fakeIPTarget = "198.18.0.1"
	const clientIP = "10.250.0.6"
	const identifier = 0x5678
	const sequence = 7
	payload := []byte("fakeip-icmp-shared-rewrite-test-payload")

	requestFrame := buildEthernetIPv4EchoRequest(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(clientIP), net.ParseIP(fakeIPTarget),
		identifier, sequence, payload,
	)

	peerSocket := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IP, 5*time.Second)
	if _, err = unix.Write(peerSocket, requestFrame); err != nil {
		t.Fatalf("transmit the echo request onto the peer interface: %v", err)
	}

	reply, replyLength := readFakeIPICMPReplyFrame(t, peerSocket, 8, parseEthernetIPv4ICMP)
	assertFakeIPICMPReply(
		t, reply, replyLength, len(requestFrame), 0,
		identifier, sequence, payload, fakeIPTarget, clientIP,
		peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr, true,
	)
	requireOneFakeIPICMPReply(t, backend, repliesBefore)
}

// TestFakeIPICMPSharedRewriteIgnoresNonICMPToFakeIPTarget verifies that the
// responder does not shadow packet-rewrite TCP/UDP handling.
func TestFakeIPICMPSharedRewriteIgnoresNonICMPToFakeIPTarget(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	self, peer := createTestVethPair(t, "sbrwudpw0", "sbrwudpw1")

	const priority = 2
	attachment, err := attachSharedRewriteInterface(self, backend, priority)
	if err != nil {
		t.Fatalf("attach the shared packet-rewrite interface: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })

	const fakeIPTarget = "198.18.0.1"
	const clientIP = "10.250.0.7"
	udpFrame := buildEthernetIPv4UDPPacket(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(clientIP), net.ParseIP(fakeIPTarget),
		40000, 53, []byte("not-icmp"),
	)

	peerSocket := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IP, 500*time.Millisecond)
	if _, err = unix.Write(peerSocket, udpFrame); err != nil {
		t.Fatalf("transmit the UDP packet onto the peer interface: %v", err)
	}

	buffer := make([]byte, 1500)
	for {
		n, readErr := unix.Read(peerSocket, buffer)
		if readErr != nil {
			// Timeout with nothing but the kernel's own loopback seen (or
			// nothing at all): fakeip_icmp correctly left this alone.
			return
		}
		frame := buffer[:n]
		const ethernetLength = 14
		if len(frame) < ethernetLength+20 || frame[ethernetLength+9] != unix.IPPROTO_ICMP {
			// Not even an ICMP frame -- almost certainly this test's own
			// UDP packet being echoed back by the kernel on the same raw
			// socket, not a reply; keep reading until the timeout.
			continue
		}
		reply := parseEthernetIPv4ICMP(t, frame)
		if reply.icmpType == 0 {
			t.Fatal("fakeip_icmp answered a UDP packet with an ICMP Echo Reply -- protocol discrimination failed")
		}
	}
}
