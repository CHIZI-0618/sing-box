//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

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

// newRealFakeIPICMPSharedNetworkBackend prepares a real shared.data_plane:
// packet_rewrite backend (SharedNetworkBackend) with fakeip_icmp enabled --
// item 10's core deliverable: prior to this, only commonEBPF.TCBackend
// (local TC, shared socket_assign) could host the fakeip_icmp responder, so
// a packet_rewrite-only inbound had nothing to attach it to even though the
// native object itself has always answered a "shared reply" the same way.
func newRealFakeIPICMPSharedNetworkBackend(t *testing.T) *commonEBPF.SharedNetworkBackend {
	t.Helper()
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{
		EnableTCP:  true,
		FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15"),
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareSharedNetwork(nil, commonEBPF.SharedNetworkConfig{
		ListenerPort:    23458,
		EnableTCP:       true,
		RedirectIPv4:    netip.MustParsePrefix("127.128.0.0/9"),
		Policy:          policy,
		MapCapacity:     commonEBPF.DefaultSharedNetworkMapCapacities(),
		UDPTimeout:      5 * time.Minute,
		FakeIPICMPReply: true,
	})
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	return backend
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

// TestFakeIPICMPSharedRewriteAnswersARealClientPing is item 10's real-packet
// proof for shared.data_plane: packet_rewrite, structurally identical to
// TestFakeIPICMPSharedReplyAnswersARealClientPing (shared socket_assign) --
// same raw-frame technique, same helpers (buildEthernetIPv4EchoRequest,
// parseEthernetIPv4ICMP, openRawLinkLayerSocket), because the responder
// being verified is the exact same native program in both cases. What is
// new here is the attachment path: attachSharedRewriteInterface (packet
// rewrite's own attach function) rather than attachTCInterfaceWithLock.
func TestFakeIPICMPSharedRewriteAnswersARealClientPing(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackend(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbrwicmpw0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbrwicmpw1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbrwicmpw0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	peer, err := netlink.LinkByName("sbrwicmpw1")
	if err != nil {
		t.Fatalf("find veth peer: %v", err)
	}
	for _, link := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring up %s: %v", link.Attrs().Name, err)
		}
	}

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

	buffer := make([]byte, 1500)
	var reply *parsedICMPEchoReply
	var replyLength int
	for attempt := 0; attempt < 8; attempt++ {
		n, readErr := unix.Read(peerSocket, buffer)
		if readErr != nil {
			t.Fatalf("read a reply: %v (the request may have gone unanswered)", readErr)
		}
		candidate := parseEthernetIPv4ICMP(t, buffer[:n])
		if candidate.icmpType == 8 {
			// The kernel's own loopback of the frame this test just
			// transmitted on the same raw socket, not a reply; keep reading.
			continue
		}
		reply = candidate
		replyLength = n
		break
	}
	if reply == nil {
		t.Fatal("only saw the echoed request on the raw socket, never a reply")
	}

	if replyLength > len(requestFrame) {
		t.Fatalf("reply is %d bytes, longer than the %d-byte request — an amplification, not a reply",
			replyLength, len(requestFrame))
	}
	if reply.icmpType != 0 {
		t.Fatalf("reply ICMP type = %d, want 0 (Echo Reply)", reply.icmpType)
	}
	if reply.identifier != identifier || reply.sequence != sequence {
		t.Fatalf("reply identifier/sequence = %d/%d, want %d/%d", reply.identifier, reply.sequence, identifier, sequence)
	}
	if string(reply.payload) != string(payload) {
		t.Fatalf("reply payload = %q, want %q unchanged", reply.payload, payload)
	}
	if !reply.srcIP.Equal(net.ParseIP(fakeIPTarget)) {
		t.Fatalf("reply source = %v, want it to still carry the FakeIP address %s", reply.srcIP, fakeIPTarget)
	}
	if !reply.dstIP.Equal(net.ParseIP(clientIP)) {
		t.Fatalf("reply destination = %v, want the client address %s", reply.dstIP, clientIP)
	}
	if reply.dstMAC.String() != peer.Attrs().HardwareAddr.String() {
		t.Fatalf("reply Ethernet destination = %s, want the client's MAC %s", reply.dstMAC, peer.Attrs().HardwareAddr)
	}
	if !reply.ipChecksumOK {
		t.Fatal("reply IPv4 header checksum does not validate")
	}
	if !reply.icmpChecksumOK {
		t.Fatal("reply ICMP checksum does not validate")
	}
	repliesAfter, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if repliesAfter != repliesBefore+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", repliesAfter, repliesBefore+1)
	}
}

// TestFakeIPICMPSharedRewriteIgnoresNonICMPToFakeIPTarget is the coexistence
// proof item 10 asks for: a UDP packet to the exact same FakeIP target the
// previous test successfully pinged must not be answered by fakeip_icmp --
// the responder discriminates by IP protocol, not just destination address,
// so packet_rewrite's own TCP/UDP handling is never shadowed by it.
func TestFakeIPICMPSharedRewriteIgnoresNonICMPToFakeIPTarget(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbrwudpw0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbrwudpw1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbrwudpw0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	peer, err := netlink.LinkByName("sbrwudpw1")
	if err != nil {
		t.Fatalf("find veth peer: %v", err)
	}
	for _, link := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring up %s: %v", link.Attrs().Name, err)
		}
	}

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
