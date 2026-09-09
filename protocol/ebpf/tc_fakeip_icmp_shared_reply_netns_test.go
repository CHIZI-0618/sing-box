//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/sys/unix"
)

// htons16 converts a 16-bit value from host to network byte order — the
// classic C socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)) idiom, needed here
// because unix.SockaddrLinklayer.Protocol and the Ethernet frame's own
// EtherType field are both defined in network byte order.
func htons16(v uint16) uint16 {
	return v<<8 | v>>8
}

// internetChecksum computes the standard Internet checksum (RFC 1071) over
// b, treating the two bytes at checksumOffset as 0 while summing — the same
// convention used to both compute a checksum before it exists and verify one
// that does (in which case the residual, not this call, would be 0).
func internetChecksum(b []byte, checksumOffset int) uint16 {
	var sum uint32
	for index := 0; index+1 < len(b); index += 2 {
		if index == checksumOffset {
			continue
		}
		sum += uint32(b[index])<<8 | uint32(b[index+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// buildEthernetIPv4EchoRequest hand-builds a complete, correctly-checksummed
// Ethernet+IPv4+ICMP Echo Request frame — the shared path is verified by
// transmitting this directly onto a raw link-layer socket bound to the
// veth's peer, arriving at the attachment's ingress side exactly as a real
// LAN client's frame would, which is not something a regular UDP/ICMP socket
// API can produce (there is no routing table entry making a client address
// this host does not own reachable through this interface).
func buildEthernetIPv4EchoRequest(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, identifier, sequence uint16, payload []byte) []byte {
	const ethernetLength = 14
	const ipv4Length = 20
	const icmpLength = 8
	frame := make([]byte, ethernetLength+ipv4Length+icmpLength+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IP)

	ip := frame[ethernetLength:]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipv4Length+icmpLength+len(payload)))
	ip[8] = 64 // TTL
	ip[9] = unix.IPPROTO_ICMP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:ipv4Length], 10))

	icmp := ip[ipv4Length:]
	icmp[0] = 8 // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp, 2))

	return frame
}

// parsedICMPEchoReply is what this test needs out of a reflected reply
// frame: enough to check every property fakeip_icmp promises (address,
// type, identifier, sequence, payload, checksum, non-amplification) without
// depending on any higher-level ICMP library, since a raw link-layer socket
// hands back full Ethernet frames, not parsed ICMP messages.
type parsedICMPEchoReply struct {
	dstMAC, srcMAC net.HardwareAddr
	srcIP, dstIP   net.IP
	icmpType       uint8
	icmpCode       uint8
	identifier     uint16
	sequence       uint16
	payload        []byte
	ipChecksumOK   bool
	icmpChecksumOK bool
}

func parseEthernetIPv4ICMP(t *testing.T, frame []byte) *parsedICMPEchoReply {
	t.Helper()
	const ethernetLength = 14
	const ipv4Length = 20
	if len(frame) < ethernetLength+ipv4Length {
		t.Fatalf("frame too short to be Ethernet+IPv4: %d bytes", len(frame))
	}
	if binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP {
		t.Fatalf("EtherType = %#04x, want IPv4", binary.BigEndian.Uint16(frame[12:14]))
	}
	ip := frame[ethernetLength:]
	if ip[0]>>4 != 4 || ip[0]&0xf != 5 {
		t.Fatalf("IP version/IHL byte = %#02x, want IPv4 with no options", ip[0])
	}
	if ip[9] != unix.IPPROTO_ICMP {
		t.Fatalf("IP protocol = %d, want ICMP", ip[9])
	}
	totalLength := int(binary.BigEndian.Uint16(ip[2:4]))
	if ethernetLength+totalLength > len(frame) {
		t.Fatalf("declared IPv4 total_length %d exceeds the %d-byte frame", totalLength, len(frame)-ethernetLength)
	}
	icmp := ip[ipv4Length:totalLength]
	if len(icmp) < 8 {
		t.Fatalf("ICMP portion is %d bytes, want at least 8", len(icmp))
	}
	return &parsedICMPEchoReply{
		dstMAC:         net.HardwareAddr(frame[0:6]),
		srcMAC:         net.HardwareAddr(frame[6:12]),
		srcIP:          net.IP(append([]byte(nil), ip[12:16]...)),
		dstIP:          net.IP(append([]byte(nil), ip[16:20]...)),
		icmpType:       icmp[0],
		icmpCode:       icmp[1],
		identifier:     binary.BigEndian.Uint16(icmp[4:6]),
		sequence:       binary.BigEndian.Uint16(icmp[6:8]),
		payload:        append([]byte(nil), icmp[8:]...),
		ipChecksumOK:   internetChecksum(ip[:ipv4Length], -1) == 0,
		icmpChecksumOK: internetChecksum(icmp, -1) == 0,
	}
}

// openRawLinkLayerSocket opens an AF_PACKET/SOCK_RAW socket bound to
// interfaceIndex, restricted to etherType frames (unix.ETH_P_IP or
// unix.ETH_P_IPV6), with a receive timeout so a missing reply fails the
// test instead of hanging it.
func openRawLinkLayerSocket(t *testing.T, interfaceIndex int, etherType uint16, timeout time.Duration) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons16(etherType)))
	if err != nil {
		t.Fatalf("open a raw link-layer socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons16(etherType),
		Ifindex:  interfaceIndex,
	}); err != nil {
		t.Fatalf("bind the raw link-layer socket to interface index %d: %v", interfaceIndex, err)
	}
	deadline := unix.NsecToTimeval(timeout.Nanoseconds())
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &deadline); err != nil {
		t.Fatalf("set a receive timeout on the raw link-layer socket: %v", err)
	}
	return fd
}

// TestFakeIPICMPSharedReplyAnswersARealClientPing is shared_reply's first
// real end-to-end proof: every other fakeip_icmp test to date only checks
// that the shared reply filter/link attaches (TestAttachTCInterfaceAddsTheFakeIPICMPFilterWhenEnabled),
// never that a genuine LAN client's Echo Request crossing it actually comes
// back reflected, correctly addressed and checksummed, with its Ethernet
// addresses swapped so the frame actually reaches the client that sent it.
//
// The request is transmitted directly onto a raw link-layer socket bound to
// the veth's peer rather than sent through any routing-aware socket API,
// because the whole point is a source address (a "LAN client") this host
// does not itself own and has no route to — sending it any other way would
// either fail outright or never reach the ingress side this test attaches
// shared_reply to.
func TestFakeIPICMPSharedReplyAnswersARealClientPing(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbicmpw0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbicmpw1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbicmpw0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	peer, err := netlink.LinkByName("sbicmpw1")
	if err != nil {
		t.Fatalf("find veth peer: %v", err)
	}
	for _, link := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring up %s: %v", link.Attrs().Name, err)
		}
	}

	const priority = 2 // force clsact; see TestFakeIPICMPLocalReplyAnswersARealPingViaTCX for the TCX case.
	lock, err := acquireTCInterfaceLock("sbicmpw0", self.Attrs().Index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		"sbicmpw0",
		tcAttachmentState{
			index:   self.Attrs().Index,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{shared: true},
		},
		false,
		priority,
		lock,
		true,
	)
	if err != nil {
		t.Fatalf("attach the interface: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.sharedICMPFilter == nil {
		t.Fatal("the fakeip_icmp shared filter was not attached alongside the ordinary one")
	}

	const fakeIPTarget = "198.18.0.1"
	const clientIP = "10.250.0.5"
	const identifier = 0x4321
	const sequence = 3
	payload := []byte("fakeip-icmp-shared-reply-test-payload")

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
	if reply.icmpCode != 0 {
		t.Fatalf("reply ICMP code = %d, want 0", reply.icmpCode)
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
		t.Fatalf("reply Ethernet destination = %s, want the client's MAC %s (the reflected frame must actually reach the client)",
			reply.dstMAC, peer.Attrs().HardwareAddr)
	}
	if reply.srcMAC.String() != self.Attrs().HardwareAddr.String() {
		t.Fatalf("reply Ethernet source = %s, want this interface's own MAC %s", reply.srcMAC, self.Attrs().HardwareAddr)
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
