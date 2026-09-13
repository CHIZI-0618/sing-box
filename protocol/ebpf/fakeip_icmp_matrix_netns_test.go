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

// This file closes the real-packet ICMP test coverage matrix (IPv4/IPv6 x
// TCX/clsact x local/shared-socket_assign/shared-packet_rewrite) the
// acceptance report for this round of work found incomplete: seven of the
// combinations the existing tests already established a pattern for had no
// dedicated real-send/real-receive proof yet. Every helper here is either
// reused directly from the existing fakeip_icmp test files (backend prep,
// IPv4 frame building/parsing, the local-role IPv6 veth/ping helpers) or is
// this file's IPv6 counterpart of one of them, so each new test below is
// just the combination-specific wiring, not a fresh setup.

// createTestVethPair is the shared-role tests' veth setup: unlike
// setupFakeIPICMPPingVeth/V6 (local role), no address/route/neighbor is
// configured on either side, since the shared-role tests inject raw,
// pre-built frames directly onto the peer's link-layer socket rather than
// relying on ordinary IP-layer routing to reach the attachment.
func createTestVethPair(t *testing.T, selfName, peerName string) (self, peer netlink.Link) {
	t.Helper()
	attributes := netlink.NewLinkAttrs()
	attributes.Name = selfName
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	var err error
	self, err = netlink.LinkByName(selfName)
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	peer, err = netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("find veth peer: %v", err)
	}
	for _, link := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring up %s: %v", link.Attrs().Name, err)
		}
	}
	return self, peer
}

// icmpv6PseudoHeaderSum returns the running (unfolded) sum over the ICMPv6
// pseudo-header -- source address, destination address, upper-layer packet
// length, and next header (RFC 8200 §8.1) -- which ICMPv6's checksum, unlike
// ICMPv4's, covers in addition to the message itself. The 32-bit length and
// next-header fields are folded in as their big-endian 16-bit-word
// contributions would be; since ones-complement addition is commutative,
// adding each as a plain integer here is numerically identical to summing
// the actual wire bytes as 16-bit words would be.
func icmpv6PseudoHeaderSum(srcIP, dstIP net.IP, upperLayerLength int) uint32 {
	var sum uint32
	src16 := srcIP.To16()
	dst16 := dstIP.To16()
	for index := 0; index+1 < len(src16); index += 2 {
		sum += uint32(src16[index])<<8 | uint32(src16[index+1])
	}
	for index := 0; index+1 < len(dst16); index += 2 {
		sum += uint32(dst16[index])<<8 | uint32(dst16[index+1])
	}
	sum += uint32(upperLayerLength >> 16)
	sum += uint32(upperLayerLength & 0xffff)
	sum += unix.IPPROTO_ICMPV6
	return sum
}

// icmpv6Checksum computes (checksumOffset naming the two bytes to treat as
// zero while summing) or verifies (checksumOffset == -1, expecting a 0
// residual) the ICMPv6 checksum of message against the pseudo-header formed
// from srcIP/dstIP -- the IPv6 counterpart of internetChecksum, which
// cannot be reused directly here because ICMPv6 (unlike ICMPv4) checksums a
// pseudo-header the plain message bytes alone do not carry.
func icmpv6Checksum(srcIP, dstIP net.IP, message []byte, checksumOffset int) uint16 {
	sum := icmpv6PseudoHeaderSum(srcIP, dstIP, len(message))
	for index := 0; index+1 < len(message); index += 2 {
		if index == checksumOffset {
			continue
		}
		sum += uint32(message[index])<<8 | uint32(message[index+1])
	}
	if len(message)%2 == 1 {
		sum += uint32(message[len(message)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// buildEthernetIPv6EchoRequest is buildEthernetIPv4EchoRequest's IPv6
// counterpart: a complete, correctly-checksummed Ethernet+IPv6+ICMPv6 Echo
// Request frame, for the same reason -- a raw link-layer socket is the only
// way to originate a frame carrying a source address this host does not
// itself own.
func buildEthernetIPv6EchoRequest(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, identifier, sequence uint16, payload []byte) []byte {
	const ethernetLength = 14
	const ipv6Length = 40
	const icmpLength = 8
	frame := make([]byte, ethernetLength+ipv6Length+icmpLength+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IPV6)

	ip := frame[ethernetLength:]
	ip[0] = 0x60 // version 6
	payloadLength := icmpLength + len(payload)
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLength))
	ip[6] = unix.IPPROTO_ICMPV6 // next header
	ip[7] = 255                 // hop limit
	copy(ip[8:24], srcIP.To16())
	copy(ip[24:40], dstIP.To16())

	icmp := ip[ipv6Length:]
	icmp[0] = 128 // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(srcIP, dstIP, icmp, 2))

	return frame
}

// parseEthernetIPv6ICMP is parseEthernetIPv4ICMP's IPv6 counterpart.
// ipChecksumOK is deliberately left at its zero value (false): IPv6 has no
// header checksum at all, so callers must not assert it for an IPv6 reply
// (see assertFakeIPICMPReply's checkIPChecksum parameter).
func parseEthernetIPv6ICMP(t *testing.T, frame []byte) *parsedICMPEchoReply {
	t.Helper()
	const ethernetLength = 14
	const ipv6Length = 40
	if len(frame) < ethernetLength+ipv6Length {
		t.Fatalf("frame too short to be Ethernet+IPv6: %d bytes", len(frame))
	}
	if binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IPV6 {
		t.Fatalf("EtherType = %#04x, want IPv6", binary.BigEndian.Uint16(frame[12:14]))
	}
	ip := frame[ethernetLength:]
	if ip[0]>>4 != 6 {
		t.Fatalf("IP version nibble = %d, want 6", ip[0]>>4)
	}
	if ip[6] != unix.IPPROTO_ICMPV6 {
		t.Fatalf("IPv6 next header = %d, want ICMPv6", ip[6])
	}
	payloadLength := int(binary.BigEndian.Uint16(ip[4:6]))
	if ethernetLength+ipv6Length+payloadLength > len(frame) {
		t.Fatalf("declared IPv6 payload_length %d exceeds the %d-byte frame", payloadLength, len(frame)-ethernetLength-ipv6Length)
	}
	icmp := ip[ipv6Length : ipv6Length+payloadLength]
	if len(icmp) < 8 {
		t.Fatalf("ICMPv6 portion is %d bytes, want at least 8", len(icmp))
	}
	srcIP := net.IP(append([]byte(nil), ip[8:24]...))
	dstIP := net.IP(append([]byte(nil), ip[24:40]...))
	return &parsedICMPEchoReply{
		dstMAC:         net.HardwareAddr(frame[0:6]),
		srcMAC:         net.HardwareAddr(frame[6:12]),
		srcIP:          srcIP,
		dstIP:          dstIP,
		icmpType:       icmp[0],
		icmpCode:       icmp[1],
		identifier:     binary.BigEndian.Uint16(icmp[4:6]),
		sequence:       binary.BigEndian.Uint16(icmp[6:8]),
		payload:        append([]byte(nil), icmp[8:]...),
		icmpChecksumOK: icmpv6Checksum(srcIP, dstIP, icmp, -1) == 0,
	}
}

// TestICMPv6ChecksumDetectsCorruption is a plain, no-root unit test of
// buildEthernetIPv6EchoRequest/parseEthernetIPv6ICMP's checksum logic in
// isolation. It exists because the netns tests in this file that rely on
// icmpChecksumOK cannot, on their own, prove the check is discriminating:
// swapping icmpv6PseudoHeaderSum's srcIP/dstIP arguments, tried first as a
// reverse-verification step for this file, left every checksum residual
// unchanged, because that sum adds every address word from both parameters
// into one accumulator, symmetric in a way that makes source and
// destination interchangeable to it -- a real corruption there would not
// have been caught by any netns test relying only on a real kernel reply.
// This test instead corrupts a built frame directly and confirms the
// parser's checksum flag actually reacts.
func TestICMPv6ChecksumDetectsCorruption(t *testing.T) {
	srcMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	dstMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	srcIP := net.ParseIP("fc00::1")
	dstIP := net.ParseIP("fd00:250::5")
	payload := []byte("checksum-corruption-probe-payload")

	frame := buildEthernetIPv6EchoRequest(dstMAC, srcMAC, srcIP, dstIP, 0x1111, 22, payload)
	if reply := parseEthernetIPv6ICMP(t, frame); !reply.icmpChecksumOK {
		t.Fatal("icmpChecksumOK = false on an untouched, freshly-built frame")
	}

	corrupted := append([]byte(nil), frame...)
	const ethernetLength, ipv6Length = 14, 40
	payloadByteOffset := ethernetLength + ipv6Length + 8 // first payload byte, past the 8-byte ICMPv6 header
	corrupted[payloadByteOffset] ^= 0xff
	if reply := parseEthernetIPv6ICMP(t, corrupted); reply.icmpChecksumOK {
		t.Fatal("icmpChecksumOK = true after flipping a payload bit -- the checksum check is not actually verifying anything")
	}

	corruptedChecksum := append([]byte(nil), frame...)
	checksumByteOffset := ethernetLength + ipv6Length + 2
	corruptedChecksum[checksumByteOffset] ^= 0xff
	if reply := parseEthernetIPv6ICMP(t, corruptedChecksum); reply.icmpChecksumOK {
		t.Fatal("icmpChecksumOK = true after flipping a checksum-field bit")
	}
}

// readFakeIPICMPReplyFrame reads frames off peerSocket, using parse to
// decode each one, until it sees one that is not simply the kernel's own
// loopback of the request this test just transmitted on the same raw
// socket (identified by requestICMPType: 8 for an IPv4 Echo Request, 128
// for an IPv6 one) -- a raw AF_PACKET socket bound to the interface it just
// wrote to always sees its own outgoing frame looped back first. Shared by
// every shared-role real-client-ping test in this file, factored out of
// the identical loop TestFakeIPICMPSharedReplyAnswersARealClientPing and
// TestFakeIPICMPSharedRewriteAnswersARealClientPing already used.
func readFakeIPICMPReplyFrame(
	t *testing.T,
	peerSocket int,
	requestICMPType uint8,
	parse func(*testing.T, []byte) *parsedICMPEchoReply,
) (*parsedICMPEchoReply, int) {
	t.Helper()
	buffer := make([]byte, 1500)
	for attempt := 0; attempt < 8; attempt++ {
		n, readErr := unix.Read(peerSocket, buffer)
		if readErr != nil {
			t.Fatalf("read a reply: %v (the request may have gone unanswered)", readErr)
		}
		candidate := parse(t, buffer[:n])
		if candidate.icmpType == requestICMPType {
			continue
		}
		return candidate, n
	}
	t.Fatal("only saw the echoed request on the raw socket, never a reply")
	return nil, 0
}

// assertFakeIPICMPReply checks every property fakeip_icmp's shared reply
// path promises against one parsed reply frame -- the assertion set every
// shared-role real-client-ping test in this file shares (socket_assign and
// packet_rewrite, IPv4 and IPv6, clsact and TCX), factored out so a new
// combination supplies only what actually differs (its own frame
// builder/parser and addresses), not another copy of these checks.
// checkIPChecksum must be false for an IPv6 reply, which has no IP header
// checksum to validate.
func assertFakeIPICMPReply(
	t *testing.T,
	reply *parsedICMPEchoReply,
	replyLength, requestLength int,
	expectedReplyType uint8,
	identifier, sequence uint16,
	payload []byte,
	fakeIPTarget, clientIP string,
	clientMAC, selfMAC net.HardwareAddr,
	checkIPChecksum bool,
) {
	t.Helper()
	if replyLength > requestLength {
		t.Fatalf("reply is %d bytes, longer than the %d-byte request — an amplification, not a reply", replyLength, requestLength)
	}
	if reply.icmpType != expectedReplyType {
		t.Fatalf("reply ICMP type = %d, want %d (Echo Reply)", reply.icmpType, expectedReplyType)
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
	if reply.dstMAC.String() != clientMAC.String() {
		t.Fatalf("reply Ethernet destination = %s, want the client's MAC %s (the reflected frame must actually reach the client)", reply.dstMAC, clientMAC)
	}
	if reply.srcMAC.String() != selfMAC.String() {
		t.Fatalf("reply Ethernet source = %s, want this interface's own MAC %s", reply.srcMAC, selfMAC)
	}
	if checkIPChecksum && !reply.ipChecksumOK {
		t.Fatal("reply IP header checksum does not validate")
	}
	if !reply.icmpChecksumOK {
		t.Fatal("reply ICMP checksum does not validate")
	}
}

// newRealFakeIPICMPSharedNetworkBackendWithIPv6 is
// newRealFakeIPICMPSharedNetworkBackend plus a FakeIP IPv6 range and an
// IPv6 redirect prefix (which is what actually turns on IPv6 for this
// backend -- SharedNetworkConfig has no separate enable flag; see
// SharedNetworkConfig.FakeIPICMPReply's own doc comment).
func newRealFakeIPICMPSharedNetworkBackendWithIPv6(t *testing.T) *commonEBPF.SharedNetworkBackend {
	t.Helper()
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{
		EnableTCP:  true,
		FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15"),
		FakeIPIPv6: netip.MustParsePrefix("fc00::/18"),
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareSharedNetwork(nil, commonEBPF.SharedNetworkConfig{
		ListenerPort:    23459,
		EnableTCP:       true,
		RedirectIPv4:    netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6:    netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
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

// attachSharedRewriteOrSkip is attachFakeIPICMPOrSkip's counterpart for the
// shared packet-rewrite data plane's own attach function: when priority
// requests TCX (defaultTCPriority) but this kernel did not actually grant a
// TCX attachment, it defers to requireOrSkipTCX -- skip on a general
// environment, fail on one configured via tcxStrictModeEnv to require TCX
// -- since attachSharedRewriteInterface falls back to clsact silently and a
// test claiming TCX coverage must not pass having silently exercised
// clsact instead.
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

// TestFakeIPICMPLocalReplyAnswersARealIPv6PingViaClsact is
// TestFakeIPICMPLocalReplyAnswersARealPing's IPv6 counterpart, completing
// the local role's coverage: IPv4 clsact, IPv4 TCX, and IPv6 TCX already
// existed; this is IPv6 clsact, forced the same way the IPv4 clsact test
// forces it (priority=2), so it cannot silently exercise TCX instead.
func TestFakeIPICMPLocalReplyAnswersARealIPv6PingViaClsact(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackendWithIPv6(t)
	t.Cleanup(func() { _ = backend.Close() })

	const fakeIPTarget = "fc00::1"
	self := setupFakeIPICMPPingVethIPv6(t, "sbicmp60", "sbicmp61", fakeIPTarget)

	const priority = 2 // force clsact; TestFakeIPICMPLocalReplyAnswersARealIPv6PingViaTCX covers TCX.
	attachment := attachFakeIPICMPOrSkip(t, backend, "sbicmp60", self.Attrs().Index, tcInterfaceRole{local: true}, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.attachmentType != "clsact" {
		t.Fatalf("attachmentType = %q, want clsact", attachment.attachmentType)
	}
	if attachment.localICMPFilter == nil {
		t.Fatal("the fakeip_icmp clsact filter was not attached alongside the ordinary one")
	}

	before, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}
	if err = pingFakeIPICMPTargetV6(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("read a reply: %v (the request may have gone to the wire instead of being answered)", err)
	}
	after, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if after != before+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", after, before+1)
	}
}

// TestFakeIPICMPSharedReplyAnswersARealIPv6ClientPing is
// TestFakeIPICMPSharedReplyAnswersARealClientPing's IPv6 counterpart for
// shared.data_plane: socket_assign, forced onto clsact the same way.
func TestFakeIPICMPSharedReplyAnswersARealIPv6ClientPing(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackendWithIPv6(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	self, peer := createTestVethPair(t, "sbicmp6w0", "sbicmp6w1")

	const priority = 2 // force clsact; TestFakeIPICMPSharedReplyAnswersARealIPv6ClientPingViaTCX covers TCX.
	attachment := attachFakeIPICMPOrSkip(t, backend, "sbicmp6w0", self.Attrs().Index, tcInterfaceRole{shared: true}, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.sharedICMPFilter == nil {
		t.Fatal("the fakeip_icmp shared clsact filter was not attached alongside the ordinary one")
	}

	const fakeIPTarget = "fc00::1"
	const clientIP = "fd00:250::5"
	const identifier = 0x6321
	const sequence = 4
	payload := []byte("fakeip-icmp-shared-reply-v6-test-payload")

	requestFrame := buildEthernetIPv6EchoRequest(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(clientIP), net.ParseIP(fakeIPTarget),
		identifier, sequence, payload,
	)
	peerSocket := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IPV6, 5*time.Second)
	if _, err = unix.Write(peerSocket, requestFrame); err != nil {
		t.Fatalf("transmit the echo request onto the peer interface: %v", err)
	}

	reply, replyLength := readFakeIPICMPReplyFrame(t, peerSocket, 128, parseEthernetIPv6ICMP)
	assertFakeIPICMPReply(
		t, reply, replyLength, len(requestFrame), 129,
		identifier, sequence, payload, fakeIPTarget, clientIP,
		peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr, false,
	)

	repliesAfter, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if repliesAfter != repliesBefore+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", repliesAfter, repliesBefore+1)
	}
}

// TestFakeIPICMPSharedReplyAnswersARealClientPingViaTCX is
// TestFakeIPICMPSharedReplyAnswersARealClientPing over TCX instead of the
// forced clsact that test uses, completing shared.data_plane: socket_assign's
// IPv4 coverage the same way TestFakeIPICMPLocalReplyAnswersARealPingViaTCX
// completes the local role's. Skips (does not fail) on a kernel without TCX.
func TestFakeIPICMPSharedReplyAnswersARealClientPingViaTCX(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	self, peer := createTestVethPair(t, "sbicmpxw0", "sbicmpxw1")

	const priority = 1 // default: TCX is attempted.
	attachment := attachFakeIPICMPOrSkip(t, backend, "sbicmpxw0", self.Attrs().Index, tcInterfaceRole{shared: true}, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.sharedICMPLink == nil {
		t.Fatal("the fakeip_icmp TCX link was not attached alongside the ordinary one")
	}

	const fakeIPTarget = "198.18.0.1"
	const clientIP = "10.250.0.8"
	const identifier = 0x7654
	const sequence = 5
	payload := []byte("fakeip-icmp-shared-reply-tcx-test-payload")

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

	repliesAfter, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if repliesAfter != repliesBefore+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", repliesAfter, repliesBefore+1)
	}
}

// TestFakeIPICMPSharedReplyAnswersARealIPv6ClientPingViaTCX combines the
// previous two: shared.data_plane: socket_assign, IPv6, TCX -- the last of
// this data plane's four combinations. Skips on a kernel without TCX.
func TestFakeIPICMPSharedReplyAnswersARealIPv6ClientPingViaTCX(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackendWithIPv6(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	self, peer := createTestVethPair(t, "sbicmp6x0", "sbicmp6x1")

	const priority = 1
	attachment := attachFakeIPICMPOrSkip(t, backend, "sbicmp6x0", self.Attrs().Index, tcInterfaceRole{shared: true}, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.sharedICMPLink == nil {
		t.Fatal("the fakeip_icmp TCX link was not attached alongside the ordinary one")
	}

	const fakeIPTarget = "fc00::1"
	const clientIP = "fd00:250::6"
	const identifier = 0x8765
	const sequence = 6
	payload := []byte("fakeip-icmp-shared-reply-v6-tcx-test-payload")

	requestFrame := buildEthernetIPv6EchoRequest(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(clientIP), net.ParseIP(fakeIPTarget),
		identifier, sequence, payload,
	)
	peerSocket := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IPV6, 5*time.Second)
	if _, err = unix.Write(peerSocket, requestFrame); err != nil {
		t.Fatalf("transmit the echo request onto the peer interface: %v", err)
	}

	reply, replyLength := readFakeIPICMPReplyFrame(t, peerSocket, 128, parseEthernetIPv6ICMP)
	assertFakeIPICMPReply(
		t, reply, replyLength, len(requestFrame), 129,
		identifier, sequence, payload, fakeIPTarget, clientIP,
		peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr, false,
	)

	repliesAfter, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if repliesAfter != repliesBefore+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", repliesAfter, repliesBefore+1)
	}
}

// TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPing is
// TestFakeIPICMPSharedRewriteAnswersARealClientPing's IPv6 counterpart for
// shared.data_plane: packet_rewrite, forced onto clsact the same way.
func TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPing(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackendWithIPv6(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	self, peer := createTestVethPair(t, "sbrw6w0", "sbrw6w1")

	const priority = 2 // force clsact; TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPingViaTCX covers TCX.
	attachment, err := attachSharedRewriteInterface(self, backend, priority)
	if err != nil {
		t.Fatalf("attach the shared packet-rewrite interface: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.icmpFilter == nil {
		t.Fatal("the fakeip_icmp shared filter was not attached alongside packet_rewrite's own ingress/egress filters")
	}

	const fakeIPTarget = "fc00::1"
	const clientIP = "fd00:250::7"
	const identifier = 0x9876
	const sequence = 8
	payload := []byte("fakeip-icmp-shared-rewrite-v6-test-payload")

	requestFrame := buildEthernetIPv6EchoRequest(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(clientIP), net.ParseIP(fakeIPTarget),
		identifier, sequence, payload,
	)
	peerSocket := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IPV6, 5*time.Second)
	if _, err = unix.Write(peerSocket, requestFrame); err != nil {
		t.Fatalf("transmit the echo request onto the peer interface: %v", err)
	}

	reply, replyLength := readFakeIPICMPReplyFrame(t, peerSocket, 128, parseEthernetIPv6ICMP)
	assertFakeIPICMPReply(
		t, reply, replyLength, len(requestFrame), 129,
		identifier, sequence, payload, fakeIPTarget, clientIP,
		peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr, false,
	)

	repliesAfter, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if repliesAfter != repliesBefore+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", repliesAfter, repliesBefore+1)
	}
}

// TestFakeIPICMPSharedRewriteAnswersARealClientPingViaTCX is
// TestFakeIPICMPSharedRewriteAnswersARealClientPing over TCX instead of the
// forced clsact that test uses. The existing comment on that test's
// priority=2 line ("TCX is covered by attachSharedRewriteInterface's own
// existing coverage") refers only to the attachment mechanism itself
// attaching correctly, not to a real ICMP round trip over it -- this test
// is that missing proof. Skips (does not fail) on a kernel without TCX.
func TestFakeIPICMPSharedRewriteAnswersARealClientPingViaTCX(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackend(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	self, peer := createTestVethPair(t, "sbrwxw0", "sbrwxw1")

	const priority = 1 // default: TCX is attempted.
	attachment := attachSharedRewriteOrSkip(t, self, backend, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.icmpLink == nil {
		t.Fatal("the fakeip_icmp TCX link was not attached alongside packet_rewrite's own ingress/egress links")
	}

	const fakeIPTarget = "198.18.0.1"
	const clientIP = "10.250.0.9"
	const identifier = 0xa987
	const sequence = 9
	payload := []byte("fakeip-icmp-shared-rewrite-tcx-test-payload")

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

	repliesAfter, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if repliesAfter != repliesBefore+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", repliesAfter, repliesBefore+1)
	}
}

// TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPingViaTCX is the last
// cell in the matrix: shared.data_plane: packet_rewrite, IPv6, TCX. Skips
// on a kernel without TCX.
func TestFakeIPICMPSharedRewriteAnswersARealIPv6ClientPingViaTCX(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPSharedNetworkBackendWithIPv6(t)
	t.Cleanup(func() { _ = backend.Close() })
	repliesBefore, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount before: %v", err)
	}

	self, peer := createTestVethPair(t, "sbrw6x0", "sbrw6x1")

	const priority = 1
	attachment := attachSharedRewriteOrSkip(t, self, backend, priority)
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.icmpLink == nil {
		t.Fatal("the fakeip_icmp TCX link was not attached alongside packet_rewrite's own ingress/egress links")
	}

	const fakeIPTarget = "fc00::1"
	const clientIP = "fd00:250::8"
	const identifier = 0xba98
	const sequence = 10
	payload := []byte("fakeip-icmp-shared-rewrite-v6-tcx-test-payload")

	requestFrame := buildEthernetIPv6EchoRequest(
		self.Attrs().HardwareAddr, peer.Attrs().HardwareAddr,
		net.ParseIP(clientIP), net.ParseIP(fakeIPTarget),
		identifier, sequence, payload,
	)
	peerSocket := openRawLinkLayerSocket(t, peer.Attrs().Index, unix.ETH_P_IPV6, 5*time.Second)
	if _, err = unix.Write(peerSocket, requestFrame); err != nil {
		t.Fatalf("transmit the echo request onto the peer interface: %v", err)
	}

	reply, replyLength := readFakeIPICMPReplyFrame(t, peerSocket, 128, parseEthernetIPv6ICMP)
	assertFakeIPICMPReply(
		t, reply, replyLength, len(requestFrame), 129,
		identifier, sequence, payload, fakeIPTarget, clientIP,
		peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr, false,
	)

	repliesAfter, err := backend.FakeIPICMPReplyCount()
	if err != nil {
		t.Fatalf("read FakeIPICMPReplyCount after: %v", err)
	}
	if repliesAfter != repliesBefore+1 {
		t.Fatalf("FakeIPICMPReplyCount = %d, want %d after one successfully answered ping", repliesAfter, repliesBefore+1)
	}
}
