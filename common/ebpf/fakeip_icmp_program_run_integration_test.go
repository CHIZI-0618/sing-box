//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFakeIPICMPPassThroughIntegration executes the native classifier with
// BPF_PROG_TEST_RUN. Every case is deliberately outside the responder's safe
// subset and must return TC_ACT_UNSPEC without changing a byte.
func TestFakeIPICMPPassThroughIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify fakeip_icmp native pass-through behavior")
	policy := newTestFakeIPPolicy(t, "198.18.0.0/15", "fc00::/18")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:    65531,
		EnableLocal:     true,
		EnableIPv4:      true,
		EnableLocalIPv6: true,
		EnableTCP:       true,
		Policy:          policy,
		FakeIPICMPReply: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	program := backend.FakeIPICMPLocalReplyProgram(TCLinkFramingEthernet)
	if program == nil {
		t.Fatal("fakeip_icmp local Ethernet program is unavailable")
	}

	validIPv4 := testIPv4EchoPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.0.1"))
	validIPv6 := testIPv6EchoPacket(netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("fc00::1"))
	ipv4Options := testIPv4EchoPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.0.1"))
	ipv4Options = append(ipv4Options, 0, 0, 0, 0)
	copy(ipv4Options[14+24:], validIPv4[14+20:])
	ipv4Options[14] = 0x46
	binary.BigEndian.PutUint16(ipv4Options[16:18], uint16(len(ipv4Options)-14))
	ipv6Extension := testIPv6EchoPacket(netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("fc00::1"))
	ipv6Extension = append(ipv6Extension, make([]byte, 8)...)
	copy(ipv6Extension[14+48:], validIPv6[14+40:])
	ipv6Extension[14+6] = 0 // Hop-by-Hop Options
	ipv6Extension[14+40] = unix.IPPROTO_ICMPV6
	binary.BigEndian.PutUint16(ipv6Extension[14+4:14+6], 16)

	testCases := []struct {
		name   string
		packet []byte
	}{
		{"non-FakeIP destination", testIPv4EchoPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.1"))},
		{"non-Echo ICMP", mutatePacket(validIPv4, func(packet []byte) { packet[14+20] = 3 })},
		{"Echo code is nonzero", mutatePacket(validIPv4, func(packet []byte) { packet[14+21] = 1 })},
		{"IPv4 options", ipv4Options},
		{"IPv4 fragment", mutatePacket(validIPv4, func(packet []byte) { binary.BigEndian.PutUint16(packet[14+6:14+8], 0x2000) })},
		{"IPv6 extension header", ipv6Extension},
		{"truncated IPv4 payload", validIPv4[:len(validIPv4)-1]},
		{"truncated IPv6 payload", validIPv6[:len(validIPv6)-1]},
		{"IPv4 declared length below Echo header", mutatePacket(validIPv4, func(packet []byte) { binary.BigEndian.PutUint16(packet[14+2:14+4], 27) })},
		{"IPv6 declared length below Echo header", mutatePacket(validIPv6, func(packet []byte) { binary.BigEndian.PutUint16(packet[14+4:14+6], 7) })},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			action, output := runTCProgram(t, program, testCase.packet)
			if action != testTCActUnspec {
				t.Fatalf("packet was claimed: action=%d", action)
			}
			if !bytes.Equal(output, testCase.packet) {
				t.Fatal("pass-through packet was modified")
			}
		})
	}

	controlMap := backend.fakeIPICMP.runtime.maps["fakeip_icmp_control"]
	zero := uint32(0)
	disabled := fakeIPICMPControl{}
	if err = controlMap.Update(&zero, &disabled, 0); err != nil {
		t.Fatalf("disable fakeip_icmp control: %v", err)
	}
	action, output := runTCProgram(t, program, validIPv4)
	if action != testTCActUnspec {
		t.Fatalf("feature-off packet was claimed: action=%d", action)
	}
	if !bytes.Equal(output, validIPv4) {
		t.Fatal("feature-off packet was modified")
	}
}

func testIPv4EchoPacket(source, destination netip.Addr) []byte {
	const ethernetLength = 14
	const ipv4Length = 20
	const icmpLength = 8
	packet := make([]byte, ethernetLength+ipv4Length+icmpLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip := packet[ethernetLength:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], ipv4Length+icmpLength)
	ip[8] = 64
	ip[9] = unix.IPPROTO_ICMP
	source4 := source.As4()
	destination4 := destination.As4()
	copy(ip[12:16], source4[:])
	copy(ip[16:20], destination4[:])
	ip[ipv4Length] = 8
	return packet
}

func testIPv6EchoPacket(source, destination netip.Addr) []byte {
	const ethernetLength = 14
	const ipv6Length = 40
	const icmpLength = 8
	packet := make([]byte, ethernetLength+ipv6Length+icmpLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IPV6)
	ip := packet[ethernetLength:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], icmpLength)
	ip[6] = unix.IPPROTO_ICMPV6
	ip[7] = 64
	source6 := source.As16()
	destination6 := destination.As16()
	copy(ip[8:24], source6[:])
	copy(ip[24:40], destination6[:])
	ip[ipv6Length] = 128
	return packet
}

func mutatePacket(packet []byte, mutate func([]byte)) []byte {
	clone := append([]byte(nil), packet...)
	mutate(clone)
	return clone
}
