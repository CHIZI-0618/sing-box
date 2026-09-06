//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

func TestParsePreMatchIPv4TCPSYN(t *testing.T) {
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = uint8(header.TCPProtocolNumber)
	copy(packet[12:16], netip.MustParseAddr("192.0.2.10").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("198.51.100.20").AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 443)
	packet[32] = 5 << 4
	packet[33] = uint8(header.TCPFlagSyn)

	parsed, ok := parsePreMatchPacket(packet)
	if !ok {
		t.Fatal("TCP SYN was not parsed")
	}
	if parsed.protocol != uint8(header.TCPProtocolNumber) {
		t.Fatalf("unexpected protocol: %d", parsed.protocol)
	}
	if parsed.source != netip.MustParseAddrPort("192.0.2.10:40000") {
		t.Fatalf("unexpected source: %s", parsed.source)
	}
	if parsed.destination != netip.MustParseAddrPort("198.51.100.20:443") {
		t.Fatalf("unexpected destination: %s", parsed.destination)
	}
}

func TestParsePreMatchFragmentsBypass(t *testing.T) {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[6] = 0x20
	packet[9] = uint8(header.UDPProtocolNumber)
	binary.BigEndian.PutUint16(packet[24:26], header.UDPMinimumSize)
	if _, ok := parsePreMatchPacket(packet); ok {
		t.Fatal("fragment was parsed for pre-match")
	}
}

func TestParsePreMatchIPv6HonorsPayloadLength(t *testing.T) {
	packet := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
	packet[0] = 0x60
	packet[6] = uint8(header.TCPProtocolNumber)
	if _, ok := parsePreMatchPacket(packet); ok {
		t.Fatal("IPv6 bytes beyond the declared payload were parsed")
	}
}

func TestPreMatchProtocols(t *testing.T) {
	controller := &preMatchController{enableTCP: true}
	if got := controller.protocols(); len(got) != 1 || got[0] != "tcp" {
		t.Fatalf("unexpected TCP-only protocols: %v", got)
	}
	controller.enableTCP = false
	controller.enableUDP = true
	if got := controller.protocols(); len(got) != 1 || got[0] != "udp" {
		t.Fatalf("unexpected UDP-only protocols: %v", got)
	}
}

func TestPreMatchFilterHooks(t *testing.T) {
	controller := &preMatchController{localEnabled: true}
	if got := controller.filterHooks(); !slices.Equal(got, []string{"OUTPUT"}) {
		t.Fatalf("unexpected local filter hooks: %v", got)
	}
	controller.localEnabled = false
	controller.sharedEnabled = true
	if got := controller.filterHooks(); !slices.Equal(got, []string{"INPUT", "FORWARD"}) {
		t.Fatalf("unexpected shared filter hooks: %v", got)
	}
	controller.localEnabled = true
	if got := controller.filterHooks(); !slices.Equal(got, []string{"OUTPUT", "INPUT", "FORWARD"}) {
		t.Fatalf("unexpected combined filter hooks: %v", got)
	}
}
