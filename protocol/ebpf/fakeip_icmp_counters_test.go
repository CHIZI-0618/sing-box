//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/binary"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/sys/unix"
)

// runFakeIPICMPProgram drives a fakeip_icmp program directly via
// BPF_PROG_TEST_RUN, the same technique common/ebpf's own
// TestFakeIPICMPPassThroughIntegration uses -- reused here rather than
// duplicated, to prove Diagnostics' counter wiring against a real,
// distinguishable count rather than the all-zero state a fresh backend
// already has (which cannot tell "correctly wired" apart from "not wired
// at all").
func runFakeIPICMPProgram(t *testing.T, program *CiliumEBPF.Program, packet []byte) uint32 {
	t.Helper()
	output := make([]byte, len(packet)+256)
	options := &CiliumEBPF.RunOptions{Data: packet, DataOut: output, Repeat: 1}
	action, err := program.Run(options)
	if err != nil {
		t.Fatalf("run fakeip_icmp program: %v", err)
	}
	return action
}

// testDisqualifiedEchoRequest builds an IPv4 ICMP Echo Request destined to
// 198.18.0.1 (inside the FakeIP prefix newRealFakeIPICMPBackend configures)
// with IPv4 options set -- disqualified by fakeip_icmp's own safe-subset
// rule (no options), which is exactly what SB_FAKEIP_ICMP_STAT_PASS_THROUGH
// counts.
func testDisqualifiedEchoRequest() []byte {
	const ethernetLength = 14
	const ipv4Length = 24 // IHL 6: one 32-bit options word beyond the fixed 20
	const icmpLength = 8
	packet := make([]byte, ethernetLength+ipv4Length+icmpLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip := packet[ethernetLength:]
	ip[0] = 0x46 // version 4, IHL 6 (options present)
	binary.BigEndian.PutUint16(ip[2:4], ipv4Length+icmpLength)
	ip[8] = 64
	ip[9] = unix.IPPROTO_ICMP
	copy(ip[12:16], []byte{192, 0, 2, 10})
	copy(ip[16:20], []byte{198, 18, 0, 1})
	icmp := ip[ipv4Length:]
	icmp[0] = 8 // Echo Request
	return packet
}

// TestDiagnosticsSumsFakeIPICMPCountersFromTCBackend proves Diagnostics'
// counter wiring against a real, distinguishable count: a disqualified ICMP
// packet run directly through the real local-reply program bumps
// PassThroughCount by exactly one, and Diagnostics() reports that same
// value, not zero (which a broken wiring would also show, indistinguishably
// from correct-but-idle).
func TestDiagnosticsSumsFakeIPICMPCountersFromTCBackend(t *testing.T) {
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC, fakeIPICMPReply: true}
	inbound.tcDataPlane = &tcDataPlane{backend: backend}

	before := inbound.Diagnostics().Counters
	if before.FakeIPICMPPassThrough != 0 {
		t.Fatalf("FakeIPICMPPassThrough = %d, want 0 before anything ran", before.FakeIPICMPPassThrough)
	}

	program := backend.FakeIPICMPLocalReplyProgram(commonEBPF.TCLinkFramingEthernet)
	if program == nil {
		t.Fatal("fakeip_icmp local Ethernet program is unavailable")
	}
	action := runFakeIPICMPProgram(t, program, testDisqualifiedEchoRequest())
	if action != ^uint32(0) { // TC_ACT_UNSPEC
		t.Fatalf("disqualified ICMP packet was claimed: action=%d", action)
	}

	after := inbound.Diagnostics().Counters
	if after.FakeIPICMPPassThrough != before.FakeIPICMPPassThrough+1 {
		t.Fatalf("Diagnostics().Counters.FakeIPICMPPassThrough = %d, want %d after one disqualified ICMP packet",
			after.FakeIPICMPPassThrough, before.FakeIPICMPPassThrough+1)
	}
	if after.FakeIPICMPReplies != 0 || after.FakeIPICMPRewriteFailureDrops != 0 {
		t.Fatalf("Diagnostics().Counters = %+v, want replies and rewrite-failure-drops still at 0", after)
	}
}

// TestDiagnosticsFakeIPICMPCountersZeroWhenDisabled confirms a backend with
// fakeip_icmp off reports zero counters rather than an error surfacing as a
// nonzero/garbage value.
func TestDiagnosticsFakeIPICMPCountersZeroWhenDisabled(t *testing.T) {
	backend := newLoopbackTestTCBackend(t)

	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.tcDataPlane = &tcDataPlane{backend: backend}

	counters := inbound.Diagnostics().Counters
	if counters.FakeIPICMPReplies != 0 || counters.FakeIPICMPPassThrough != 0 || counters.FakeIPICMPRewriteFailureDrops != 0 {
		t.Fatalf("fakeip_icmp counters = %+v, want all zero when fakeip_icmp was never enabled", counters)
	}
}
