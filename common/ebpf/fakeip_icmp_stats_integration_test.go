//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"
)

// TestFakeIPICMPStatsCountsPassThroughNotOrdinaryTraffic distinguishes an
// unsupported echo request from unrelated traffic to the same FakeIP.
func TestFakeIPICMPStatsCountsPassThroughNotOrdinaryTraffic(t *testing.T) {
	requireEBPFIntegration(t, "verify fakeip_icmp_stats counts pass-through correctly")
	policy := newTestFakeIPPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:    65530,
		EnableLocal:     true,
		EnableIPv4:      true,
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

	before, err := backend.FakeIPICMPPassThroughCount()
	if err != nil {
		t.Fatalf("read PassThroughCount before: %v", err)
	}

	// An ICMP Echo Request with IPv4 options: this object commits to no
	// options at all, so this is a disqualified ICMP packet -- PassThrough.
	validIPv4 := testIPv4EchoPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.0.1"))
	ipv4Options := append(validIPv4, 0, 0, 0, 0)
	copy(ipv4Options[14+24:], validIPv4[14+20:])
	ipv4Options[14] = 0x46
	action, _ := runTCProgram(t, program, ipv4Options)
	if action != testTCActUnspec {
		t.Fatalf("disqualified ICMP packet was claimed: action=%d", action)
	}

	afterDisqualifiedICMP, err := backend.FakeIPICMPPassThroughCount()
	if err != nil {
		t.Fatalf("read PassThroughCount after disqualified ICMP: %v", err)
	}
	if afterDisqualifiedICMP != before+1 {
		t.Fatalf("PassThroughCount = %d, want %d after one disqualified ICMP packet", afterDisqualifiedICMP, before+1)
	}

	// An ordinary TCP packet to the same FakeIP destination: not ICMP at
	// all, so this must not move PassThroughCount even one more.
	tcpPacket := testIPv4TCPPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.0.1"), 51234, 80)
	action, _ = runTCProgram(t, program, tcpPacket)
	if action != testTCActUnspec {
		t.Fatalf("ordinary TCP packet was claimed: action=%d", action)
	}

	afterTCP, err := backend.FakeIPICMPPassThroughCount()
	if err != nil {
		t.Fatalf("read PassThroughCount after TCP packet: %v", err)
	}
	if afterTCP != afterDisqualifiedICMP {
		t.Fatalf("PassThroughCount = %d, want unchanged at %d -- an ordinary TCP packet must not count as an ICMP pass-through",
			afterTCP, afterDisqualifiedICMP)
	}
}

// TestFakeIPICMPStatsZeroWhenDisabled confirms the trivial case: a backend
// that never enabled fakeip_icmp has no counters to read at all, matching
// FakeIPICMPEnabled's own existing false-when-off contract.
func TestFakeIPICMPStatsZeroWhenDisabled(t *testing.T) {
	policy := newTestFakeIPPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65530,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if _, err := backend.FakeIPICMPReplyCount(); err == nil {
		t.Fatal("FakeIPICMPReplyCount succeeded on a backend that never enabled fakeip_icmp")
	}
	if _, err := backend.FakeIPICMPPassThroughCount(); err == nil {
		t.Fatal("FakeIPICMPPassThroughCount succeeded on a backend that never enabled fakeip_icmp")
	}
	if _, err := backend.FakeIPICMPRewriteFailureCount(); err == nil {
		t.Fatal("FakeIPICMPRewriteFailureCount succeeded on a backend that never enabled fakeip_icmp")
	}
}
