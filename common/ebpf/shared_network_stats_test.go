//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// TestSharedNetworkStatsReadCleanlyWithNoFailures is a minimal sanity check
// for RewriteFailures (item 8's kernel-side "packet rewrite failures"
// counter, native/shared_network_rewrite.h) alongside the pre-existing
// TokenReservationFailures: both must read back as zero, with no error, on a
// freshly-prepared backend that has never processed a packet. Genuinely
// forcing rewrite_ipv4/rewrite_ipv6 or reserve_token to fail requires
// conditions (a checksum helper failing, token space exhaustion) this test
// environment cannot manufacture; the real reply-path netns tests in
// protocol/ebpf independently prove the reply-succeeds side of the same
// code paths against a real kernel.
func TestSharedNetworkStatsReadCleanlyWithNoFailures(t *testing.T) {
	policy := newTestSharedNetworkFakeIPPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedNetwork(nil, newTestSharedNetworkConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if tokenFailures, err := backend.TokenReservationFailures(); err != nil {
		t.Fatalf("TokenReservationFailures: %v", err)
	} else if tokenFailures != 0 {
		t.Fatalf("TokenReservationFailures = %d, want 0 on a backend that has processed nothing", tokenFailures)
	}
	if rewriteFailures, err := backend.RewriteFailures(); err != nil {
		t.Fatalf("RewriteFailures: %v", err)
	} else if rewriteFailures != 0 {
		t.Fatalf("RewriteFailures = %d, want 0 on a backend that has processed nothing", rewriteFailures)
	}
}

// TestSharedNetworkStatsIndependent proves the two categories are read from
// distinct indices, not the same counter under two names: incrementing the
// underlying kernel map at TokenReservationFailure's index directly must not
// move RewriteFailures.
func TestSharedNetworkStatsIndependent(t *testing.T) {
	policy := newTestSharedNetworkFakeIPPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedNetwork(nil, newTestSharedNetworkConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	statsMap := backend.runtime.maps["shared_stats"]
	if statsMap == nil {
		t.Fatal("shared_stats map is unavailable")
	}
	perCPU := make([]uint64, CiliumEBPF.MustPossibleCPU())
	perCPU[0] = 1
	if err := statsMap.Put(sharedNetworkStatTokenReservationFailure, perCPU); err != nil {
		t.Fatalf("seed shared_stats[token_reservation_failure]: %v", err)
	}

	tokenFailures, err := backend.TokenReservationFailures()
	if err != nil {
		t.Fatalf("TokenReservationFailures: %v", err)
	}
	if tokenFailures != 1 {
		t.Fatalf("TokenReservationFailures = %d, want 1", tokenFailures)
	}
	rewriteFailures, err := backend.RewriteFailures()
	if err != nil {
		t.Fatalf("RewriteFailures: %v", err)
	}
	if rewriteFailures != 0 {
		t.Fatalf("RewriteFailures = %d, want 0 -- it must not read the token-reservation-failure slot", rewriteFailures)
	}
}
