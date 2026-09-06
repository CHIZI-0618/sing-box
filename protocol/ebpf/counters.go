//go:build with_ebpf && (linux || android)

package ebpf

import "sync/atomic"

// ebpfCounters are the low-overhead, concurrency-safe counts item 8 of the
// eBPF inbound reliability work asks for: plain atomics, incremented at the
// point each event is already detected (never a new check added just to
// count it), read only when Diagnostics is called. None of them is per-
// client or per-destination -- that would be an unbounded cardinality this
// series has spent real effort keeping every other structure clear of (see
// udpReplySocketPool's fixed capacity) -- and none of them logs a single
// packet; a counter increments, nothing more.
//
// All of these are cumulative since the inbound started and never reset on
// their own: there is no "reset" operation, and none is needed, since every
// one of them is meant to answer "how many of these has this process ever
// seen", not "how many since I last looked". A caller wanting a rate takes
// two snapshots and subtracts.
type ebpfCounters struct {
	// assignmentLookupFailures is TC eBPF TCP/UDP assignment lookups
	// (tc_connection.go's two LookupAssignment call sites) that came back
	// empty or errored -- a packet the kernel classifier redirected here
	// with no matching userspace-visible assignment, so the connection had
	// to be dropped/closed instead of routed.
	assignmentLookupFailures atomic.Uint64
	// sharedReconcileFailures is shared packet-rewrite's own dataPlane.reconcile
	// failing (see updateTCInterfaces): the attach/health-check pass for
	// that data plane did not complete cleanly. This is not a per-packet
	// rewrite-failure count -- the native shared_network object has no
	// counter for that yet (see EBPFCounters' doc comment) -- it is the
	// data-plane-level failure this process can already observe without one.
	sharedReconcileFailures atomic.Uint64
	// recoveryAttempts, recoverySuccesses, and recoveryFailures track
	// interface_monitor.go's scheduler across all three of its components
	// (shared packet-rewrite, general TC, bypass_rule_set): one attempt per
	// round in which at least one component reported Recoverable, one
	// success per component transition from Recoverable to Settled, one
	// failure per component transition to Unrecoverable.
	recoveryAttempts  atomic.Uint64
	recoverySuccesses atomic.Uint64
	recoveryFailures  atomic.Uint64
}

// EBPFCounters is ebpfCounters' point-in-time snapshot for diagnostics.
//
// TokenReservationFailures and UDPReplySockets (embedded in EBPFDiagnostics
// alongside this) round out item 8's full list; they are not duplicated
// here because they already have their own accurate source: shared
// packet-rewrite's native object already counts token-reservation failures
// in the kernel (SharedNetworkBackend.TokenReservationFailures, wired into
// shared_network_flow.h's reserve_token) and udpReplySocketPool already
// tracks capacity rejections and reclaims (item 4). Item 8's "packet
// rewrite failures" and "FakeIP ICMP replies, parse/policy pass-throughs,
// rewrite-failure drops" bullets need new per-packet counters inside the
// native objects themselves (shared_network.bpf.c and fakeip_icmp.bpf.c
// respectively); this round does not add them; see the delivery notes for
// why (rebuilding the native objects requires the pinned Android NDK r29
// Clang 21 toolchain this environment does not have, and changing the .c
// sources without regenerating the checked-in objects would leave them out
// of sync).
type EBPFCounters struct {
	AssignmentLookupFailures uint64 `json:"assignment_lookup_failures"`
	// TokenReservationFailures is 0 whenever this inbound has no shared
	// packet-rewrite backend to read it from, not necessarily because
	// nothing ever failed.
	TokenReservationFailures uint64 `json:"token_reservation_failures"`
	SharedReconcileFailures  uint64 `json:"shared_reconcile_failures"`
	RecoveryAttempts         uint64 `json:"recovery_attempts"`
	RecoverySuccesses        uint64 `json:"recovery_successes"`
	RecoveryFailures         uint64 `json:"recovery_failures"`
}

func (c *ebpfCounters) snapshot() EBPFCounters {
	return EBPFCounters{
		AssignmentLookupFailures: c.assignmentLookupFailures.Load(),
		SharedReconcileFailures:  c.sharedReconcileFailures.Load(),
		RecoveryAttempts:         c.recoveryAttempts.Load(),
		RecoverySuccesses:        c.recoverySuccesses.Load(),
		RecoveryFailures:         c.recoveryFailures.Load(),
	}
}
