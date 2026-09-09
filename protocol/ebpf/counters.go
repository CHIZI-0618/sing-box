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

// EBPFCounters is ebpfCounters' point-in-time snapshot for diagnostics,
// merged with counters read fresh from the kernel on every call rather than
// tracked as Go-side atomics: TokenReservationFailures and RewriteFailures
// (shared packet-rewrite's own native object, shared_network.bpf.c) and
// FakeIPICMPReplies/FakeIPICMPPassThrough/FakeIPICMPRewriteFailureDrops
// (the fakeip_icmp responder, common to every path that hosts it -- local
// TC, shared socket_assign, and shared packet_rewrite -- summed across
// however many of those this inbound actually has enabled). UDPReplySockets
// (embedded in EBPFDiagnostics alongside this) rounds out item 8's list
// from udpReplySocketPool's own existing capacity/reclaim tracking (item 4).
type EBPFCounters struct {
	AssignmentLookupFailures uint64 `json:"assignment_lookup_failures"`
	// TokenReservationFailures and RewriteFailures are 0 whenever this
	// inbound has no shared packet-rewrite backend to read them from, not
	// necessarily because nothing ever failed.
	TokenReservationFailures uint64 `json:"token_reservation_failures"`
	RewriteFailures          uint64 `json:"rewrite_failures"`
	SharedReconcileFailures  uint64 `json:"shared_reconcile_failures"`
	RecoveryAttempts         uint64 `json:"recovery_attempts"`
	RecoverySuccesses        uint64 `json:"recovery_successes"`
	RecoveryFailures         uint64 `json:"recovery_failures"`
	// FakeIPICMPReplies, FakeIPICMPPassThrough, and
	// FakeIPICMPRewriteFailureDrops are all 0 when fakeip_icmp is not
	// enabled on any path, not necessarily because nothing happened.
	// PassThrough counts only ICMP/ICMPv6 Echo Request this object examined
	// and declined to answer -- never ordinary non-ICMP traffic on the same
	// interface, which would make it a count of ambient traffic rather than
	// a fact about fakeip_icmp's own behavior.
	FakeIPICMPReplies             uint64 `json:"fakeip_icmp_replies"`
	FakeIPICMPPassThrough         uint64 `json:"fakeip_icmp_pass_through"`
	FakeIPICMPRewriteFailureDrops uint64 `json:"fakeip_icmp_rewrite_failure_drops"`
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
