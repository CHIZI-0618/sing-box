//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"reflect"
	"testing"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
)

// TestRevertBypassCIDRBackendsRevertsMostRecentFirst proves the unwind order:
// the backend that was applied last (and so is most likely to be the one
// whose own failure triggered the unwind) is reverted first, matching how a
// stack of partially-applied changes is normally unwound.
func TestRevertBypassCIDRBackendsRevertsMostRecentFirst(t *testing.T) {
	var order []string
	applied := []bypassCIDRAppliedBackend{
		{name: "TC", revert: func() error { order = append(order, "TC"); return nil }},
		{name: "cgroup", revert: func() error { order = append(order, "cgroup"); return nil }},
		{name: "shared", revert: func() error { order = append(order, "shared"); return nil }},
	}
	failed := revertBypassCIDRBackends(applied, func(string, error) { t.Fatal("no revert should fail in this case") })
	if len(failed) != 0 {
		t.Fatalf("failed = %v, want none", failed)
	}
	want := []string{"shared", "cgroup", "TC"}
	if len(order) != len(want) {
		t.Fatalf("revert order = %v, want %v", order, want)
	}
	for index, name := range want {
		if order[index] != name {
			t.Fatalf("revert order = %v, want %v", order, want)
		}
	}
}

// TestRevertBypassCIDRBackendsReportsEveryFailedPath proves the unwind does
// not stop at the first backend that refuses to revert: a later backend
// (earlier in application order) that also cannot revert is exactly as
// important to report as the first, since both are now on the new policy
// with no compensating change applied.
func TestRevertBypassCIDRBackendsReportsEveryFailedPath(t *testing.T) {
	tcErr := errString("TC revert failed")
	sharedErr := errString("shared revert failed")
	applied := []bypassCIDRAppliedBackend{
		{name: "TC", revert: func() error { return tcErr }},
		{name: "cgroup", revert: func() error { return nil }},
		{name: "shared", revert: func() error { return sharedErr }},
	}
	var warned []string
	failed := revertBypassCIDRBackends(applied, func(name string, err error) { warned = append(warned, name) })
	if len(failed) != 2 || failed[0] != "shared" || failed[1] != "TC" {
		t.Fatalf("failed = %v, want [shared TC] (revert order, both reported despite TC being tried after cgroup succeeded)", failed)
	}
	if len(warned) != 2 {
		t.Fatalf("warn was called %d times, want once per failed backend", len(warned))
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// newLoopbackTestTCBackend prepares a real TC eBPF backend with no interface
// attachment at all -- exactly what applyBypassCIDRPolicyLocked needs, since
// it only ever calls the backend's own policy-update methods, never anything
// attachment-related.
func newLoopbackTestTCBackend(t *testing.T) *commonEBPF.TCBackend {
	t.Helper()
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort: 23457,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func bypassPolicyFor(t *testing.T, prefixes ...netip.Prefix) commonEBPF.BypassCIDRPolicy {
	t.Helper()
	policy, err := commonEBPF.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		t.Fatalf("compile bypass CIDR policy: %v", err)
	}
	return policy
}

// TestApplyBypassCIDRPolicyRevertsAnEarlierBackendWhenALaterOneFails is the
// core proof for item 6: a real TC backend takes the new policy first and
// succeeds, a permanently-unusable cgroup backend (its zero value -- never
// loaded, so every call reports the backend as not usable) then fails, and
// the already-applied TC backend must end up back on the previous policy
// rather than left on the new one nothing else agrees with.
//
// TC's own state is not directly observable from outside common/ebpf, so
// this checks it indirectly: calling UpdateCompiledBypassCIDR with the
// previous policy again afterward must report changed=false -- the backend
// is already there -- which would be false (changed=true, a real diff) had
// the revert not actually happened.
//
// It also proves the version bookkeeping on this same successful-revert
// path: the attempt counter still advances (a failed attempt is still an
// attempt), but TC's own backend version -- having been bumped to the new
// value when its forward apply succeeded -- is rolled back to the version it
// held before this call once its compensating revert also succeeds, so a
// diagnostics reader sees TC as caught back up to what bypassRuleSetPolicy
// itself was rolled back to, not left claiming the new version it never
// actually kept.
func TestApplyBypassCIDRPolicyRevertsAnEarlierBackendWhenALaterOneFails(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	previous := bypassPolicyFor(t, netip.MustParsePrefix("10.0.0.0/8"))
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.tcDataPlane = &tcDataPlane{backend: tc}
	inbound.setCgroupBackend(&commonEBPF.CgroupBackend{}) // zero value: never usable
	inbound.bypassRuleSetPolicy = previous
	inbound.bypassRuleSetVersion = 5
	inbound.bypassRuleSetTCVersion = 5

	err := inbound.applyBypassCIDRPolicyLocked(next)
	if err == nil {
		t.Fatal("apply succeeded despite the cgroup backend being permanently unusable")
	}
	if inbound.bypassRuleSetInconsistent {
		t.Fatal("marked inconsistent even though TC's own revert had no reason to fail")
	}
	if !reflect.DeepEqual(inbound.bypassRuleSetPolicy, previous) {
		t.Fatalf("bypassRuleSetPolicy = %+v, want it left at the previous policy on failure", inbound.bypassRuleSetPolicy)
	}
	changed, revertCheckErr := tc.UpdateCompiledBypassCIDR(previous)
	if revertCheckErr != nil {
		t.Fatalf("re-apply the previous policy to check TC's state: %v", revertCheckErr)
	}
	if changed {
		t.Fatal("TC backend was not actually reverted to the previous policy: re-applying it was not a no-op")
	}
	if inbound.bypassRuleSetVersion != 6 {
		t.Fatalf("bypassRuleSetVersion = %d, want 6 (the attempt counter advances even on a failed attempt)", inbound.bypassRuleSetVersion)
	}
	if inbound.bypassRuleSetTCVersion != 5 {
		t.Fatalf("bypassRuleSetTCVersion = %d, want 5 (rolled back to the pre-attempt version once TC's own revert succeeded)", inbound.bypassRuleSetTCVersion)
	}
}

// TestApplyBypassCIDRPolicyLeavesBackendVersionOnFailedRevert is the
// companion to the test above for the case EBPFDiagnostics'
// BypassRuleSetConsistent=false is meant to flag: a backend's own
// compensating revert fails too, so its true state relative to
// bypassRuleSetPolicy is unknown, and its recorded version is left at the
// new value it was bumped to on the (later-unwound) forward apply rather
// than being rolled back to a number that would falsely claim it is back on
// the previous policy.
//
// TC's UpdateCompiledBypassCIDR rejects any policy over
// commonEBPF's compiled-in bypass CIDR map capacity (65536 entries)
// before touching the backend's state at all, independent of whether the
// backend is otherwise healthy. That check is used here, rather than a
// fake/mock backend, to make the revert call itself fail with a real,
// reproducible error without adding a test-only seam to the production
// type: "previous" is deliberately compiled from more prefixes than the
// cap allows (each one isolated so compileBypassCIDRPolicy's set builder
// cannot merge them into fewer, in-cap prefixes), so the forward apply of
// a small, valid "next" policy succeeds first, and only the later revert
// back to the oversized "previous" fails.
func TestApplyBypassCIDRPolicyLeavesBackendVersionOnFailedRevert(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	previous := oversizedBypassPolicy(t)
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.logger = log.NewNOPFactory().Logger()
	inbound.tcDataPlane = &tcDataPlane{backend: tc}
	inbound.setCgroupBackend(&commonEBPF.CgroupBackend{}) // zero value: never usable
	inbound.bypassRuleSetPolicy = previous
	inbound.bypassRuleSetVersion = 5
	inbound.bypassRuleSetTCVersion = 5

	err := inbound.applyBypassCIDRPolicyLocked(next)
	if err == nil {
		t.Fatal("apply succeeded despite the cgroup backend being permanently unusable")
	}
	if !inbound.bypassRuleSetInconsistent {
		t.Fatal("want bypassRuleSetInconsistent=true: TC's own revert to the oversized previous policy must have failed")
	}
	if inbound.bypassRuleSetVersion != 6 {
		t.Fatalf("bypassRuleSetVersion = %d, want 6 (the attempt counter advances even on a failed attempt)", inbound.bypassRuleSetVersion)
	}
	if inbound.bypassRuleSetTCVersion != 6 {
		t.Fatalf(
			"bypassRuleSetTCVersion = %d, want 6 (left at the new version: TC's own revert failed, so its true "+
				"state is unknown and must not be reported as caught back up to the pre-attempt version)",
			inbound.bypassRuleSetTCVersion,
		)
	}
}

// oversizedBypassPolicy compiles a BypassCIDRPolicy with one more IPv4
// prefix than commonEBPF's bypass CIDR map capacity allows, guaranteed not
// to collapse into fewer, in-cap prefixes: each address is spaced four
// apart, so no two are adjacent and compileBypassCIDRPolicy's IPSetBuilder
// cannot merge any of them into a larger CIDR block.
func oversizedBypassPolicy(t *testing.T) commonEBPF.BypassCIDRPolicy {
	t.Helper()
	const entries = 65537
	prefixes := make([]netip.Prefix, 0, entries)
	for i := 0; i < entries; i++ {
		offset := uint32(i) * 4
		addr := netip.AddrFrom4([4]byte{10, byte(offset >> 16), byte(offset >> 8), byte(offset)})
		prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
	}
	return bypassPolicyFor(t, prefixes...)
}

// TestApplyBypassCIDRPolicySucceedsAcrossRealBackends is the companion
// clean-path proof: with every backend usable, the policy lands on all of
// them and bypassRuleSetPolicy tracks the new value, and the version
// bookkeeping reflects a single successful attempt: the attempt counter
// advances by one, and TC's own version is set to that same new value.
func TestApplyBypassCIDRPolicySucceedsAcrossRealBackends(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.tcDataPlane = &tcDataPlane{backend: tc}
	inbound.bypassRuleSetVersion = 5
	inbound.bypassRuleSetTCVersion = 5

	if err := inbound.applyBypassCIDRPolicyLocked(next); err != nil {
		t.Fatalf("apply with only a healthy TC backend: %v", err)
	}
	if !reflect.DeepEqual(inbound.bypassRuleSetPolicy, next) {
		t.Fatalf("bypassRuleSetPolicy = %+v, want the newly-applied policy", inbound.bypassRuleSetPolicy)
	}
	if inbound.bypassRuleSetInconsistent {
		t.Fatal("marked inconsistent after a fully successful apply")
	}
	if inbound.bypassRuleSetVersion != 6 {
		t.Fatalf("bypassRuleSetVersion = %d, want 6 (one attempt beyond the starting version)", inbound.bypassRuleSetVersion)
	}
	if inbound.bypassRuleSetTCVersion != 6 {
		t.Fatalf("bypassRuleSetTCVersion = %d, want 6 (TC caught up to the new version on a successful apply)", inbound.bypassRuleSetTCVersion)
	}
}
