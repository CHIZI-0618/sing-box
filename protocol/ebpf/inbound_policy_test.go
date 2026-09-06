//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"reflect"
	"testing"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
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
func TestApplyBypassCIDRPolicyRevertsAnEarlierBackendWhenALaterOneFails(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	previous := bypassPolicyFor(t, netip.MustParsePrefix("10.0.0.0/8"))
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.tcDataPlane = &tcDataPlane{backend: tc}
	inbound.setCgroupBackend(&commonEBPF.CgroupBackend{}) // zero value: never usable
	inbound.bypassRuleSetPolicy = previous

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
}

// TestApplyBypassCIDRPolicySucceedsAcrossRealBackends is the companion
// clean-path proof: with every backend usable, the policy lands on all of
// them and bypassRuleSetPolicy tracks the new value.
func TestApplyBypassCIDRPolicySucceedsAcrossRealBackends(t *testing.T) {
	tc := newLoopbackTestTCBackend(t)
	next := bypassPolicyFor(t, netip.MustParsePrefix("192.168.0.0/16"))

	inbound := &Inbound{}
	inbound.tcDataPlane = &tcDataPlane{backend: tc}

	if err := inbound.applyBypassCIDRPolicyLocked(next); err != nil {
		t.Fatalf("apply with only a healthy TC backend: %v", err)
	}
	if !reflect.DeepEqual(inbound.bypassRuleSetPolicy, next) {
		t.Fatalf("bypassRuleSetPolicy = %+v, want the newly-applied policy", inbound.bypassRuleSetPolicy)
	}
	if inbound.bypassRuleSetInconsistent {
		t.Fatal("marked inconsistent after a fully successful apply")
	}
}
