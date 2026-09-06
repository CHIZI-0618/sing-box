//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"strings"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"
)

// TestTCPolicyRollbackClassificationAndHealthContract covers two units the
// update entry points rely on, and nothing more: how a failed policy rollback is
// classified, and what invalidateLocked records.
//
// It does not exercise UpdateHostAddresses or UpdateCompiledBypassCIDR, and it
// does not show that the kernel data path was switched off — the backend here
// has no real control map, so the disable is expected to fail. What it pins is
// that the failure is surfaced rather than swallowed.
func TestTCPolicyRollbackClassificationAndHealthContract(t *testing.T) {
	updateErr := E.New("update failed")
	rollbackErr := E.New("rollback failed")

	if policyRollbackFailed(policyUpdateError(updateErr, nil)) {
		t.Fatal("a successful rollback must not be reported as a rollback failure")
	}
	wrapped := policyUpdateError(updateErr, rollbackErr)
	if !policyRollbackFailed(wrapped) {
		t.Fatal("a failed rollback must be detectable by the caller")
	}
	// Both entry points wrap the replace helper's error before the guard sees it,
	// so detection has to survive wrapping.
	if !policyRollbackFailed(E.Cause(wrapped, "update TC eBPF IPv6 host addresses")) {
		t.Fatal("rollback failure lost through E.Cause wrapping")
	}

	var backend TCBackend
	backend.runtime = &tcRuntime{}
	if err := backend.requireUsableLocked(); err != nil {
		t.Fatalf("a fresh backend should be usable: %v", err)
	}

	// Enabled starts at 1 so the transition is observable, and the control map FD
	// is invalid so writing the disable through to the kernel fails.
	backend.control.Enabled = 1
	backend.controlMapFD = -1
	invalidateErr := backend.invalidateLocked("host address policy", wrapped)

	if backend.control.Enabled != 0 {
		t.Fatalf("control.Enabled = %d after invalidation, want 0", backend.control.Enabled)
	}
	if !errors.Is(invalidateErr, updateErr) {
		t.Fatalf("the original update error must survive invalidation: %v", invalidateErr)
	}
	if !errors.Is(invalidateErr, rollbackErr) {
		t.Fatalf("the rollback error must survive invalidation: %v", invalidateErr)
	}
	// The in-memory flag was cleared but the write that would have applied it did
	// not land, and that has to be reported rather than dropped.
	if !strings.Contains(invalidateErr.Error(), "disable unusable TC backend") {
		t.Fatalf("the failed control map disable must stay in the error chain: %v", invalidateErr)
	}
	if backend.health.rebuildRequired == nil {
		t.Fatal("invalidation must record that a rebuild is required")
	}
	if !errors.Is(invalidateErr, backend.health.rebuildRequired) {
		t.Fatalf("the rebuild-required marker must be returned to the caller: %v", invalidateErr)
	}
	if backend.requireUsableLocked() == nil {
		t.Fatal("an invalidated backend must refuse further use")
	}
}

// TestTCBackendRequiresRebuild covers the public accessor protocol/ebpf's
// bypass_rule_set coordinator relies on to tell "this backend's own forward
// apply failed in a way its internal rollback also failed" apart from an
// ordinary, harmless rejection (a policy over capacity, say): the backend
// is still open (a real caller cannot distinguish it from a healthy one any
// other way), but every later operation on it will keep failing the same
// way. Mirrors TestSharedNetworkBackendRequiresRebuild.
func TestTCBackendRequiresRebuild(t *testing.T) {
	var backend TCBackend
	if backend.RequiresRebuild() {
		t.Fatal("a fresh backend reports that it requires a rebuild")
	}

	backend.runtime = &tcRuntime{}
	if backend.requireUsableLocked() != nil {
		t.Fatal("a backend with a runtime reports itself unusable")
	}
	if backend.RequiresRebuild() {
		t.Fatal("an open backend reports that it requires a rebuild")
	}

	backend.health.invalidate("TC", "test policy")
	if !backend.RequiresRebuild() {
		t.Fatal("an invalidated backend does not report that it requires a rebuild")
	}
	if backend.requireUsableLocked() == nil {
		t.Fatal("an invalidated backend still reports itself usable")
	}

	var absent *TCBackend
	if absent.RequiresRebuild() {
		t.Fatal("a nil backend reports that it requires a rebuild")
	}
}
