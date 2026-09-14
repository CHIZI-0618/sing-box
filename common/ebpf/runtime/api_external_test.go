//go:build with_ebpf && (linux || android)

package runtime_test

import (
	"testing"

	kernelRuntime "github.com/sagernet/sing-box/common/ebpf/runtime"
)

func TestPublicTCConstructorRejectsMissingBackend(t *testing.T) {
	runtime, err := kernelRuntime.NewTCRuntime(kernelRuntime.TCRuntimeConfig{})
	if err == nil {
		t.Fatal("TC constructor accepted a missing backend")
	}
	if runtime != nil {
		t.Fatal("TC constructor returned an owner when no resource was created")
	}
}

func TestPublicUnstartedTCNilBackendIsClosed(t *testing.T) {
	runtime := kernelRuntime.NewUnstartedTCRuntime(nil)
	if !runtime.IsClosed() {
		t.Fatal("nil TC backend produced an open resource owner")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close nil TC owner: %v", err)
	}
}

func TestPublicSharedRuntimeWaitingStateHasLifetime(t *testing.T) {
	runtime := kernelRuntime.NewSharedPacketRewriteRuntime(kernelRuntime.SharedPacketRewriteRuntimeConfig{})
	if runtime.IsClosed() {
		t.Fatal("runtime waiting for its first interface reports itself closed")
	}
	if runtime.IsEnabled() || runtime.Backend() != nil {
		t.Fatal("waiting runtime unexpectedly enabled or created a backend")
	}
	if err := runtime.Reconcile(nil, nil); err != nil {
		t.Fatalf("reconcile empty waiting state: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close waiting runtime: %v", err)
	}
	if !runtime.IsClosed() {
		t.Fatal("shared runtime did not transition to closed")
	}
	if !runtime.BackendClosed() {
		t.Fatal("closed shared runtime reports an open backend state")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("idempotent shared close: %v", err)
	}
	if err := runtime.Reconcile(nil, nil); err == nil {
		t.Fatal("closed shared runtime accepted reconciliation")
	}
}
