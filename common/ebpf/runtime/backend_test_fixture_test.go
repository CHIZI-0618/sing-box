//go:build with_ebpf && (linux || android)

package runtime

import (
	"testing"

	core "github.com/sagernet/sing-box/common/ebpf"
)

func newLoopbackTestTCBackend(t *testing.T) *core.TCBackend {
	t.Helper()
	policy, err := core.CompilePolicy(core.PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := core.PrepareTC(core.TCConfig{
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
