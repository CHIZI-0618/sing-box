//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

// newTestFakeIPPolicy compiles a CompiledPolicy carrying only what
// PrepareFakeIPICMP needs: FakeIP prefixes and the protocol toggles
// prepareTC's own validation requires.
func newTestFakeIPPolicy(t *testing.T, fakeIPv4, fakeIPv6 string) CompiledPolicy {
	t.Helper()
	config := PolicyConfig{EnableTCP: true}
	if fakeIPv4 != "" {
		config.FakeIPIPv4 = netip.MustParsePrefix(fakeIPv4)
	}
	if fakeIPv6 != "" {
		config.FakeIPIPv6 = netip.MustParsePrefix(fakeIPv6)
	}
	policy, err := CompilePolicy(config)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return policy
}

// TestPrepareTCLoadsFakeIPICMPWhenRequested drives PrepareTC with
// FakeIPICMPReply set against a real kernel: real maps, real programs, a real
// verifier pass (already proven separately for the object itself; this
// confirms the Go-side loading and control-map population reach the same
// result end to end).
func TestPrepareTCLoadsFakeIPICMPWhenRequested(t *testing.T) {
	policy := newTestFakeIPPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:    12345,
		EnableLocal:     true,
		EnableIPv4:      true,
		EnableTCP:       true,
		Policy:          policy,
		FakeIPICMPReply: true,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if !backend.FakeIPICMPEnabled() {
		t.Fatal("FakeIPICMPEnabled() = false after requesting fakeip_icmp=reply")
	}
	for _, framing := range []TCLinkFraming{TCLinkFramingEthernet, TCLinkFramingRawIP} {
		if fd := backend.FakeIPICMPLocalReplyProgramFD(framing); fd < 0 {
			t.Fatalf("local reply program FD for framing %v is unset", framing)
		}
		if fd := backend.FakeIPICMPSharedReplyProgramFD(framing); fd < 0 {
			t.Fatalf("shared reply program FD for framing %v is unset", framing)
		}
	}
}

// TestPrepareTCRefusesFakeIPICMPWithoutAPrefix is the Go-side mirror of the
// native object's own refusal to run with nothing to match: requesting
// fakeip_icmp=reply with no FakeIP prefix compiled at all must fail, not load
// a control map that can never enable itself.
func TestPrepareTCRefusesFakeIPICMPWithoutAPrefix(t *testing.T) {
	before := openFDCount(t)
	policy := newTestFakeIPPolicy(t, "", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:    12345,
		EnableLocal:     true,
		EnableIPv4:      true,
		EnableTCP:       true,
		Policy:          policy,
		FakeIPICMPReply: true,
	})
	if err == nil {
		_ = backend.Close()
		t.Fatal("fakeip_icmp=reply with no FakeIP prefix at all was reported as success")
	}
	after := openFDCount(t)
	if after > before {
		t.Fatalf("open file descriptors went from %d to %d; the fakeip_icmp maps and "+
			"programs loaded before the refusal were not released", before, after)
	}
}

// TestPrepareTCWithoutFakeIPICMPLoadsNothingExtra confirms the default,
// feature-off path: FakeIPICMPEnabled is false and none of the fakeip_icmp
// program accessors return a usable FD, without touching the object at all.
func TestPrepareTCWithoutFakeIPICMPLoadsNothingExtra(t *testing.T) {
	policy := newTestFakeIPPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 12345,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if backend.FakeIPICMPEnabled() {
		t.Fatal("FakeIPICMPEnabled() = true without requesting fakeip_icmp=reply")
	}
	if fd := backend.FakeIPICMPLocalReplyProgramFD(TCLinkFramingEthernet); fd >= 0 {
		t.Fatalf("local reply program FD = %d, want unset when the feature is off", fd)
	}
}
