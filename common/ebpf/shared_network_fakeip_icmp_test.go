//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"time"
)

// newTestSharedNetworkFakeIPPolicy compiles a CompiledPolicy carrying only
// what PrepareSharedNetwork's fakeip_icmp wiring needs.
func newTestSharedNetworkFakeIPPolicy(t *testing.T, fakeIPv4 string) CompiledPolicy {
	t.Helper()
	config := PolicyConfig{EnableTCP: true}
	if fakeIPv4 != "" {
		config.FakeIPIPv4 = netip.MustParsePrefix(fakeIPv4)
	}
	policy, err := CompilePolicy(config)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return policy
}

func newTestSharedNetworkConfig(policy CompiledPolicy, fakeIPICMPReply bool) SharedNetworkConfig {
	return SharedNetworkConfig{
		ListenerPort:    34567,
		EnableTCP:       true,
		RedirectIPv4:    netip.MustParsePrefix("127.128.0.0/9"),
		Policy:          policy,
		MapCapacity:     DefaultSharedNetworkMapCapacities(),
		UDPTimeout:      5 * time.Minute,
		FakeIPICMPReply: fakeIPICMPReply,
	}
}

// TestPrepareSharedNetworkLoadsFakeIPICMPWhenRequested is item 10's Go-side
// proof that shared.data_plane: packet_rewrite can host the fakeip_icmp
// responder on its own, independent of TCBackend -- the whole point of
// FakeIPICMPBackend existing as a standalone type (fakeip_icmp_backend.go).
func TestPrepareSharedNetworkLoadsFakeIPICMPWhenRequested(t *testing.T) {
	policy := newTestSharedNetworkFakeIPPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedNetwork(nil, newTestSharedNetworkConfig(policy, true))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if !backend.FakeIPICMPEnabled() {
		t.Fatal("FakeIPICMPEnabled() = false after requesting fakeip_icmp=reply")
	}
	if fd := backend.FakeIPICMPSharedReplyProgramFD(TCLinkFramingEthernet); fd < 0 {
		t.Fatal("shared reply program FD is unset")
	}
}

// TestPrepareSharedNetworkWithoutFakeIPICMPLoadsNothingExtra confirms the
// default, feature-off path costs nothing beyond the config check.
func TestPrepareSharedNetworkWithoutFakeIPICMPLoadsNothingExtra(t *testing.T) {
	policy := newTestSharedNetworkFakeIPPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedNetwork(nil, newTestSharedNetworkConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if backend.FakeIPICMPEnabled() {
		t.Fatal("FakeIPICMPEnabled() = true without requesting fakeip_icmp=reply")
	}
	if fd := backend.FakeIPICMPSharedReplyProgramFD(TCLinkFramingEthernet); fd >= 0 {
		t.Fatalf("shared reply program FD = %d, want unset when the feature is off", fd)
	}
}

// TestPrepareSharedNetworkRefusesFakeIPICMPWithoutAPrefix mirrors
// TestPrepareTCRefusesFakeIPICMPWithoutAPrefix: requesting fakeip_icmp=reply
// with no FakeIP prefix at all must fail cleanly, leaking no FDs -- the
// whole backend (not just the fakeip_icmp half of it) is torn down, since
// PrepareSharedNetwork's own contract is to return nil on any error.
func TestPrepareSharedNetworkRefusesFakeIPICMPWithoutAPrefix(t *testing.T) {
	before := openFDCount(t)
	policy := newTestSharedNetworkFakeIPPolicy(t, "")
	backend, err := PrepareSharedNetwork(nil, newTestSharedNetworkConfig(policy, true))
	if err == nil {
		_ = backend.Close()
		t.Fatal("fakeip_icmp=reply with no FakeIP prefix at all was reported as success")
	}
	after := openFDCount(t)
	if after > before {
		t.Fatalf("open file descriptors went from %d to %d; PrepareSharedNetwork did not fully release "+
			"what it loaded before the fakeip_icmp refusal", before, after)
	}
}
