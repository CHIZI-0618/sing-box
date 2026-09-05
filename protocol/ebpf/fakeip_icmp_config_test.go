//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeFakeIPICMP(t *testing.T) {
	for _, testCase := range []struct {
		mode    string
		enabled bool
		wantErr bool
	}{
		{"", false, false},
		{"off", false, false},
		{"reply", true, false},
		{"REPLY", false, true},
		{"on", false, true},
	} {
		enabled, err := normalizeFakeIPICMP(testCase.mode)
		if (err != nil) != testCase.wantErr {
			t.Fatalf("normalizeFakeIPICMP(%q) error = %v, wantErr %v", testCase.mode, err, testCase.wantErr)
		}
		if err == nil && enabled != testCase.enabled {
			t.Fatalf("normalizeFakeIPICMP(%q) = %v, want %v", testCase.mode, enabled, testCase.enabled)
		}
	}
}

// TestValidateFakeIPICMP covers every branch of the eBPF-only half of the
// fakeip_icmp=reply requirement: it needs a FakeIP prefix to answer for, and
// it needs to land on a data plane that actually has a TC attachment for it
// to ride — local.data_plane=tc or shared.data_plane=socket_assign. Both
// local.data_plane=cgroup alone and shared.data_plane=packet_rewrite alone
// are refused by name, not folded into one generic error, because each has
// its own reason (no packet visibility at all; a different backend this
// round does not attach to) that a caller fixing the configuration needs to
// see.
func TestValidateFakeIPICMP(t *testing.T) {
	fakeIPv4 := netip.MustParsePrefix("198.18.0.0/15")
	noPrefix := netip.Prefix{}

	for _, testCase := range []struct {
		name            string
		enabled         bool
		fakeIPIPv4      netip.Prefix
		localEnabled    bool
		localDataPlane  string
		sharedEnabled   bool
		sharedDataPlane string
		wantErr         bool
		wantErrContains string
	}{
		{name: "disabled is always fine", enabled: false},
		{
			name: "disabled ignores a missing FakeIP prefix",
			enabled: false, fakeIPIPv4: noPrefix,
		},
		{
			name: "reply without any FakeIP prefix", enabled: true, fakeIPIPv4: noPrefix,
			localEnabled: true, localDataPlane: localDataPlaneTC,
			wantErr: true, wantErrContains: "requires a FakeIP range",
		},
		{
			name: "reply on local TC", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneTC,
			wantErr: false,
		},
		{
			name: "reply on shared socket_assign", enabled: true, fakeIPIPv4: fakeIPv4,
			sharedEnabled: true, sharedDataPlane: sharedDataPlaneSocketAssign,
			wantErr: false,
		},
		{
			name: "reply on local cgroup alone is refused by name", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneCgroup,
			wantErr: true, wantErrContains: "local.data_plane=cgroup",
		},
		{
			name: "reply on shared packet_rewrite alone is refused by name", enabled: true, fakeIPIPv4: fakeIPv4,
			sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite,
			wantErr: true, wantErrContains: "shared.data_plane=packet_rewrite",
		},
		{
			name: "reply on cgroup plus shared socket_assign uses the shared path", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneCgroup,
			sharedEnabled: true, sharedDataPlane: sharedDataPlaneSocketAssign,
			wantErr: false,
		},
		{
			name: "reply on cgroup plus shared packet_rewrite has no attachable path", enabled: true, fakeIPIPv4: fakeIPv4,
			localEnabled: true, localDataPlane: localDataPlaneCgroup,
			sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite,
			wantErr: true,
		},
		{
			name: "reply with nothing enabled at all", enabled: true, fakeIPIPv4: fakeIPv4,
			wantErr: true, wantErrContains: "requires local.data_plane=tc or shared.data_plane=socket_assign",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateFakeIPICMP(
				testCase.enabled, testCase.fakeIPIPv4, netip.Prefix{},
				testCase.localEnabled, testCase.localDataPlane,
				testCase.sharedEnabled, testCase.sharedDataPlane,
			)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("validateFakeIPICMP() error = %v, wantErr %v", err, testCase.wantErr)
			}
			if err != nil && testCase.wantErrContains != "" && !strings.Contains(err.Error(), testCase.wantErrContains) {
				t.Fatalf("validateFakeIPICMP() error = %q, want it to mention %q", err.Error(), testCase.wantErrContains)
			}
		})
	}
}
