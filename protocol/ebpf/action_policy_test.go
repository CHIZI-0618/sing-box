//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestCompileProcessUIDPolicySubtractsExcludedRanges(t *testing.T) {
	inbound := &Inbound{
		localPolicy: commonEBPF.LocalPolicy{
			IncludeUIDConfigured: true,
			IncludeUID:           []commonEBPF.UIDRange{{Start: 1000, End: 1999}},
			ExcludeUID:           []commonEBPF.UIDRange{{Start: 1400, End: 1499}},
		},
	}
	decisions, defaultAction := inbound.compileProcessUIDPolicy()
	if defaultAction != commonEBPF.DecisionPass {
		t.Fatalf("default action = %v, want pass", defaultAction)
	}
	want := []commonEBPF.UIDDecision{
		{Start: 1000, End: 1399, Action: commonEBPF.DecisionIntercept},
		{Start: 1500, End: 1999, Action: commonEBPF.DecisionIntercept},
	}
	if len(decisions) != len(want) {
		t.Fatalf("decisions = %+v, want %+v", decisions, want)
	}
	for index := range want {
		if decisions[index] != want[index] {
			t.Fatalf("decisions = %+v, want %+v", decisions, want)
		}
	}
}

func TestCompileProcessUIDPolicyUsesExcludeActionsByDefault(t *testing.T) {
	inbound := &Inbound{localPolicy: commonEBPF.LocalPolicy{
		ExcludeUID: []commonEBPF.UIDRange{{Start: 10000, End: 10010}},
	}}
	decisions, defaultAction := inbound.compileProcessUIDPolicy()
	if defaultAction != commonEBPF.DecisionIntercept {
		t.Fatalf("default action = %v, want intercept", defaultAction)
	}
	if len(decisions) != 1 || decisions[0].Action != commonEBPF.DecisionPass {
		t.Fatalf("decisions = %+v, want one pass decision", decisions)
	}
}

func TestCombineDestinationDecisionsRetainsStaticPasses(t *testing.T) {
	inbound := &Inbound{}
	combined, err := inbound.combineDestinationDecisions(
		[]commonEBPF.CIDRDecision{{
			Prefix: netip.MustParsePrefix("192.168.0.0/16"), Action: commonEBPF.DecisionPass,
		}},
		[]commonEBPF.CIDRDecision{{
			Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: commonEBPF.DecisionPass,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(combined) != 2 {
		t.Fatalf("combined decisions = %+v, want static and dynamic pass entries", combined)
	}
}
