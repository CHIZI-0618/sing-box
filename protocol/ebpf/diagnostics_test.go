//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// TestDiagnosticsReportsWaitingForInterfaceWhenNothingIsAttachedYet covers
// the state that is not a failure at all: a data plane is configured but no
// matching interface exists yet, so there is nothing to attach to.
func TestDiagnosticsReportsWaitingForInterfaceWhenNothingIsAttachedYet(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	if diagnostics.SchemaVersion != 2 || diagnostics.ObservedAt.IsZero() {
		t.Fatalf("diagnostics metadata = version %d at %v, want schema version 2 and timestamp", diagnostics.SchemaVersion, diagnostics.ObservedAt)
	}
	if diagnostics.State != EBPFDiagnosticsStateWaitingForInterface {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateWaitingForInterface)
	}
	if len(diagnostics.Attachments) != 0 {
		t.Fatalf("attachments = %v, want none", diagnostics.Attachments)
	}
}

func TestEBPFDiagnosticsUsesShortRequestDrivenCache(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	first := inbound.EBPFDiagnostics()
	second := inbound.EBPFDiagnostics()
	if !first.ObservedAt.Equal(second.ObservedAt) {
		t.Fatalf("cache miss inside TTL: first=%v second=%v", first.ObservedAt, second.ObservedAt)
	}
	firstRuntime := inbound.EBPFKernelRuntime()
	secondRuntime := inbound.EBPFKernelRuntime()
	if !firstRuntime.ObservedAt.Equal(secondRuntime.ObservedAt) {
		t.Fatalf("kernel runtime cache miss inside TTL: first=%v second=%v", firstRuntime.ObservedAt, secondRuntime.ObservedAt)
	}
}

func TestKernelRuntimeForAPI(t *testing.T) {
	observedAt := time.UnixMilli(1700000000123)
	diagnostics := kernelRuntimeForAPI(observedAt, commonEBPF.RuntimeState{
		Programs: []commonEBPF.RuntimeProgram{{
			ID:       42,
			Name:     "sb_share_ingress",
			MapCount: 2,
		}},
		ProgramsError: errors.New("program enumeration denied"),
		MapOccupancy: commonEBPF.MapOccupancyReport{
			Status: "unknown",
			Maps: []commonEBPF.MapOccupancy{{
				ID: 9, Name: "sb_shared_flows", Type: "LRUHash", MaxEntries: 4096,
				Entries: 3, Supported: true,
			}},
			Error: "map enumeration incomplete",
		},
	})
	if !diagnostics.ObservedAt.Equal(observedAt) || diagnostics.ProgramsError != "program enumeration denied" {
		t.Fatalf("unexpected runtime metadata: %+v", diagnostics)
	}
	if len(diagnostics.Programs) != 1 || diagnostics.Programs[0].ID != 42 || diagnostics.Programs[0].MapCount != 2 {
		t.Fatalf("unexpected programs: %+v", diagnostics.Programs)
	}
	if diagnostics.MapOccupancy.Status != "unknown" || diagnostics.MapOccupancy.Error != "map enumeration incomplete" ||
		len(diagnostics.MapOccupancy.Maps) != 1 || diagnostics.MapOccupancy.Maps[0].Entries != 3 {
		t.Fatalf("unexpected map occupancy: %+v", diagnostics.MapOccupancy)
	}
}

// TestDiagnosticsReportsNormalWithAHealthyAttachment covers the ordinary
// case: local TC configured and actually attached to an interface, nothing
// failing, no rollback anomaly.
func TestDiagnosticsReportsNormalWithAHealthyAttachment(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.tcDataPlane = &testTCRuntime{
		attachments: []commonEBPF.AttachmentInfo{{
			InterfaceName:  "eth0",
			InterfaceIndex: 2,
			Role:           "local",
			Mechanism:      "tcx",
		}},
	}
	diagnostics := inbound.Diagnostics()
	if diagnostics.State != EBPFDiagnosticsStateNormal {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateNormal)
	}
	if len(diagnostics.Attachments) != 1 || diagnostics.Attachments[0].InterfaceName != "eth0" {
		t.Fatalf("attachments = %+v, want one entry for eth0", diagnostics.Attachments)
	}
	if diagnostics.Attachments[0].Mechanism != "tcx" || diagnostics.Attachments[0].Role != "local" {
		t.Fatalf("attachment = %+v, want mechanism=tcx role=local", diagnostics.Attachments[0])
	}
}

// TestDiagnosticsReportsRecoveringWhileAGeneralFailureIsOutstanding proves
// recordTCUpdateOutcome's wiring: a Recoverable outcome from the update loop
// shows up as RecoveryPending and the "recovering" state, without needing a
// real interface at all.
func TestDiagnosticsReportsRecoveringWhileAGeneralFailureIsOutstanding(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryPending {
		t.Fatal("RecoveryPending = false, want true with a Recoverable general outcome")
	}
	if diagnostics.State != EBPFDiagnosticsStateRecovering {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateRecovering)
	}
}

// TestDiagnosticsRecordsRecoveryTimeOnTransitionToSettled proves
// LastRecoveryAt is set exactly when a previously-Recoverable component
// transitions to Settled, not on every Settled round (which would make it
// meaningless -- almost every round is Settled).
func TestDiagnosticsRecordsRecoveryTimeOnTransitionToSettled(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if diagnostics := inbound.Diagnostics(); diagnostics.LastRecoveryAt != nil {
		t.Fatalf("LastRecoveryAt = %v, want nil before any failure ever happened", diagnostics.LastRecoveryAt)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if diagnostics := inbound.Diagnostics(); diagnostics.LastRecoveryAt != nil {
		t.Fatalf("LastRecoveryAt = %v, want nil while still failing", diagnostics.LastRecoveryAt)
	}
	before := time.Now()
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if diagnostics.LastRecoveryAt == nil {
		t.Fatal("LastRecoveryAt = nil, want set after a Recoverable -> Settled transition")
	}
	if diagnostics.LastRecoveryAt.Before(before) {
		t.Fatalf("LastRecoveryAt = %v, want at or after %v", diagnostics.LastRecoveryAt, before)
	}
}

// TestDiagnosticsReportsNeedsAttentionWhenUnrecoverable is an independent
// review's finding: an Unrecoverable component (the backend reported
// itself closed or requiring a rebuild the scheduler cannot perform on its
// own) was not checked anywhere in deriveDiagnosticsState at all --
// RecoveryPending only ever looked for Recoverable, so an Unrecoverable
// shared packet-rewrite backend with its attachment record still present
// (attachmentHasRole is satisfied, so waiting_for_interface never
// triggers either) fell all the way through to State=normal, exactly the
// state an operator would least expect for a backend that has given up.
func TestDiagnosticsReportsNeedsAttentionWhenUnrecoverable(t *testing.T) {
	inbound := &Inbound{sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite, udpTimeout: time.Minute}
	shared := newSharedRewrite(inbound, option.EBPFSharedOptions{})
	shared.setDataPlane(&testSharedKernelRuntime{
		attachments: []commonEBPF.AttachmentInfo{{
			InterfaceName:  "eth0",
			InterfaceIndex: 2,
			Role:           "shared",
			Mechanism:      "tcx",
		}},
	})
	inbound.setSharedRewrite(shared)
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteUnrecoverable,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryUnrecoverable {
		t.Fatal("RecoveryUnrecoverable = false, want true with an Unrecoverable shared-rewrite outcome")
	}
	if diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state = %q, want %q", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
}

func TestDiagnosticsIncludesBypassRuleSetRecovery(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteRecoverable,
	})
	if diagnostics := inbound.Diagnostics(); !diagnostics.RecoveryPending {
		t.Fatal("RecoveryPending = false with a recoverable bypass_rule_set update")
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteUnrecoverable,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryUnrecoverable || diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("unrecoverable bypass_rule_set diagnostics = %+v", diagnostics)
	}
}

// TestDiagnosticsUnrecoverableSurvivesAnUnknownRound ensures an unevaluated
// component cannot erase a previously reported unrecoverable state.
func TestDiagnosticsUnrecoverableSurvivesAnUnknownRound(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteUnrecoverable,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if diagnostics := inbound.Diagnostics(); diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state after the Unrecoverable round = %q, want %q", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
	// A later round that never re-evaluated sharedRewrite this time (its
	// zero value, Unknown) must not be read as "settled".
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	diagnostics := inbound.Diagnostics()
	if !diagnostics.RecoveryUnrecoverable {
		t.Fatal("RecoveryUnrecoverable = false after an Unknown round, want the prior Unrecoverable result preserved")
	}
	if diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state after the Unknown round = %q, want %q (an Unknown round must not erase an unresolved fault)", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
}

// TestDiagnosticsUDPSessionCountIncludesSharedPacketRewriteClients covers a
// packet-rewrite-only inbound with no local UDP client table.
func TestDiagnosticsUDPSessionCountIncludesSharedPacketRewriteClients(t *testing.T) {
	inbound := &Inbound{udpTimeout: time.Minute}
	shared := newSharedRewrite(inbound, option.EBPFSharedOptions{})
	inbound.setSharedRewrite(shared)
	shared.sharedUDPClientTable.loadOrCreate(udpSessionKey{
		Source: netip.MustParseAddrPort("192.0.2.1:12345"),
		Scope:  udpSessionScopeSharedRewrite,
	})

	diagnostics := inbound.Diagnostics()
	if diagnostics.UDPSessionCount != 1 {
		t.Fatalf("UDPSessionCount = %d, want 1 with one live shared packet-rewrite UDP client and no local clients", diagnostics.UDPSessionCount)
	}
}

// TestDiagnosticsReportsNeedsAttentionWhenBypassRuleSetIsInconsistent proves
// the one state that is not expected to self-heal on its own gets reported
// distinctly from an ordinary in-progress recovery.
func TestDiagnosticsReportsNeedsAttentionWhenBypassRuleSetIsInconsistent(t *testing.T) {
	inbound := &Inbound{}
	inbound.bypassRuleSetInconsistent = true
	diagnostics := inbound.Diagnostics()
	if diagnostics.BypassRuleSetConsistent {
		t.Fatal("BypassRuleSetConsistent = true, want false")
	}
	if diagnostics.State != EBPFDiagnosticsStateNeedsAttention {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateNeedsAttention)
	}
}

// TestDiagnosticsLastErrorPicksTheMostRecentAcrossCategories proves the
// cross-category "most recent wins" selection actually compares timestamps
// rather than, say, always preferring one fixed category.
func TestDiagnosticsLastErrorPicksTheMostRecentAcrossCategories(t *testing.T) {
	inbound := &Inbound{}
	inbound.interfaceWarnings.topology.record(time.Now().Add(-time.Minute), "older: topology issue")
	inbound.policyWarnings.record(time.Now(), "newer: policy issue")
	diagnostics := inbound.Diagnostics()
	if !strings.Contains(diagnostics.LastError, "newer: policy issue") {
		t.Fatalf("LastError = %q, want the more recent policy warning", diagnostics.LastError)
	}
}

// TestDiagnosticsWriteJSONRoundTrips proves the JSON writer actually
// produces valid, complete JSON matching the struct's fields -- not just
// that it doesn't panic.
func TestDiagnosticsWriteJSONRoundTrips(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	var buffer bytes.Buffer
	if err := diagnostics.WriteJSON(&buffer); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded EBPFDiagnostics
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON: %v (input: %s)", err, buffer.String())
	}
	if decoded.State != diagnostics.State {
		t.Fatalf("decoded state = %s, want %s", decoded.State, diagnostics.State)
	}
}

// TestDiagnosticsWriteTextIncludesTheKeyFields covers the text-only fields.
func TestDiagnosticsWriteTextIncludesTheKeyFields(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	var buffer bytes.Buffer
	if err := diagnostics.WriteText(&buffer); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	text := buffer.String()
	for _, want := range []string{
		"Tag:", "State:", "Attachments:", "Recovery pending:", "UDP sessions:", "UDP NAT:", "UDP reply sockets:",
		"tc_socket_lookup_failures=", "tc_sk_assign_failures=", "tc_assignment_update_failures=",
		"tc_local_fragment_passes=", "tc_shared_fragment_passes=",
		"shared_ingress_passes=", "shared_egress_passes=", "shared_ingress_fragment_passes=", "shared_egress_fragment_passes=",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text output missing %q; got:\n%s", want, text)
		}
	}
}
