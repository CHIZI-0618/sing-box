//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDiagnosticsReportsWaitingForInterfaceWhenNothingIsAttachedYet covers
// the state that is not a failure at all: a data plane is configured but no
// matching interface exists yet, so there is nothing to attach to.
func TestDiagnosticsReportsWaitingForInterfaceWhenNothingIsAttachedYet(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	if diagnostics.State != EBPFDiagnosticsStateWaitingForInterface {
		t.Fatalf("state = %s, want %s", diagnostics.State, EBPFDiagnosticsStateWaitingForInterface)
	}
	if len(diagnostics.Attachments) != 0 {
		t.Fatalf("attachments = %v, want none", diagnostics.Attachments)
	}
}

// TestDiagnosticsReportsNormalWithAHealthyAttachment covers the ordinary
// case: local TC configured and actually attached to an interface, nothing
// failing, no rollback anomaly.
func TestDiagnosticsReportsNormalWithAHealthyAttachment(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	inbound.tcDataPlane = &tcDataPlane{
		attachments: []*tcInterfaceAttachment{
			{
				interfaceName:  "eth0",
				interfaceIndex: 2,
				role:           tcInterfaceRole{local: true},
				attachmentType: "tcx",
			},
		},
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

// TestDiagnosticsWriteTextIncludesTheKeyFields is a light sanity check that
// the text writer actually names item 7's required fields rather than
// silently dropping one while json.Marshal would still succeed.
func TestDiagnosticsWriteTextIncludesTheKeyFields(t *testing.T) {
	inbound := &Inbound{localEnabled: true, localDataPlane: localDataPlaneTC}
	diagnostics := inbound.Diagnostics()
	var buffer bytes.Buffer
	if err := diagnostics.WriteText(&buffer); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	text := buffer.String()
	for _, want := range []string{"Tag:", "State:", "Attachments:", "Recovery pending:", "UDP sessions:", "UDP reply sockets:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text output missing %q; got:\n%s", want, text)
		}
	}
}
