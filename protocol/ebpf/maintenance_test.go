//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestTCAssignmentPressureHysteresis(t *testing.T) {
	usage := commonEBPF.MapUsage{Entries: 70, Capacity: 100}
	active, rounds, entered, exited := updateTCAssignmentPressure(false, 0, usage)
	if !active || rounds != 0 || !entered || exited {
		t.Fatalf("pressure did not enter: active=%v rounds=%d entered=%v exited=%v", active, rounds, entered, exited)
	}
	usage.Entries = 50
	for round := uint32(1); round <= tcAssignmentPressureExitRounds; round++ {
		active, rounds, entered, exited = updateTCAssignmentPressure(active, rounds, usage)
		if round < tcAssignmentPressureExitRounds && (!active || rounds != round || entered || exited) {
			t.Fatalf("pressure exited too early at round %d: active=%v rounds=%d entered=%v exited=%v", round, active, rounds, entered, exited)
		}
	}
	if active || rounds != 0 || entered || !exited {
		t.Fatalf("pressure did not clear: active=%v rounds=%d entered=%v exited=%v", active, rounds, entered, exited)
	}
}

func TestTCAssignmentPartialUsageIsNotPressureEvidence(t *testing.T) {
	active, rounds, entered, exited := updateTCAssignmentPressure(false, 0, commonEBPF.MapUsage{})
	if active || rounds != 0 || entered || exited {
		t.Fatalf("empty/unknown usage changed pressure state: active=%v rounds=%d entered=%v exited=%v", active, rounds, entered, exited)
	}
}
