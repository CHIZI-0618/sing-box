//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestUpdateSharedRewriteFlowPressure(t *testing.T) {
	usage := commonEBPF.MapUsage{Capacity: 100}
	active, rounds, entered, exited := updateSharedFlowPressure(false, 0, usage)
	if active || rounds != 0 || entered || exited {
		t.Fatal("empty map unexpectedly entered pressure mode")
	}
	usage.Entries = 70
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if !active || !entered || exited {
		t.Fatal("70% map usage did not enter pressure mode")
	}
	usage.Entries = 50
	for expected := 1; expected < sharedFlowPressureExitRounds; expected++ {
		active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
		if !active || rounds != expected || entered || exited {
			t.Fatalf("unexpected pressure exit state at round %d", expected)
		}
	}
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if active || rounds != 0 || entered || !exited {
		t.Fatal("pressure mode did not exit after stable low usage")
	}
}

func TestSharedRewriteFlowSweepRequired(t *testing.T) {
	if sharedFlowSweepRequired(sharedFlowSweepInterval-time.Second, false, false, false) {
		t.Fatal("normal shared flow sweep ran early")
	}
	if !sharedFlowSweepRequired(sharedFlowSweepInterval, false, false, false) {
		t.Fatal("normal shared flow sweep did not run on schedule")
	}
	if !sharedFlowSweepRequired(time.Second, true, false, false) {
		t.Fatal("map pressure did not request an early sweep")
	}
	if !sharedFlowSweepRequired(time.Second, false, true, false) {
		t.Fatal("token reservation failure did not request an early sweep")
	}
	if !sharedFlowSweepRequired(time.Second, false, false, true) {
		t.Fatal("incremental scan did not request continuation")
	}
}
