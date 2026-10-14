//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

const (
	tcAssignmentMaintenanceInterval = time.Minute
	tcAssignmentMaintenanceContinue = 100 * time.Millisecond
	tcAssignmentPressureMaxIdle     = 15 * time.Second
	tcAssignmentNormalMaxIdle       = 2 * time.Minute
	tcAssignmentMaintenanceBudget   = 1024
	tcAssignmentPressureExitPercent = 50
	tcAssignmentPressureExitRounds  = 3
)

// startTCAssignmentJanitor owns the TC assignment side of the same bounded
// maintenance model used by shared packet-rewrite. It is event-woken for
// observed assignment activity, periodically checks pressure for kernel-only
// updates, and immediately continues a partial fallback traversal.
func (i *Inbound) startTCAssignmentJanitor() {
	i.tcAssignmentJanitorAccess.Lock()
	defer i.tcAssignmentJanitorAccess.Unlock()
	if i.tcAssignmentJanitorCancel != nil || i.tcBackend() == nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.tcAssignmentJanitorCancel = cancel
	i.tcAssignmentJanitorDone = done
	go i.runTCAssignmentJanitor(ctx, done)
}

func (i *Inbound) stopTCAssignmentJanitor() {
	i.tcAssignmentJanitorAccess.Lock()
	if i.tcAssignmentJanitorCancel == nil {
		i.tcAssignmentJanitorAccess.Unlock()
		return
	}
	cancel := i.tcAssignmentJanitorCancel
	done := i.tcAssignmentJanitorDone
	i.tcAssignmentJanitorCancel = nil
	i.tcAssignmentJanitorDone = nil
	i.tcAssignmentJanitorAccess.Unlock()
	cancel()
	<-done
}

func (i *Inbound) requestTCAssignmentMaintenance() {
	if i.tcAssignmentWake == nil {
		return
	}
	select {
	case i.tcAssignmentWake <- struct{}{}:
	default:
	}
}

func (i *Inbound) runTCAssignmentJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(tcAssignmentMaintenanceInterval)
	defer ticker.Stop()
	var continuation <-chan time.Time
	var timer *time.Timer
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-i.tcAssignmentWake:
		case <-ticker.C:
		case <-continuation:
			continuation = nil
		}
		complete, err := i.sweepTCAssignmentMaintenance()
		if err != nil || complete {
			continue
		}
		if !complete {
			if timer == nil {
				timer = time.NewTimer(tcAssignmentMaintenanceContinue)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(tcAssignmentMaintenanceContinue)
			}
			continuation = timer.C
		}
	}
}

// sweepTCAssignmentMaintenance is shared by the standalone TC janitor and the
// shared packet-rewrite maintenance worker. It keeps pressure hysteresis in
// the inbound so both paths expose identical state and cleanup behavior.
func (i *Inbound) sweepTCAssignmentMaintenance() (bool, error) {
	backend := i.tcBackend()
	if backend == nil || backend.IsClosed() {
		return true, nil
	}
	maxIdle := tcAssignmentNormalMaxIdle
	if i.tcAssignmentSweepPressure.Load() {
		maxIdle = tcAssignmentPressureMaxIdle
	}
	result, err := backend.SweepAssignments(maxIdle, tcAssignmentMaintenanceBudget)
	if err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "sweep TC eBPF assignments: ", err)
		return true, err
	}
	i.recordTCAssignmentSweep(result)
	if !result.Complete {
		return false, nil
	}
	active, rounds, entered, exited := updateTCAssignmentPressure(
		i.tcAssignmentSweepPressure.Load(),
		i.tcAssignmentPressureRounds.Load(),
		result.Usage,
	)
	i.tcAssignmentSweepPressure.Store(active)
	i.tcAssignmentPressureRounds.Store(rounds)
	if entered {
		i.logger.Warn("eBPF TC assignment map pressure: state=", result.Usage.Entries, "/", result.Usage.Capacity,
			", max_idle=", tcAssignmentPressureMaxIdle)
	} else if exited {
		i.logger.Info("eBPF TC assignment map pressure cleared: state=", result.Usage.Entries, "/", result.Usage.Capacity)
	}
	return true, nil
}

func updateTCAssignmentPressure(active bool, belowExitRounds uint32, usage commonEBPF.MapUsage) (bool, uint32, bool, bool) {
	if usage.Capacity == 0 {
		return active, 0, false, false
	}
	if !active {
		if uint64(usage.Entries)*100 >= uint64(usage.Capacity)*70 {
			return true, 0, true, false
		}
		return false, 0, false, false
	}
	if uint64(usage.Entries)*100 > uint64(usage.Capacity)*tcAssignmentPressureExitPercent {
		return true, 0, false, false
	}
	belowExitRounds++
	if belowExitRounds < tcAssignmentPressureExitRounds {
		return true, belowExitRounds, false, false
	}
	return false, 0, false, true
}

func (i *Inbound) recordTCAssignmentSweep(result commonEBPF.TCAssignmentSweepResult) {
	i.tcAssignmentSweepScanned.Add(uint64(result.Scanned))
	i.tcAssignmentSweepRemoved.Add(uint64(result.Removed))
	i.tcAssignmentSweepRuns.Add(1)
	i.tcAssignmentSweepComplete.Store(result.Complete)
	i.tcAssignmentSweepLastAt.Store(time.Now().UnixNano())
	if result.Complete {
		i.tcAssignmentSweepPartialAt.Store(0)
		i.tcAssignmentSweepEntries.Store(uint64(result.Usage.Entries))
		i.tcAssignmentSweepCapacity.Store(uint64(result.Usage.Capacity))
	} else {
		i.tcAssignmentSweepPartial.Add(1)
		if i.tcAssignmentSweepPartialAt.Load() == 0 {
			i.tcAssignmentSweepPartialAt.Store(time.Now().UnixNano())
		}
	}
}
