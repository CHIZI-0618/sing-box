//go:build with_ebpf && (linux || android)

package ebpf

import (
	"container/heap"
	"context"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

const (
	cgroupRecoveryMaxIdle          = 30 * time.Second
	cgroupRecoverySweepBudget      = 1024
	cgroupRecoveryQueueSize        = 1024
	cgroupRecoveryContinuation     = 100 * time.Millisecond
	cgroupRecoveryFallbackInterval = 10 * time.Second
	// Ring-buffer notifications are an acceleration path, not the ownership
	// source of truth. The watchdog reads the kernel loss counter; it schedules
	// a sweep only after observed loss. A reader failure explicitly switches to
	// the periodic compatibility fallback.
	cgroupRecoveryWatchdogInterval = 10 * time.Second
)

type cgroupRecoveryDeadline struct {
	event    commonEBPF.UDPReleaseEvent
	deadline time.Time
}

type cgroupRecoveryDeadlineHeap []cgroupRecoveryDeadline

func (h cgroupRecoveryDeadlineHeap) Len() int { return len(h) }
func (h cgroupRecoveryDeadlineHeap) Less(left, right int) bool {
	return h[left].deadline.Before(h[right].deadline)
}
func (h cgroupRecoveryDeadlineHeap) Swap(left, right int) { h[left], h[right] = h[right], h[left] }
func (h *cgroupRecoveryDeadlineHeap) Push(value any) {
	*h = append(*h, value.(cgroupRecoveryDeadline))
}
func (h *cgroupRecoveryDeadlineHeap) Pop() any {
	items := *h
	last := len(items) - 1
	entry := items[last]
	items[last] = cgroupRecoveryDeadline{}
	*h = items[:last]
	return entry
}

// startCgroupRecoveryScheduler uses release events and a deadline heap on the
// normal path. Kernels without release notifications retain a bounded,
// low-frequency sweep as the compatibility fallback.
func (i *Inbound) startCgroupRecoveryScheduler(backend *commonEBPF.CgroupBackend) {
	if backend == nil || i.udpTimeout <= 0 {
		return
	}
	i.cgroupRecoveryAccess.Lock()
	defer i.cgroupRecoveryAccess.Unlock()
	if i.cgroupRecoveryCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.cgroupRecoveryCancel = cancel
	i.cgroupRecoveryDone = done
	if backend.UDPUserspaceCleanupMode() == "ringbuf" {
		i.cgroupRecoveryEvents = make(chan commonEBPF.UDPReleaseEvent, cgroupRecoveryQueueSize)
		i.cgroupRecoverySweepWake = make(chan struct{}, 1)
		i.cgroupRecoveryReaderError = make(chan struct{}, 1)
	}
	go i.runCgroupRecoveryScheduler(ctx, backend, done)
}

func (i *Inbound) stopCgroupRecoveryScheduler() {
	i.cgroupRecoveryAccess.Lock()
	if i.cgroupRecoveryCancel == nil {
		i.cgroupRecoveryAccess.Unlock()
		return
	}
	cancel := i.cgroupRecoveryCancel
	done := i.cgroupRecoveryDone
	i.cgroupRecoveryCancel = nil
	i.cgroupRecoveryDone = nil
	i.cgroupRecoveryAccess.Unlock()
	cancel()
	<-done
	i.cgroupRecoveryAccess.Lock()
	i.cgroupRecoveryEvents = nil
	i.cgroupRecoverySweepWake = nil
	i.cgroupRecoveryReaderError = nil
	i.cgroupRecoveryAccess.Unlock()
}

func (i *Inbound) enqueueCgroupRecoveryEvent(event commonEBPF.UDPReleaseEvent) {
	i.cgroupRecoveryAccess.Lock()
	queue := i.cgroupRecoveryEvents
	if queue == nil {
		i.cgroupRecoveryAccess.Unlock()
		return
	}
	select {
	case queue <- event:
		i.cgroupRecoveryAccess.Unlock()
		return
	default:
	}
	i.cgroupRecoveryAccess.Unlock()
	i.cgroupRecoveryQueueOverflows.Add(1)
	i.cgroupRecoveryQueueOverflowAt.Store(time.Now().UnixNano())
	// A full queue means the event stream is incomplete. Coalesce recovery onto
	// the scheduler instead of scanning synchronously in the ring-buffer reader:
	// blocking that reader would amplify the same overflow we are recovering.
	i.requestCgroupRecoverySweep()
}

func (i *Inbound) requestCgroupRecoverySweep() {
	i.cgroupRecoveryAccess.Lock()
	wake := i.cgroupRecoverySweepWake
	i.cgroupRecoveryAccess.Unlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (i *Inbound) signalCgroupRecoveryReaderError() {
	i.cgroupRecoveryAccess.Lock()
	readerError := i.cgroupRecoveryReaderError
	i.cgroupRecoveryAccess.Unlock()
	if readerError == nil {
		return
	}
	select {
	case readerError <- struct{}{}:
	default:
	}
}

func (i *Inbound) runCgroupRecoveryScheduler(ctx context.Context, backend *commonEBPF.CgroupBackend, done chan<- struct{}) {
	defer close(done)
	i.cgroupRecoveryAccess.Lock()
	events := i.cgroupRecoveryEvents
	sweepWake := i.cgroupRecoverySweepWake
	readerError := i.cgroupRecoveryReaderError
	i.cgroupRecoveryAccess.Unlock()
	if events == nil {
		i.runCgroupRecoveryFallback(ctx, backend)
		return
	}
	deadlines := make(cgroupRecoveryDeadlineHeap, 0, cgroupRecoveryQueueSize)
	heap.Init(&deadlines)
	timer := time.NewTimer(time.Hour)
	stopCgroupRecoveryTimer(timer)
	defer timer.Stop()
	watchdog := time.NewTicker(cgroupRecoveryWatchdogInterval)
	defer watchdog.Stop()
	var fallbackTicker *time.Ticker
	var fallbackC <-chan time.Time
	defer func() {
		if fallbackTicker != nil {
			fallbackTicker.Stop()
		}
	}()
	var timerC <-chan time.Time
	continuation := time.NewTimer(time.Hour)
	stopCgroupRecoveryTimer(continuation)
	defer continuation.Stop()
	var continuationC <-chan time.Time
	lossFollowup := time.NewTimer(time.Hour)
	stopCgroupRecoveryTimer(lossFollowup)
	defer lossFollowup.Stop()
	var lossFollowupC <-chan time.Time
	scheduleLossFollowup := func() {
		stopCgroupRecoveryTimer(lossFollowup)
		lossFollowup.Reset(cgroupRecoveryMaxIdle)
		lossFollowupC = lossFollowup.C
	}
	resetContinuation := func(delay time.Duration) {
		stopCgroupRecoveryTimer(continuation)
		continuation.Reset(delay)
		continuationC = continuation.C
	}
	clearContinuation := func() {
		stopCgroupRecoveryTimer(continuation)
		continuationC = nil
	}
	runSweep := func(reason string) {
		result, err := backend.SweepUDPRecovery(cgroupRecoveryMaxIdle, cgroupRecoverySweepBudget)
		if err != nil {
			if !backend.IsClosed() {
				i.logger.Debug("sweep cgroup eBPF UDP recovery after ", reason, ": ", err)
				// A notification was already lost, so a transient map error
				// cannot return us to the healthy event-only state. Retry with
				// bounded backoff until one complete scan restores confidence.
				resetContinuation(cgroupRecoveryFallbackInterval)
			} else {
				clearContinuation()
			}
			return
		}
		if !result.Complete {
			resetContinuation(cgroupRecoveryContinuation)
		} else {
			clearContinuation()
		}
	}
	lastKernelDrops, _ := backend.UDPReleaseNotificationDrops()
	resetTimer := func() {
		if len(deadlines) == 0 {
			timerC = nil
			return
		}
		stopCgroupRecoveryTimer(timer)
		delay := time.Until(deadlines[0].deadline)
		if delay < 0 {
			delay = 0
		}
		timer.Reset(delay)
		timerC = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			heap.Push(&deadlines, cgroupRecoveryDeadline{event: event, deadline: time.Now().Add(cgroupRecoveryMaxIdle)})
			resetTimer()
		case <-sweepWake:
			scheduleLossFollowup()
			runSweep("userspace release queue overflow")
		case <-continuationC:
			continuationC = nil
			runSweep("partial scan continuation")
		case <-lossFollowupC:
			lossFollowupC = nil
			runSweep("release notification loss deadline")
		case <-readerError:
			if fallbackTicker == nil {
				fallbackTicker = time.NewTicker(cgroupRecoveryFallbackInterval)
				fallbackC = fallbackTicker.C
			}
			runSweep("release event reader failure")
		case <-fallbackC:
			runSweep("release event reader fallback")
		case <-timerC:
			now := time.Now()
			for len(deadlines) > 0 && !deadlines[0].deadline.After(now) {
				entry := heap.Pop(&deadlines).(cgroupRecoveryDeadline)
				_, err := backend.DeleteUDPRecovery(entry.event.Listener, entry.event.SocketCookie, entry.event.NetworkGeneration, entry.event.ReleasedAtNS)
				if err != nil && !backend.IsClosed() {
					i.logger.Debug("delete expired cgroup eBPF UDP recovery entry: ", err)
					resetContinuation(cgroupRecoveryContinuation)
				}
			}
			resetTimer()
		case <-watchdog.C:
			// A lost kernel event cannot wake userspace, but its per-CPU drop
			// counter can. Healthy ring-buffer operation performs no map scan.
			drops, err := backend.UDPReleaseNotificationDrops()
			if err != nil {
				if !backend.IsClosed() {
					i.logger.Debug("read cgroup eBPF UDP release drop counter: ", err)
				}
				continue
			}
			if drops != lastKernelDrops {
				lastKernelDrops = drops
				scheduleLossFollowup()
				runSweep("kernel release notification loss")
			}
		}
	}
}

func (i *Inbound) runCgroupRecoveryFallback(ctx context.Context, backend *commonEBPF.CgroupBackend) {
	timer := time.NewTimer(cgroupRecoveryFallbackInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		result, err := backend.SweepUDPRecovery(cgroupRecoveryMaxIdle, cgroupRecoverySweepBudget)
		if err != nil && !backend.IsClosed() {
			i.logger.Debug("sweep stale cgroup eBPF UDP recovery entries: ", err)
		}
		delay := cgroupRecoveryFallbackInterval
		if err == nil && !result.Complete {
			delay = cgroupRecoveryContinuation
		}
		timer.Reset(delay)
	}
}

func stopCgroupRecoveryTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
