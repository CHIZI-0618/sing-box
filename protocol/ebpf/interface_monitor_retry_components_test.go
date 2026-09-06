//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"
)

// componentRetryLoopHarness is retryLoopHarness's sibling for tests that
// need independent control over all three tcUpdateOutcome components, not
// just sharedRewrite. It shares the same fake-timer substitution and the
// same round-synchronization contract (one timer action per round).
type componentRetryLoopHarness struct {
	updates  chan struct{}
	timer    *testRetryTimer
	cancel   context.CancelFunc
	finished chan struct{}
	access   sync.Mutex
	outcome  tcUpdateOutcome
	ran      chan struct{}
}

func newComponentRetryLoopHarness(t *testing.T) *componentRetryLoopHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	timer := &testRetryTimer{
		expired: make(chan time.Time, 1),
		actions: make(chan testRetryTimerAction, 64),
	}
	previousFactory := tcRetryTimerFactory
	tcRetryTimerFactory = func() tcRetryTimer { return timer }
	t.Cleanup(func() { tcRetryTimerFactory = previousFactory })

	// A health check this short would otherwise fire spuriously mid-test;
	// tests that want to exercise it set it back down explicitly.
	previousInterval := tcHealthCheckInterval
	tcHealthCheckInterval = time.Hour
	t.Cleanup(func() { tcHealthCheckInterval = previousInterval })

	harness := &componentRetryLoopHarness{
		updates:  make(chan struct{}, 1),
		timer:    timer,
		cancel:   cancel,
		finished: make(chan struct{}),
		ran:      make(chan struct{}, 64),
		outcome: tcUpdateOutcome{
			sharedRewrite: tcSharedRewriteSettled,
			general:       tcSharedRewriteSettled,
			bypassRuleSet: tcSharedRewriteSettled,
		},
	}
	go func() {
		defer close(harness.finished)
		runTCInterfaceUpdateLoop(ctx, harness.updates, func(context.Context) tcUpdateOutcome {
			harness.access.Lock()
			outcome := harness.outcome
			harness.access.Unlock()
			harness.ran <- struct{}{}
			return outcome
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-harness.finished:
		case <-time.After(2 * time.Second):
			t.Error("update loop did not exit after cancellation")
		}
	})
	return harness
}

func (h *componentRetryLoopHarness) setOutcome(outcome tcUpdateOutcome) {
	h.access.Lock()
	h.outcome = outcome
	h.access.Unlock()
}

func (h *componentRetryLoopHarness) round(t *testing.T, trigger func(), outcome tcUpdateOutcome) testRetryTimerAction {
	t.Helper()
	h.setOutcome(outcome)
	trigger()
	select {
	case <-h.ran:
	case <-time.After(2 * time.Second):
		t.Fatal("update did not run")
	}
	select {
	case action := <-h.timer.actions:
		return action
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not arm or disarm after the update")
	}
	return testRetryTimerAction{}
}

func (h *componentRetryLoopHarness) notify() { h.updates <- struct{}{} }

func (h *componentRetryLoopHarness) fire(t *testing.T) func() {
	return func() { h.timer.fire(t) }
}

func allSettled() tcUpdateOutcome {
	return tcUpdateOutcome{sharedRewrite: tcSharedRewriteSettled, general: tcSharedRewriteSettled, bypassRuleSet: tcSharedRewriteSettled}
}

// TestRetryLoopGeneralComponentBacksOffIndependently proves the general
// bucket (TC attachment/infrastructure/host policy) gets the same real
// exponential backoff sharedRewrite already had, and settles on its own.
func TestRetryLoopGeneralComponentBacksOffIndependently(t *testing.T) {
	harness := newComponentRetryLoopHarness(t)

	failing := allSettled()
	failing.general = tcSharedRewriteRecoverable
	action := harness.round(t, harness.notify, failing)
	if !action.armed || action.delay != tcRetryInitialDelay {
		t.Fatalf("action = %+v, want armed at %s for the general component", action, tcRetryInitialDelay)
	}

	action = harness.round(t, harness.fire(t), failing)
	if !action.armed || action.delay != 2*tcRetryInitialDelay {
		t.Fatalf("action = %+v, want the general component's backoff to advance", action)
	}

	action = harness.round(t, harness.fire(t), allSettled())
	if action.armed {
		t.Fatalf("action = %+v, want disarmed once the general component settled", action)
	}
}

// TestRetryLoopBypassRuleSetComponentBacksOffIndependently is the same proof
// for the bypass_rule_set component specifically, since it is normally
// driven by rule-set update callbacks rather than network events -- the
// scheduler is what gives it a retry path at all when nothing else changes.
func TestRetryLoopBypassRuleSetComponentBacksOffIndependently(t *testing.T) {
	harness := newComponentRetryLoopHarness(t)

	failing := allSettled()
	failing.bypassRuleSet = tcSharedRewriteRecoverable
	action := harness.round(t, harness.notify, failing)
	if !action.armed || action.delay != tcRetryInitialDelay {
		t.Fatalf("action = %+v, want armed at %s for the bypass_rule_set component", action, tcRetryInitialDelay)
	}

	action = harness.round(t, harness.fire(t), allSettled())
	if action.armed {
		t.Fatalf("action = %+v, want disarmed once bypass_rule_set settled", action)
	}
}

// TestRetryLoopComponentsAreIndependent is the core requirement item 5 names
// explicitly: one component succeeding must not clear another's pending
// failure. sharedRewrite fails, then settles while general is still failing;
// the scheduler must still have a retry outstanding for general afterward,
// and general's own backoff must not have been disturbed by sharedRewrite's
// unrelated recovery.
func TestRetryLoopComponentsAreIndependent(t *testing.T) {
	harness := newComponentRetryLoopHarness(t)

	both := allSettled()
	both.sharedRewrite = tcSharedRewriteRecoverable
	both.general = tcSharedRewriteRecoverable
	action := harness.round(t, harness.notify, both)
	if !action.armed || action.delay != tcRetryInitialDelay {
		t.Fatalf("action = %+v, want both components armed at %s", action, tcRetryInitialDelay)
	}

	action = harness.round(t, harness.fire(t), both)
	if !action.armed || action.delay != 2*tcRetryInitialDelay {
		t.Fatalf("action = %+v, want both components advance to %s", action, 2*tcRetryInitialDelay)
	}

	// sharedRewrite recovers; general keeps failing. The earliest outstanding
	// deadline is still general's own, at its own (unreset) backoff.
	onlyGeneralFailing := allSettled()
	onlyGeneralFailing.general = tcSharedRewriteRecoverable
	action = harness.round(t, harness.fire(t), onlyGeneralFailing)
	if !action.armed || action.delay != 4*tcRetryInitialDelay {
		t.Fatalf(
			"action = %+v, want general's backoff to keep advancing to %s -- "+
				"sharedRewrite settling must not have reset or cleared it",
			action, 4*tcRetryInitialDelay,
		)
	}

	// A later sharedRewrite-only failure must start its own backoff over,
	// proving its state was actually cleared when it settled rather than
	// merely being masked by general's still-outstanding one.
	onlySharedFailing := allSettled()
	onlySharedFailing.sharedRewrite = tcSharedRewriteRecoverable
	action = harness.round(t, harness.fire(t), onlySharedFailing)
	// general is disarmed by this round (it reported Settled); sharedRewrite
	// arms fresh at the initial delay, which is earlier than nothing, so the
	// timer now reflects sharedRewrite's own restarted backoff.
	if !action.armed || action.delay != tcRetryInitialDelay {
		t.Fatalf("action = %+v, want sharedRewrite's backoff to have restarted at %s", action, tcRetryInitialDelay)
	}
}

// TestRetryLoopHealthCheckRunsWithNothingOutstanding proves the periodic,
// unconditional health check: with every component settled and no retry
// timer armed at all, a tick on the health-check ticker still drives an
// update pass -- the scenario a purely event- and retry-driven scheduler
// would never reach on its own, which is exactly the drift-with-no-event
// case (an attachment health check failing between network changes) this
// exists to catch.
func TestRetryLoopHealthCheckRunsWithNothingOutstanding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	timer := &testRetryTimer{
		expired: make(chan time.Time, 1),
		actions: make(chan testRetryTimerAction, 64),
	}
	previousFactory := tcRetryTimerFactory
	tcRetryTimerFactory = func() tcRetryTimer { return timer }
	t.Cleanup(func() { tcRetryTimerFactory = previousFactory })
	previousInterval := tcHealthCheckInterval
	tcHealthCheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { tcHealthCheckInterval = previousInterval })

	ran := make(chan struct{}, 64)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runTCInterfaceUpdateLoop(ctx, nil, func(context.Context) tcUpdateOutcome {
			ran <- struct{}{}
			return allSettled()
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("update loop did not exit after cancellation")
		}
	})

	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the health check never drove an update with nothing outstanding and no netlink events")
	}
	// A second tick proves it as a real recurring check, not a one-shot
	// artifact of loop startup.
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("the health check did not recur")
	}
}
