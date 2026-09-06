//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

type tcInterfaceMonitor struct {
	access                   sync.Mutex
	network                  tun.NetworkUpdateMonitor
	networkOwned             bool
	networkCallback          *list.Element[tun.NetworkUpdateCallback]
	defaultInterface         tun.DefaultInterfaceMonitor
	defaultInterfaceOwned    bool
	defaultInterfaceCallback *list.Element[tun.DefaultInterfaceUpdateCallback]
	defaultInterfaceName     string
	cancel                   context.CancelFunc
	updates                  chan struct{}
}

func (i *Inbound) InterfaceUpdated(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	i.setDefaultInterfaceName(i.currentDefaultInterfaceName())
}

func (i *Inbound) startTCInterfaceMonitor() error {
	networkMonitor := i.networkManager.NetworkMonitor()
	networkOwned := false
	if networkMonitor == nil {
		var err error
		networkMonitor, err = tun.NewNetworkUpdateMonitor(i.logger)
		if err != nil {
			return E.Cause(err, "create TC eBPF network monitor")
		}
		networkOwned = true
	}
	defaultInterfaceMonitor := i.networkManager.InterfaceMonitor()
	defaultInterfaceOwned := false
	if defaultInterfaceMonitor == nil {
		var err error
		defaultInterfaceMonitor, err = tun.NewDefaultInterfaceMonitor(networkMonitor, i.logger, tun.DefaultInterfaceMonitorOptions{
			InterfaceFinder: i.networkManager.InterfaceFinder(),
		})
		if err != nil {
			if networkOwned {
				_ = networkMonitor.Close()
			}
			return E.Cause(err, "create TC eBPF default interface monitor")
		}
		defaultInterfaceOwned = true
	}
	monitorContext, cancel := context.WithCancel(i.ctx)
	updates := make(chan struct{}, 1)
	state := &i.interfaceMonitor
	state.access.Lock()
	if state.network != nil {
		state.access.Unlock()
		cancel()
		if defaultInterfaceOwned {
			_ = defaultInterfaceMonitor.Close()
		}
		if networkOwned {
			_ = networkMonitor.Close()
		}
		return nil
	}
	state.network = networkMonitor
	state.networkOwned = networkOwned
	state.defaultInterface = defaultInterfaceMonitor
	state.defaultInterfaceOwned = defaultInterfaceOwned
	state.cancel = cancel
	state.updates = updates
	state.networkCallback = networkMonitor.RegisterCallback(i.notifyTCInterfaceUpdate)
	state.defaultInterfaceCallback = defaultInterfaceMonitor.RegisterCallback(i.defaultInterfaceUpdated)
	state.defaultInterfaceName = interfaceName(defaultInterfaceMonitor.DefaultInterface())
	state.access.Unlock()
	go i.runTCInterfaceUpdates(monitorContext, updates)
	if networkOwned {
		if err := networkMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF network monitor"), i.stopTCInterfaceMonitor())
		}
	}
	if defaultInterfaceOwned {
		if err := defaultInterfaceMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF default interface monitor"), i.stopTCInterfaceMonitor())
		}
	}
	i.notifyTCInterfaceUpdate()
	return nil
}

func (i *Inbound) stopTCInterfaceMonitor() error {
	state := &i.interfaceMonitor
	state.access.Lock()
	networkMonitor := state.network
	networkOwned := state.networkOwned
	networkCallback := state.networkCallback
	defaultInterfaceMonitor := state.defaultInterface
	defaultInterfaceOwned := state.defaultInterfaceOwned
	defaultInterfaceCallback := state.defaultInterfaceCallback
	cancel := state.cancel
	state.network = nil
	state.networkOwned = false
	state.networkCallback = nil
	state.defaultInterface = nil
	state.defaultInterfaceOwned = false
	state.defaultInterfaceCallback = nil
	state.defaultInterfaceName = ""
	state.cancel = nil
	state.updates = nil
	state.access.Unlock()
	if networkMonitor == nil {
		return nil
	}
	if networkCallback != nil {
		networkMonitor.UnregisterCallback(networkCallback)
	}
	if defaultInterfaceMonitor != nil && defaultInterfaceCallback != nil {
		defaultInterfaceMonitor.UnregisterCallback(defaultInterfaceCallback)
	}
	if cancel != nil {
		cancel()
	}
	var closeErr error
	if defaultInterfaceOwned {
		closeErr = defaultInterfaceMonitor.Close()
	}
	if networkOwned {
		closeErr = E.Errors(closeErr, networkMonitor.Close())
	}
	return closeErr
}

func (i *Inbound) defaultInterfaceUpdated(defaultInterface *control.Interface, _ int) {
	i.setDefaultInterfaceName(interfaceName(defaultInterface))
}

func interfaceName(networkInterface *control.Interface) string {
	if networkInterface == nil {
		return ""
	}
	return networkInterface.Name
}

func (i *Inbound) currentDefaultInterfaceName() string {
	defaultInterfaceMonitor := i.networkManager.InterfaceMonitor()
	if defaultInterfaceMonitor == nil {
		return ""
	}
	return interfaceName(defaultInterfaceMonitor.DefaultInterface())
}

func (i *Inbound) setDefaultInterfaceName(interfaceName string) {
	state := &i.interfaceMonitor
	state.access.Lock()
	state.defaultInterfaceName = interfaceName
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if active {
		notifyTCInterfaceUpdate(updates)
	}
}

func (i *Inbound) notifyTCInterfaceUpdate() {
	state := &i.interfaceMonitor
	state.access.Lock()
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if !active {
		return
	}
	notifyTCInterfaceUpdate(updates)
}

func notifyTCInterfaceUpdate(updates chan<- struct{}) {
	select {
	case updates <- struct{}{}:
	default:
	}
}

const (
	tcRetryInitialDelay = 2 * time.Second
	tcRetryMaximumDelay = time.Minute
)

// tcHealthCheckInterval is the low-frequency, unconditional recheck this loop
// also performs, independent of any outstanding recovery: a reconcile pass
// that finds nothing has drifted is cheap, and this is what catches drift no
// event ever fires for (an attachment health check failing on its own
// between network changes is exactly this case). It is a plain, real ticker
// rather than something folded into the retry timer's arm/disarm bookkeeping
// below, so it neither participates in nor disturbs the backoff any
// component is or is not currently in. A var, not a const, so a test can
// substitute a short interval instead of waiting on the real one.
var tcHealthCheckInterval = 10 * time.Minute

// tcSharedRewriteOutcome is what one named component of an interface update
// reported.
//
// A single update can name more than one outcome (see tcUpdateOutcome):
// tcSharedRewriteOutcome itself is not scoped to shared packet-rewrite
// specifically despite the name, which is kept only because runTCInterfaceUpdateLoop's
// existing tests, and shared_rewrite_dataplane.go's own retryOutcome, already
// name it and its four values throughout.
type tcSharedRewriteOutcome int

const (
	// tcSharedRewriteUnknown means the shared packet-rewrite step did not run,
	// because the update returned before reaching it. It says nothing about
	// whether a recovery is outstanding, so a pending retry is left alone rather
	// than cancelled.
	tcSharedRewriteUnknown tcSharedRewriteOutcome = iota
	// tcSharedRewriteSettled means there is nothing to recover: the step
	// succeeded, or there is no shared packet-rewrite data plane to run.
	tcSharedRewriteSettled
	tcSharedRewriteRecoverable
	// tcSharedRewriteUnrecoverable means the backend is closed or has to be
	// rebuilt, so repeating the attach cannot succeed.
	tcSharedRewriteUnrecoverable
)

// tcRetryComponent names one of tcUpdateOutcome's independently-backed-off
// fields, for logging and for indexing runTCInterfaceUpdateLoop's internal
// per-component state.
type tcRetryComponent int

const (
	tcRetryComponentSharedRewrite tcRetryComponent = iota
	tcRetryComponentGeneral
	tcRetryComponentBypassRuleSet
	tcRetryComponentCount
)

func (c tcRetryComponent) String() string {
	switch c {
	case tcRetryComponentSharedRewrite:
		return "shared packet-rewrite"
	case tcRetryComponentGeneral:
		return "TC attachment/infrastructure/host policy"
	case tcRetryComponentBypassRuleSet:
		return "bypass_rule_set"
	default:
		return "unknown"
	}
}

// tcUpdateOutcome is what one full interface-update pass reported, broken out
// per component so runTCInterfaceUpdateLoop can back each one off
// independently: one component settling must not cancel another's pending
// recovery, matching the same requirement shared packet-rewrite's own outcome
// already satisfied before general TC and bypass_rule_set failures were also
// covered by this scheduler.
//
//   - sharedRewrite: the shared packet-rewrite attach step specifically (see
//     tcSharedRewriteOutcome's own history; sharedRewriteDataPlane.retryOutcome
//     is this field's classifier).
//   - general: every other TC step in updateTCInterfaces -- inventory,
//     topology, infrastructure (routing/rules/delivery veth), the attachment
//     reconcile itself, and host address policy. These are combined into one
//     bucket rather than tracked individually: they already run as one
//     sequential pass sharing the same lock and largely the same recovery
//     path (a fresh reconcile), so splitting them further would track more
//     state without changing what actually gets retried or when.
//   - bypassRuleSet: refreshing the compiled bypass_rule_set policy, driven
//     normally by rule-set update callbacks rather than network events, which
//     is exactly the case this scheduler exists to also cover: a transient
//     failure with no later rule-set change to retry it.
type tcUpdateOutcome struct {
	sharedRewrite tcSharedRewriteOutcome
	general       tcSharedRewriteOutcome
	bypassRuleSet tcSharedRewriteOutcome
}

// tcRetryTimer is the slice of *time.Timer this loop needs, reduced to the two
// operations a round performs. A round makes at most one of them: an
// event-driven round that finds the shared step did not run makes none, because
// it must leave the deadline it did not observe exactly as it was. Arming hides
// the stop-and-drain a bare Reset would require, which keeps a signal from a
// previous delay out of the next one. Tests substitute it to drive the backoff
// without waiting on real time.
type tcRetryTimer interface {
	Arm(delay time.Duration)
	Disarm()
	Expired() <-chan time.Time
}

type tcRealRetryTimer struct {
	timer *time.Timer
}

// newTCRetryTimer returns a timer that is not running, so the loop can hold one
// for its whole life and arm it only when a recovery is outstanding.
func newTCRetryTimer() tcRetryTimer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return &tcRealRetryTimer{timer: timer}
}

func (t *tcRealRetryTimer) Arm(delay time.Duration) {
	t.drain()
	t.timer.Reset(delay)
}

func (t *tcRealRetryTimer) Disarm() {
	t.drain()
}

func (t *tcRealRetryTimer) drain() {
	if !t.timer.Stop() {
		select {
		case <-t.timer.C:
		default:
		}
	}
}

func (t *tcRealRetryTimer) Expired() <-chan time.Time { return t.timer.C }

var tcRetryTimerFactory = newTCRetryTimer

func (i *Inbound) runTCInterfaceUpdates(ctx context.Context, updates <-chan struct{}) {
	runTCInterfaceUpdateLoop(ctx, updates, func(ctx context.Context) tcUpdateOutcome {
		outcome := i.updateTCInterfaces(ctx)
		i.recordTCUpdateOutcome(outcome)
		return outcome
	}, i.recordNextRetryDeadline)
}

// tcRetryState is one component's independently-tracked backoff: delay is
// the duration it last waited (0 means nothing pending), and deadline is the
// absolute time that delay was measured from -- computed once, from the same
// "now" snapshot used across a whole round, specifically so a component that
// becomes the single earliest one this round arms the real timer for exactly
// delay, with no wall-clock rounding from re-deriving it through time.Now()
// a second time.
type tcRetryState struct {
	delay    time.Duration
	deadline time.Time
}

// runTCInterfaceUpdateLoop drives interface updates from netlink
// notifications, from a low-frequency unconditional health check
// (tcHealthCheckInterval), and, while any of update's three components has a
// recoverable failure outstanding, from that component's own backoff timer.
//
// Only one physical timer exists; it is armed for whichever component's
// deadline is soonest. A netlink notification or the health check still runs
// an update immediately, but neither resets any component's backoff: this
// data plane generates netlink events of its own while attaching and
// detaching, and an unrelated event on another interface arrives just as
// often, so treating any event as progress would keep restarting the delay
// and turn the backoff into a busy loop. A component's delay resets only
// after a round in which that component reported nothing left to recover.
// onScheduleChange, when non-nil, is called every time the loop's single
// physical timer is armed or disarmed, with the absolute time it is now
// armed for (or the zero time when disarmed) -- runTCInterfaceUpdates uses
// it to keep Diagnostics' "next retry time" in sync with the same schedule
// the timer itself is actually running on, rather than recomputing it
// separately from state this function does not otherwise expose.
func runTCInterfaceUpdateLoop(
	ctx context.Context,
	updates <-chan struct{},
	update func(context.Context) tcUpdateOutcome,
	onScheduleChange func(deadline time.Time),
) {
	retryTimer := tcRetryTimerFactory()
	defer retryTimer.Disarm()
	healthCheck := time.NewTicker(tcHealthCheckInterval)
	defer healthCheck.Stop()
	var (
		retryChannel <-chan time.Time
		states       [tcRetryComponentCount]tcRetryState
	)
	for {
		// The timer's channel is only selected on while some component has a
		// recovery outstanding, so a disarmed timer cannot deliver a signal
		// from an earlier delay.
		triggeredByTimer := false
		select {
		case <-ctx.Done():
			return
		case <-updates:
		case <-healthCheck.C:
		case <-retryChannel:
			triggeredByTimer = true
		}
		// A notification, the health check, and the retry timer can all be
		// ready together and select picks one at random. The three signals
		// are handled differently and neither of the other two is lost:
		// re-arming or disarming below drains a timer fire that was already
		// queued, since it belongs to a deadline this round has just
		// superseded, while a queued notification stays in its channel and
		// drives the next round, and the health check ticker keeps its own
		// schedule independently of anything below.
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		outcome := update(ctx)
		outcomes := [tcRetryComponentCount]tcSharedRewriteOutcome{
			tcRetryComponentSharedRewrite: outcome.sharedRewrite,
			tcRetryComponentGeneral:       outcome.general,
			tcRetryComponentBypassRuleSet: outcome.bypassRuleSet,
		}
		changed := false
		for component, componentOutcome := range outcomes {
			switch componentOutcome {
			case tcSharedRewriteRecoverable:
				// Advance on every failed round, including one an event or the
				// health check triggered, so a stream of those cannot hold this
				// component's delay down.
				states[component].delay = nextTCRetryDelay(states[component].delay)
				states[component].deadline = now.Add(states[component].delay)
				changed = true
			case tcSharedRewriteUnknown:
				// This component's step did not run, so it says nothing about an
				// outstanding recovery for that component specifically. Only
				// re-arm when the timer is what woke this round: some
				// component's deadline has passed, and if it was this one its
				// retry would otherwise be dropped. An event- or health-check-
				// driven round leaves this component's existing deadline alone,
				// or a stream of those returning early would postpone its retry
				// indefinitely.
				if triggeredByTimer && states[component].delay > 0 {
					states[component].deadline = now.Add(states[component].delay)
					changed = true
				}
			default: // settled or unrecoverable
				// sharedRewrite's own settled/unrecoverable handling has
				// always unconditionally touched the timer, proven by tests
				// predating general and bypassRuleSet joining this scheduler,
				// including a first-ever round with nothing previously
				// tracked. general and bypassRuleSet keep the more efficient
				// transition-gated behavior: since a component with nothing
				// to recover is by far the common case for both, an
				// unconditional touch would mean every single round pays for
				// a real timer access, for two components most rounds never
				// have anything to say about.
				if tcRetryComponent(component) == tcRetryComponentSharedRewrite || !states[component].deadline.IsZero() {
					changed = true
				}
				states[component].delay = 0
				states[component].deadline = time.Time{}
			}
		}
		if !changed {
			continue
		}
		earliest := -1
		for component := range states {
			if states[component].deadline.IsZero() {
				continue
			}
			if earliest == -1 || states[component].deadline.Before(states[earliest].deadline) {
				earliest = component
			}
		}
		if earliest == -1 {
			retryTimer.Disarm()
			retryChannel = nil
			if onScheduleChange != nil {
				onScheduleChange(time.Time{})
			}
			continue
		}
		delay := states[earliest].deadline.Sub(now)
		if delay < 0 {
			delay = 0
		}
		retryTimer.Arm(delay)
		retryChannel = retryTimer.Expired()
		if onScheduleChange != nil {
			onScheduleChange(states[earliest].deadline)
		}
	}
}

func nextTCRetryDelay(current time.Duration) time.Duration {
	if current <= 0 {
		return tcRetryInitialDelay
	}
	next := current * 2
	if next > tcRetryMaximumDelay {
		return tcRetryMaximumDelay
	}
	return next
}

// updateTCInterfaces runs one reconciliation pass and reports what each of
// tcUpdateOutcome's three components made of it: sharedRewrite from the
// shared packet-rewrite step alone (unchanged from before this scheduler also
// covered the other two -- a shared packet-rewrite recovery must not be
// cancelled by an unrelated success), general from every other TC step below
// (inventory, topology, infrastructure, the attachment reconcile, host
// policy), and bypassRuleSet from retrying a previously-failed bypass_rule_set
// refresh. general is left at its zero value (tcSharedRewriteUnknown) only
// while genuinely nothing in this pass has run it yet; every path that
// returns after touching it leaves it Recoverable or Settled, since it runs
// unconditionally every round.
func (i *Inbound) updateTCInterfaces(ctx context.Context) (outcome tcUpdateOutcome) {
	if ctx.Err() != nil {
		return
	}
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	outcome.bypassRuleSet = i.retryBypassRuleSetIfNeededLocked()
	if err := i.networkManager.UpdateInterfaces(); err != nil {
		i.interfaceWarnings.inventory.warn(i.logger, "update interfaces for TC eBPF: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	defaultInterface := i.monitoredDefaultInterfaceName()
	localTCEnabled := i.localTCEnabled()
	localInterface, err := availableLocalTCInterface(localTCEnabled, defaultInterface)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logger, "inspect TC eBPF local interface: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	if localTCEnabled && localInterface == "" {
		i.interfaceWarnings.defaultInterface.warn(i.logger, "default interface unavailable; retaining previous local TC attachment")
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	tcSharedInterfaces := sharedInterfaces
	if i.sharedRewriteEnabled() {
		tcSharedInterfaces = nil
	}
	hostAddresses := i.hostAddresses()
	sharedDataPlane := (*sharedRewriteDataPlane)(nil)
	if shared := i.sharedRewriteInstance(); shared != nil {
		sharedDataPlane = shared.dataPlaneInstance()
	}
	if sharedDataPlane != nil {
		previous := sharedDataPlane.attachmentDescriptions()
		if err = sharedDataPlane.reconcile(sharedInterfaces, hostAddresses); err != nil {
			i.counters.sharedReconcileFailures.Add(1)
			i.interfaceWarnings.reconcile.warn(i.logger, "refresh shared packet-rewrite interfaces: ", err)
			outcome.sharedRewrite = sharedDataPlane.retryOutcome()
		} else {
			outcome.sharedRewrite = tcSharedRewriteSettled
			if attachments := sharedDataPlane.attachmentDescriptions(); !slices.Equal(previous, attachments) {
				i.logger.Debug("eBPF shared packet-rewrite attachments updated: attachments=[", strings.Join(attachments, ", "), "]")
			}
		}
	} else {
		outcome.sharedRewrite = tcSharedRewriteSettled
	}
	infrastructureChanged, err := i.repairTCInfrastructure()
	infrastructureHealthy := err == nil
	if err != nil {
		i.interfaceWarnings.infrastructure.warn(i.logger, "repair TC eBPF network state: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	changed, err := i.tcAttachmentStateChanged(localInterface, tcSharedInterfaces)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logger, "inspect TC eBPF interfaces: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	if !changed {
		if err = i.updateTCHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logger, "refresh TC eBPF host addresses: ", err)
			outcome.general = tcSharedRewriteRecoverable
		}
		if err = i.updateCgroupHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logger, "refresh cgroup eBPF host addresses: ", err)
			outcome.general = tcSharedRewriteRecoverable
		}
		if infrastructureChanged && infrastructureHealthy {
			i.logger.Debug("eBPF TC network state restored")
		}
		if outcome.general == tcSharedRewriteUnknown {
			outcome.general = tcSharedRewriteSettled
		}
		return
	}
	previousAttachments := i.tcAttachmentDescriptions()
	i.udpNat.Purge()
	if err = i.udpReplySockets.reset(); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "reset TC eBPF UDP reply sockets: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	if err = i.reconcileTCDataPlane(localInterface, tcSharedInterfaces, hostAddresses); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "refresh TC eBPF interfaces: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	i.warnIfLocalFakeIPICMPIPv6Unroutable(localInterface)
	if err = i.updateCgroupHostAddresses(hostAddresses); err != nil {
		i.interfaceWarnings.hostPolicy.warn(i.logger, "refresh cgroup eBPF host addresses: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	attachments := i.tcAttachmentDescriptions()
	if !slices.Equal(previousAttachments, attachments) {
		i.logger.Debug(
			"eBPF TC attachments updated: attachments=[",
			strings.Join(attachments, ", "),
			"]",
		)
	}
	if outcome.general == tcSharedRewriteUnknown {
		outcome.general = tcSharedRewriteSettled
	}
	return outcome
}

func (i *Inbound) repairTCInfrastructure() (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.repairInfrastructure()
}

func (i *Inbound) monitoredDefaultInterfaceName() string {
	state := &i.interfaceMonitor
	state.access.Lock()
	defer state.access.Unlock()
	return state.defaultInterfaceName
}

func availableLocalTCInterface(enabled bool, interfaceName string) (string, error) {
	if !enabled || interfaceName == "" {
		return "", nil
	}
	_, err := netlink.LinkByName(interfaceName)
	if err != nil && tcLinkNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", E.Cause(err, "find local TC eBPF interface ", interfaceName)
	}
	return interfaceName, nil
}

func activeSharedInterfaces(configured []string, defaultInterface string) []string {
	return slices.DeleteFunc(slices.Clone(configured), func(interfaceName string) bool {
		return interfaceName == defaultInterface
	})
}

func (i *Inbound) tcAttachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.attachmentStateChanged(localInterface, sharedInterfaces)
}

func (i *Inbound) tcAttachmentDescriptions() []string {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.attachmentDescriptions()
}

func (i *Inbound) updateTCHostAddresses(hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.updateHostAddresses(hostAddresses)
}

func (i *Inbound) updateCgroupHostAddresses(hostAddresses []netip.Addr) error {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return nil
	}
	return backend.UpdateHostAddresses(hostAddresses)
}

func (i *Inbound) hostAddresses() []netip.Addr {
	return collectHostAddresses(i.networkManager.InterfaceFinder().Interfaces())
}

func collectHostAddresses(interfaces []control.Interface) []netip.Addr {
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	addresses = slices.Compact(addresses)
	return addresses
}

func (d *tcDataPlane) attachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	d.access.Lock()
	defer d.access.Unlock()
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return false, err
	}
	if tcAttachmentTopologyChanged(d.attachments, desired) {
		return true, nil
	}
	for _, attachment := range d.attachments {
		if localInterface == "" && attachment.role.local {
			if _, err = netlink.LinkByName(attachment.interfaceName); tcLinkNotFound(err) {
				continue
			}
			if err != nil {
				return false, err
			}
			// During a mobile-network handoff the default-interface monitor can
			// briefly report no interface while the old link and its TC filters
			// are still usable. Avoid treating a transient netlink observation as
			// a filter loss and repeatedly tearing down the active attachment.
			continue
		}
		attached, err := attachment.filtersAttached(d.priority, d.backend)
		if err != nil {
			return false, err
		}
		if !attached {
			return true, nil
		}
	}
	return false, nil
}

type tcAttachmentState struct {
	index   int
	framing commonEBPF.TCLinkFraming
	role    tcInterfaceRole
}

func desiredTCAttachmentState(
	localInterface string,
	sharedInterfaces []string,
	linkByName func(string) (netlink.Link, error),
) (map[string]tcAttachmentState, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	interfaces := make(map[string]tcAttachmentState, len(roles))
	for interfaceName, role := range roles {
		link, err := linkByName(interfaceName)
		if err != nil && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "find TC eBPF interface ", interfaceName)
		}
		if link == nil || link.Attrs() == nil {
			return nil, E.New("invalid TC eBPF interface ", interfaceName)
		}
		framing, err := tcLinkFraming(link)
		if err != nil {
			return nil, err
		}
		interfaces[interfaceName] = tcAttachmentState{
			index:   link.Attrs().Index,
			framing: framing,
			role:    role,
		}
	}
	return interfaces, nil
}

func tcAttachmentTopologyChanged(attachments []*tcInterfaceAttachment, desired map[string]tcAttachmentState) bool {
	if len(attachments) != len(desired) {
		return true
	}
	for _, attachment := range attachments {
		state, loaded := desired[attachment.interfaceName]
		if !loaded || state.index != attachment.interfaceIndex ||
			state.framing != attachment.framing || state.role != attachment.role {
			return true
		}
	}
	return false
}
