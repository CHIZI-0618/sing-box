//go:build with_ebpf && (linux || android)

package ebpf

import (
	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) Close() error {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	return i.closeResources()
}

func (i *Inbound) cleanupStartFailure() error {
	return i.closeResources()
}

func (i *Inbound) closeResources() error {
	i.stopTCAssignmentJanitor()
	monitorErr := i.stopTCInterfaceMonitor()
	i.stopBypassRuleSets()
	sharedRewriteErr := error(nil)
	if shared := i.takeSharedRewrite(); shared != nil {
		sharedRewriteErr = shared.Close()
		if !shared.IsClosed() {
			i.setSharedRewrite(shared)
			if sharedRewriteErr == nil {
				sharedRewriteErr = E.New("shared packet-rewrite runtime remained open after close")
			}
		}
	}
	dataPlane := i.takeTCDataPlane()
	disableErr := error(nil)
	if dataPlane != nil {
		disableErr = dataPlane.Disable()
	}
	cgroupBackend := i.takeCgroupBackend()
	cgroupErr := error(nil)
	if cgroupBackend != nil {
		i.stopCgroupRecoveryScheduler()
		cgroupErr = cgroupBackend.Close()
		i.cgroupReleaseWait.Wait()
		// Close keeps the runtime when a program could not be detached, because a
		// legacy cgroup attachment is owned by the cgroup rather than by the
		// program handle: dropping the handles would leave that program attached
		// with nothing able to detach it. Take the backend back so a later close
		// can retry the slots that failed.
		if !cgroupBackend.IsClosed() {
			i.setCgroupBackend(cgroupBackend)
			if cgroupErr == nil {
				cgroupErr = E.New("cgroup eBPF backend remained open after close")
			}
		}
	}
	listenerErr := i.closeListeners()
	udpNATErr := i.udpNat.Close()
	i.udpReplySockets.stopSweeper()
	udpReplySocketErr := i.udpReplySockets.close()
	dataPlaneErr := i.closeTakenTCDataPlane(dataPlane)
	// Failed detaches retain their owner and dependencies for the next Close.
	// In particular, removing redirect routes or self-bypass while a hook is
	// still attached can redirect traffic into a dead path or capture ourselves.
	if i.tcBackend() != nil || i.cgroupBackendInstance() != nil || i.sharedRewriteInstance() != nil {
		return E.Errors(monitorErr, sharedRewriteErr, disableErr, listenerErr, udpNATErr, udpReplySocketErr, dataPlaneErr, cgroupErr)
	}
	namespaceErr := error(nil)
	if i.tcBackend() == nil {
		i.tcNamespaceAccess.Lock()
		if i.tcNamespace != nil {
			namespaceErr = i.tcNamespace.Close()
			i.tcNamespace = nil
		}
		i.tcNamespaceAccess.Unlock()
	}
	routeErr := i.removeLocalRoutes()
	selfBypassErr := error(nil)
	if i.selfBypass != nil {
		if clearer, loaded := i.networkManager.(interface {
			ClearEBPFSelfBypass(*commonEBPF.SelfBypass)
		}); loaded {
			clearer.ClearEBPFSelfBypass(i.selfBypass)
		}
		selfBypassErr = i.selfBypass.Close()
		if i.selfBypass.IsClosed() {
			i.selfBypass = nil
		} else if selfBypassErr == nil {
			selfBypassErr = E.New("eBPF self-bypass remained open after close")
		}
	}
	processTrackerErr := error(nil)
	if i.processTracker != nil {
		i.processTracker, processTrackerErr = closeProcessTrackerOwner(i.processTracker)
	}
	processTrackerRollbackErr := error(nil)
	if i.processTrackerRollback != nil {
		i.processTrackerRollback, processTrackerRollbackErr = closeProcessTrackerOwner(i.processTrackerRollback)
	}
	return E.Errors(monitorErr, sharedRewriteErr, disableErr, listenerErr, udpNATErr, udpReplySocketErr, dataPlaneErr, namespaceErr, cgroupErr, routeErr, processTrackerErr, processTrackerRollbackErr, selfBypassErr)
}

func closeProcessTrackerOwner(tracker processTrackerOwner) (processTrackerOwner, error) {
	if tracker == nil {
		return nil, nil
	}
	closeErr := tracker.Close()
	if tracker.IsClosed() {
		return nil, closeErr
	}
	if closeErr == nil {
		closeErr = E.New("eBPF process tracker remained open after close")
	}
	return tracker, closeErr
}
