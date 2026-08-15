//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"
)

const (
	localTCPRedirectMaxAge        = 10 * time.Minute
	localTCPRedirectSweepInterval = time.Minute
)

func (i *Inbound) startTCPRedirectJanitor() {
	if i.tcpJanitorStop != nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.tcpJanitorStop = cancel
	i.tcpJanitorDone = done
	go i.runTCPRedirectJanitor(ctx, done)
}

func (i *Inbound) stopTCPRedirectJanitor() {
	if i.tcpJanitorStop == nil {
		return
	}
	i.tcpJanitorStop()
	<-i.tcpJanitorDone
	i.tcpJanitorStop = nil
	i.tcpJanitorDone = nil
}

func (i *Inbound) runTCPRedirectJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(localTCPRedirectSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		backend := i.cgroupBackendInstance()
		if backend == nil {
			return
		}
		result, err := backend.SweepStaleTCPRedirects(localTCPRedirectMaxAge)
		if err != nil {
			i.tcpJanitorWarn.warn(i.logger, "sweep stale local TCP redirects: ", err)
			continue
		}
		if result.Removed > 0 {
			i.logger.Info(
				"eBPF local TCP redirect cleanup: removed=", result.Removed,
				", redirect_state=", result.Usage.Entries, "/", result.Usage.Capacity,
			)
		}
	}
}
