//go:build with_ebpf && (linux || android)

package ebpf

import (
	"slices"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

// retainedInbounds holds inbounds whose Close kept kernel resources after a
// failed detach or removal. The adapter scope runs each cleanup only once, so
// a later box, such as after a reload or service restart, retries them before
// attaching new resources that would conflict with the stale ones.
//
// Only the next eBPF inbound retries them. Without one, as when the service
// stops or the next configuration has no eBPF inbound, they stay recorded
// until the process exits. The kernel then releases resources held by file
// descriptors, but not local routes or legacy cgroup attachments.
var retainedInbounds struct {
	access   sync.Mutex
	inbounds []*Inbound
}

func retainForRetry(inbound *Inbound) {
	retainedInbounds.access.Lock()
	defer retainedInbounds.access.Unlock()
	if !slices.Contains(retainedInbounds.inbounds, inbound) {
		retainedInbounds.inbounds = append(retainedInbounds.inbounds, inbound)
	}
}

func releaseRetained(inbound *Inbound) {
	retainedInbounds.access.Lock()
	defer retainedInbounds.access.Unlock()
	retainedInbounds.inbounds = slices.DeleteFunc(retainedInbounds.inbounds, func(it *Inbound) bool {
		return it == inbound
	})
}

func retryRetainedInbounds() error {
	retainedInbounds.access.Lock()
	inbounds := slices.Clone(retainedInbounds.inbounds)
	retainedInbounds.access.Unlock()
	var errors []error
	for _, inbound := range inbounds {
		if err := inbound.Close(); err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return E.Cause(E.Errors(errors...), "clean up resources retained by a previous eBPF inbound")
	}
	return nil
}

// retainsResources reports whether a failed cleanup kept resources that a
// later Close must release.
func (i *Inbound) retainsResources() bool {
	i.tcNamespaceAccess.RLock()
	tcNamespace := i.tcNamespace
	i.tcNamespaceAccess.RUnlock()
	return i.tcBackend() != nil || i.cgroupBackendInstance() != nil || i.sharedRewriteInstance() != nil ||
		tcNamespace != nil || i.localRoutes != nil || i.selfBypass != nil ||
		i.processTracker != nil || i.processTrackerRollback != nil
}
