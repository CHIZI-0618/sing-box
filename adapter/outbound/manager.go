package outbound

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	startAccess             sync.Mutex
	scope                   *adapter.Scope
	currentStage            adapter.StartStage
	startedStages           map[string]adapter.StartStage
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		startedStages: make(map[string]adapter.StartStage),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	outbounds := m.outbounds
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		if err := m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...)); err != nil {
			return err
		}
	} else {
		for _, outbound := range outbounds {
			lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			err := m.startOutbound(scope, outbound, lifecycle, stage, name)
			if err != nil {
				return err
			}
		}
	}
	m.access.Lock()
	if m.scope == nil {
		m.scope = scope
	}
	m.currentStage = stage
	m.access.Unlock()
	return nil
}

func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			if endpoint, isEndpoint := outboundToStart.(adapter.Endpoint); isEndpoint {
				err := m.endpoint.StartEndpoint(endpoint)
				if err != nil {
					return err
				}
				continue
			}
			lifecycle, isLifecycle := outboundToStart.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			err := m.startOutbound(scope, outboundToStart, lifecycle, adapter.StartStateStart, name)
			if err != nil {
				return err
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

func (m *Manager) startOutbound(scope *adapter.Scope, outbound adapter.Outbound, lifecycle adapter.Lifecycle, stage adapter.StartStage, name string) error {
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	return m.startOutboundLocked(scope, outbound, lifecycle, stage, name)
}

func (m *Manager) startOutboundLocked(scope *adapter.Scope, outbound adapter.Outbound, lifecycle adapter.Lifecycle, stage adapter.StartStage, name string) error {
	m.access.RLock()
	startedStage, started := m.startedStages[outbound.Tag()]
	m.access.RUnlock()
	if started && startedStage >= stage {
		return nil
	}
	if err := scope.Start(name, lifecycle, stage); err != nil {
		return err
	}
	m.access.Lock()
	if currentStage, loaded := m.startedStages[outbound.Tag()]; !loaded || currentStage < stage {
		m.startedStages[outbound.Tag()] = stage
	}
	m.access.Unlock()
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.RLock()
	_, loaded := m.outboundByTag[tag]
	scope := m.scope
	currentStage := m.currentStage
	m.access.RUnlock()
	if loaded {
		return E.New("duplicate outbound tag: ", tag)
	}
	if scope != nil {
		if lifecycle, isLifecycle := outbound.(adapter.Lifecycle); isLifecycle {
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			for _, stage := range adapter.ListStartStages {
				if stage > currentStage {
					break
				}
				if err = m.startOutboundLocked(scope, outbound, lifecycle, stage, name); err != nil {
					return err
				}
			}
		}
	}
	m.access.Lock()
	defer m.access.Unlock()
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
	}
	return nil
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	outbound, loaded := m.outboundByTag[tag]
	if !loaded {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.outboundByTag, tag)
	for i, item := range m.outbounds {
		if item == outbound {
			m.outbounds = append(m.outbounds[:i], m.outbounds[i+1:]...)
			break
		}
	}
	if m.defaultOutbound == outbound {
		m.defaultOutbound = nil
	}
	delete(m.startedStages, tag)
	m.access.Unlock()
	if closer, ok := outbound.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
