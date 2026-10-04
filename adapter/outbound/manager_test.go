package outbound

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	endpointmanager "github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type lifecycleTestOutbound struct {
	tag    string
	access sync.Mutex
	stages []adapter.StartStage
}

func (o *lifecycleTestOutbound) Type() string { return "test" }

func (o *lifecycleTestOutbound) Tag() string { return o.tag }

func (o *lifecycleTestOutbound) Network() []string { return []string{N.NetworkTCP} }

func (o *lifecycleTestOutbound) Dependencies() []string { return nil }

func (o *lifecycleTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (o *lifecycleTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (o *lifecycleTestOutbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	o.access.Lock()
	o.stages = append(o.stages, stage)
	o.access.Unlock()
	return nil
}

func (o *lifecycleTestOutbound) startedStages() []adapter.StartStage {
	o.access.Lock()
	defer o.access.Unlock()
	return append([]adapter.StartStage(nil), o.stages...)
}

func TestCreateStartsDynamicOutboundAtCurrentStage(t *testing.T) {
	registry := NewRegistry()
	created := make(map[string]*lifecycleTestOutbound)
	Register[struct{}](registry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
		outbound := &lifecycleTestOutbound{tag: tag}
		created[tag] = outbound
		return outbound, nil
	})

	manager := NewManager(registry, endpointmanager.NewManager(endpointmanager.NewRegistry()), "")
	if err := manager.Create(context.Background(), nil, nil, "static", "test", nil); err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := manager.endpoint.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Create(context.Background(), nil, nil, "dynamic", "test", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(adapter.StartStatePostStart, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(adapter.StartStateStarted, scope); err != nil {
		t.Fatal(err)
	}

	want := []adapter.StartStage{
		adapter.StartStateInitialize,
		adapter.StartStateStart,
		adapter.StartStatePostStart,
		adapter.StartStateStarted,
	}
	for _, tag := range []string{"static", "dynamic"} {
		if got := created[tag].startedStages(); len(got) != len(want) {
			t.Fatalf("%s started at %v, want %v", tag, got, want)
		} else {
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("%s started at %v, want %v", tag, got, want)
				}
			}
		}
	}
}
