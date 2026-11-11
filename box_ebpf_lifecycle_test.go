//go:build with_ebpf && (linux || android)

package box_test

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// A box that is created and closed without starting, as for a configuration
// check, must not leave eBPF goroutines or an unclaimed self-bypass behind.
func TestBoxCloseBeforeStartReleasesEBPF(t *testing.T) {
	ctx := include.Context(context.Background())
	var options option.Options
	err := json.UnmarshalContext(ctx, []byte(`{"log":{"disabled":true},"inbounds":[{"type":"ebpf","tag":"ebpf-in"}]}`), &options)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			t.Fatal(err)
		}
		provider, loaded := instance.Network().(interface {
			EBPFSelfBypass() *commonEBPF.SelfBypass
		})
		if !loaded {
			t.Fatal("network manager does not expose eBPF self-bypass")
		}
		tracker := provider.EBPFSelfBypass()
		if tracker == nil {
			t.Fatal("eBPF self-bypass was not prepared")
		}
		if err = instance.Close(); err != nil {
			t.Fatal(err)
		}
		if !tracker.IsClosed() || provider.EBPFSelfBypass() != nil {
			t.Fatal("unclaimed eBPF self-bypass survived box close")
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		buffer := make([]byte, 1<<20)
		stacks := string(buffer[:runtime.Stack(buffer, true)])
		if !strings.Contains(stacks, "udpNATService).cleanupLoop") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("eBPF UDP NAT cleanup goroutine leaked by a box that never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
