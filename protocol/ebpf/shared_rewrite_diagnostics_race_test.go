//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// TestSharedRewriteDiagnosticsDoesNotRaceWithClose is a real go test -race
// reproduction for a gap an independent review found: Diagnostics() read
// i.sharedRewrite and i.sharedRewrite.dataPlane directly, with no lock,
// while closeResources' plain field write and sharedRewrite.Close's own
// dataPlane write happen under locks nothing on the read side ever takes.
// Diagnostics is reachable from an HTTP handler (the Clash API's /ebpf
// route) with no relationship to this inbound's own shutdown sequence, so
// nothing else coincidentally serializes a request against a concurrent
// close the way, say, the interface monitor's own stop-before-close
// ordering does for its own reads of the same fields.
//
// This does not fail as a functional assertion -- there is nothing to
// assert beyond "the race detector found nothing" -- so its only real
// content is here to be run under -race, which the reverse-verification for
// this test (reverting sharedRewriteInstance/dataPlaneInstance to plain
// field access and re-running) confirms actually matters: that reversion
// reproduces a real WARNING: DATA RACE between this test's Diagnostics()
// call and Close()'s writes.
func TestSharedRewriteDiagnosticsDoesNotRaceWithClose(t *testing.T) {
	inbound := &Inbound{udpTimeout: time.Minute}
	shared := newSharedRewrite(inbound, option.EBPFSharedOptions{})
	inbound.setSharedRewrite(shared)
	shared.setDataPlane(newSharedRewriteDataPlane(shared, 1))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for round := 0; round < 2000; round++ {
			inbound.Diagnostics()
		}
	}()
	if err := shared.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-done
}
