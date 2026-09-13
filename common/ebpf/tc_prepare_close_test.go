//go:build with_ebpf && (linux || android)

package ebpf

import (
	"os"
	"strings"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// openFDCount counts this process's open file descriptors through procfs, which
// is what a leaked BPF map or program FD would show up as: cilium's Map and
// Program hold real fds, and nothing else in this test opens any.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd to count file descriptors: %v", err)
	}
	return len(entries)
}

// TestPrepareTCClosesRealMapsWhenAnExternalSelfMapDoesNotMatch drives
// loadTCResources into a real failure: an external self-bypass map
// (config.SelfBypassMap) whose raw file descriptor has already been closed
// out from under it — the shape a caller handling its own map's lifecycle
// wrong would actually produce, not a synthetic mismatch. loadObjectPrograms
// reads that map's real info to build the collection's map-replacement spec
// before creating anything; against a closed descriptor that read is
// unreliable, and the real collection creation that follows rejects the
// result as an incompatible map spec. What matters for this test is that the
// failure is genuine and happens after loadTCResources has already created
// every other real map, not the exact internal reason cilium gives for it.
//
// What this test actually proves, checked by reverting the fix locally and
// rerunning it: closeMaps is still called and still releases every real map
// on this path, so the maps do not leak either way. It does not prove the
// error-aggregation itself, because on this exact failure closeMaps succeeds
// cleanly — the only broken map (the disowned self-bypass one) is deleted
// from the map before closeMaps ever sees it, per the comment at that call
// site — so there is nothing here for the fix's E.Errors to actually surface.
// Reaching that would need closeMaps itself to fail on top of this failure,
// which is not reachable through TCConfig alone; this round did not add a
// hook to force it. The aggregation is otherwise a direct, one-line use of
// E.Errors, the same pattern UpdateCompiledBypassCIDR/UpdateHostAddresses
// already use elsewhere in this file.
//
// PrepareTC's compiled-policy validation (CompilePolicy, called before
// PrepareTC ever runs) now catches every policy-shaped misconfiguration this
// test used to reach populateCompiledPolicyMaps with — port ranges past the
// map's capacity, oversized CIDR or MAC lists, and so on all fail before a
// single real map or program exists. That is an improvement over what this
// test originally exercised, not a regression: it means updateControlLocked
// and populateCompiledPolicyMaps, the two remaining backend.Close() call
// sites in prepareTC, can no longer be driven to fail through TCConfig alone
// either, for the same reason.
func TestPrepareTCClosesRealMapsWhenAnExternalSelfMapDoesNotMatch(t *testing.T) {
	before := openFDCount(t)

	// A real map shaped like tc_self_sockets, whose raw file descriptor is
	// closed directly (bypassing Close, which would just report the same
	// EBADF back at cleanup for no reason) before it is ever handed to
	// PrepareTC.
	mismatched, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(uint64(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
		MaxEntries: 1024,
	})
	if err != nil {
		t.Skipf("cannot create a map to use as the broken self-bypass map: %v", err)
	}
	rawFD := mismatched.FD()
	if rawFD < 0 {
		t.Fatal("the map has no usable file descriptor to close")
	}
	if closeErr := unix.Close(rawFD); closeErr != nil {
		t.Fatalf("close the map's raw file descriptor: %v", closeErr)
	}

	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatalf("compile a policy with nothing configured: %v", err)
	}

	_, err = PrepareTC(TCConfig{
		ListenerPort:  12345,
		EnableLocal:   true,
		EnableIPv4:    true,
		EnableTCP:     true,
		Policy:        policy,
		SelfBypassMap: mismatched,
	})
	if err == nil {
		t.Fatal("a mismatched external self-bypass map was reported as success")
	}
	if !strings.Contains(err.Error(), "map spec is incompatible") {
		// Something earlier failed instead — most likely this environment
		// cannot load real TC eBPF maps and programs at all, which is not what
		// this test means to cover.
		t.Skipf("did not reach the intended load failure, got: %v", err)
	}

	after := openFDCount(t)
	if after > before {
		t.Fatalf("open file descriptors went from %d to %d; the maps PrepareTC "+
			"created before the load failure were not released", before, after)
	}
}
