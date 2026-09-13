//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestSysctlRoot builds a stand-in for /proc/sys/net/ipv4/conf holding one
// rp_filter file per named interface, and points the production code at it.
func newTestSysctlRoot(t *testing.T, values map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, value := range values {
		directory := filepath.Join(root, name)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("create %s: %v", directory, err)
		}
		if err := os.WriteFile(filepath.Join(directory, "rp_filter"), []byte(value+"\n"), 0o644); err != nil {
			t.Fatalf("write rp_filter for %s: %v", name, err)
		}
	}
	previous := tcSysctlRoot
	tcSysctlRoot = root
	t.Cleanup(func() { tcSysctlRoot = previous })
	return root
}

// readTestSysctl trims the value the way the kernel's procfs writers and the
// production code both do, so an untouched file that still carries its trailing
// newline compares equal to one sing-box rewrote.
func readTestSysctl(t *testing.T, interfaceName string) string {
	t.Helper()
	value, err := os.ReadFile(tcInterfaceSysctlPath(interfaceName, "rp_filter"))
	if err != nil {
		t.Fatalf("read rp_filter for %s: %v", interfaceName, err)
	}
	return strings.TrimSpace(string(value))
}

func assertSysctl(t *testing.T, interfaceName, expected string) {
	t.Helper()
	if actual := readTestSysctl(t, interfaceName); actual != expected {
		t.Fatalf("rp_filter for %s = %q, want %q", interfaceName, actual, expected)
	}
}

// TestClearTCAggregateRPFilterPinsOtherInterfaces covers the kernel's
// max(conf.all, conf.<device>) composition: the aggregate knob has to reach 0
// for the delivery interface's own rp_filter=0 to mean anything, and every other
// interface has to be raised to the previous aggregate first so its effective
// policy is unchanged.
func TestClearTCAggregateRPFilterPinsOtherInterfaces(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{
		"all":         "2",
		"default":     "0",
		"wlan0":       "0",
		"rmnet_data0": "1",
		"lo":          "2",
		"sbd00010001": "0",
	})

	states, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("clear aggregate rp_filter: %v", err)
	}

	assertSysctl(t, "all", "0")
	// Raised to the old aggregate so max(all, dev) still evaluates to 2.
	assertSysctl(t, "default", "2")
	assertSysctl(t, "wlan0", "2")
	assertSysctl(t, "rmnet_data0", "2")
	// Already at or above the aggregate, so untouched.
	assertSysctl(t, "lo", "2")
	// The delivery interface is the one interface that must stay at 0.
	assertSysctl(t, "sbd00010001", "0")

	if err = restoreTCSysctlStates(states); err != nil {
		t.Fatalf("restore sysctl states: %v", err)
	}
	assertSysctl(t, "all", "2")
	assertSysctl(t, "default", "0")
	assertSysctl(t, "wlan0", "0")
	assertSysctl(t, "rmnet_data0", "1")
	assertSysctl(t, "lo", "2")
}

func TestClearTCAggregateRPFilterSkipsDisabledAggregate(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{"all": "0", "wlan0": "0"})

	states, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("clear aggregate rp_filter: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("recorded %d states for an already cleared aggregate", len(states))
	}
	assertSysctl(t, "wlan0", "0")
}

// TestRestoreTCSysctlStatesKeepsExternalChange covers a value that someone else
// changed while sing-box was running. Restoring it would overwrite a setting
// that is no longer ours, so the entry is skipped.
func TestRestoreTCSysctlStatesKeepsExternalChange(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{"all": "2", "wlan0": "0"})

	states, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("clear aggregate rp_filter: %v", err)
	}
	if err = os.WriteFile(tcInterfaceSysctlPath("all", "rp_filter"), []byte("1\n"), 0o644); err != nil {
		t.Fatalf("simulate external change: %v", err)
	}

	if err = restoreTCSysctlStates(states); err != nil {
		t.Fatalf("restore sysctl states: %v", err)
	}
	assertSysctl(t, "all", "1")
	assertSysctl(t, "wlan0", "0")
}

func TestAppendTCSysctlStatesKeepsEarliestOriginal(t *testing.T) {
	states := appendTCSysctlStates(nil, []tcSysctlState{
		{path: "/a", original: "2", applied: "0"},
		{path: "/b", original: "0", applied: "2"},
	})
	states = appendTCSysctlStates(states, []tcSysctlState{
		{path: "/a", original: "0", applied: "0"},
		{path: "/c", original: "1", applied: "2"},
	})

	if len(states) != 3 {
		t.Fatalf("recorded %d states, want 3", len(states))
	}
	if states[0].path != "/a" || states[0].original != "2" {
		t.Fatalf("first state = %+v, want the earliest original for /a", states[0])
	}
	if states[2].path != "/c" {
		t.Fatalf("third state = %+v, want /c", states[2])
	}
}

// TestDeliveryReplacementKeepsAggregateRPFilterCleared is the regression test
// for the repair path: a replacement delivery link is created while the link it
// replaces still holds conf.all.rp_filter at 0, so the replacement records no
// restore state of its own. Without the handoff, closing the old link puts the
// aggregate knob back and every redirected packet is dropped as a martian source
// again, with no log line and no counter moving.
func TestDeliveryReplacementKeepsAggregateRPFilterCleared(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{
		"all":         "2",
		"wlan0":       "0",
		"sbd00010001": "0",
		"sbd00010002": "0",
	})

	first := &tcDeliveryLink{deliveryName: "sbd00010001"}
	firstStates, err := clearTCAggregateRPFilter(first.deliveryName)
	if err != nil {
		t.Fatalf("clear aggregate rp_filter for the first link: %v", err)
	}
	first.globalSysctls = appendTCSysctlStates(first.globalSysctls, firstStates)
	assertSysctl(t, "all", "0")

	// The replacement is built before the old link is closed, and finds nothing
	// left to clear.
	second := &tcDeliveryLink{deliveryName: "sbd00010002"}
	secondStates, err := clearTCAggregateRPFilter(second.deliveryName)
	if err != nil {
		t.Fatalf("clear aggregate rp_filter for the replacement: %v", err)
	}
	if len(secondStates) != 0 {
		t.Fatalf("replacement recorded %d aggregate states, want 0", len(secondStates))
	}
	second.globalSysctls = appendTCSysctlStates(second.globalSysctls, secondStates)

	handoffTCGlobalSysctls(first, second)
	if err = first.Close(); err != nil {
		t.Fatalf("close the replaced link: %v", err)
	}

	assertSysctl(t, "all", "0")
	assertSysctl(t, "wlan0", "2")

	// The replacement now owns the restore, so shutting it down puts the system
	// back the way it was found.
	if err = second.Close(); err != nil {
		t.Fatalf("close the replacement link: %v", err)
	}
	assertSysctl(t, "all", "2")
	assertSysctl(t, "wlan0", "0")
}

// TestAppendTCSysctlStatesTracksLatestApplied covers a repair round that writes
// a different value than the first round did, which happens when the aggregate
// knob changes underneath sing-box. The original has to stay at the value the
// interface had before sing-box touched it, but applied has to follow the most
// recent write or the restore guard mistakes sing-box's own value for someone
// else's change and leaves it behind.
func TestAppendTCSysctlStatesTracksLatestApplied(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{
		"all":         "1",
		"wlan0":       "0",
		"sbd00010001": "0",
	})

	first, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("clear aggregate rp_filter: %v", err)
	}
	states := appendTCSysctlStates(nil, first)
	assertSysctl(t, "all", "0")
	assertSysctl(t, "wlan0", "1")

	// Something else raises the aggregate, and the next repair round pins wlan0
	// to the new value.
	if err = os.WriteFile(tcInterfaceSysctlPath("all", "rp_filter"), []byte("2\n"), 0o644); err != nil {
		t.Fatalf("simulate external change: %v", err)
	}
	second, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("clear aggregate rp_filter again: %v", err)
	}
	states = appendTCSysctlStates(states, second)
	assertSysctl(t, "all", "0")
	assertSysctl(t, "wlan0", "2")

	if err = restoreTCSysctlStates(states); err != nil {
		t.Fatalf("restore sysctl states: %v", err)
	}
	// wlan0 must come back to the value it had before sing-box ever pinned it.
	assertSysctl(t, "wlan0", "0")
}

// TestRestoreTCSysctlStatesRaisesBeforeLowering covers a pin recorded after the
// aggregate entry, which happens when an interface appears between repair
// rounds. Walking the list backwards would drop that interface's own filter
// while conf.all.rp_filter is still 0 and leave it briefly unprotected, so
// restores that raise a value have to run first.
func TestRestoreTCSysctlStatesRaisesBeforeLowering(t *testing.T) {
	root := newTestSysctlRoot(t, map[string]string{
		"all":         "2",
		"wlan0":       "0",
		"sbd00010001": "0",
	})

	first, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("clear aggregate rp_filter: %v", err)
	}
	states := appendTCSysctlStates(nil, first)

	// A new interface shows up and the aggregate is reset externally, so the next
	// round appends usb0's pin after the aggregate entry already in the list.
	if err = os.MkdirAll(filepath.Join(root, "usb0"), 0o755); err != nil {
		t.Fatalf("create usb0: %v", err)
	}
	if err = os.WriteFile(filepath.Join(root, "usb0", "rp_filter"), []byte("0\n"), 0o644); err != nil {
		t.Fatalf("write usb0 rp_filter: %v", err)
	}
	if err = os.WriteFile(tcInterfaceSysctlPath("all", "rp_filter"), []byte("2\n"), 0o644); err != nil {
		t.Fatalf("simulate external reset: %v", err)
	}
	second, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("clear aggregate rp_filter again: %v", err)
	}
	states = appendTCSysctlStates(states, second)

	aggregateIndex := -1
	usbIndex := -1
	for index, state := range states {
		switch state.path {
		case tcInterfaceSysctlPath("all", "rp_filter"):
			aggregateIndex = index
		case tcInterfaceSysctlPath("usb0", "rp_filter"):
			usbIndex = index
		}
	}
	if aggregateIndex < 0 || usbIndex < 0 {
		t.Fatalf("states = %+v, want both the aggregate and usb0 recorded", states)
	}
	if usbIndex < aggregateIndex {
		t.Fatalf("usb0 recorded at %d before the aggregate at %d; the ordering hazard is not reproduced",
			usbIndex, aggregateIndex)
	}
	// The recorded order alone would drop usb0 first. The restore sequence has
	// to put the aggregate ahead of it regardless.
	ordered := tcSysctlRestoreOrder(states)
	aggregatePosition := -1
	usbPosition := -1
	for position, state := range ordered {
		switch state.path {
		case tcInterfaceSysctlPath("all", "rp_filter"):
			aggregatePosition = position
		case tcInterfaceSysctlPath("usb0", "rp_filter"):
			usbPosition = position
		}
	}
	if aggregatePosition < 0 || usbPosition < 0 {
		t.Fatalf("restore order = %+v, want both entries present", ordered)
	}
	if aggregatePosition > usbPosition {
		t.Fatalf("restore order puts the aggregate at %d after usb0 at %d, which leaves usb0 "+
			"unprotected while conf.all.rp_filter is still 0", aggregatePosition, usbPosition)
	}

	if err = restoreTCSysctlStates(states); err != nil {
		t.Fatalf("restore sysctl states: %v", err)
	}
	assertSysctl(t, "all", "2")
	assertSysctl(t, "usb0", "0")
	assertSysctl(t, "wlan0", "0")
}

// TestClearTCAggregateRPFilterRejectsUnparsableAggregate covers a value that
// cannot be read at all. Reporting no work to do would let startup succeed while
// the delivery interface is still behind an aggregate filter nobody lowered, so
// the failure has to surface and nothing may be touched on the way out.
func TestClearTCAggregateRPFilterRejectsUnparsableAggregate(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{
		"all":         "not-a-number",
		"wlan0":       "0",
		"sbd00010001": "0",
	})

	states, err := clearTCAggregateRPFilter("sbd00010001")
	if err == nil {
		t.Fatalf("an unparsable aggregate was accepted, recording %+v", states)
	}
	if states != nil {
		t.Fatalf("states recorded on the failure path: %+v", states)
	}
	assertSysctl(t, "all", "not-a-number")
	assertSysctl(t, "wlan0", "0")
}

// TestClearTCAggregateRPFilterRejectsUnparsableInterface is the case that
// matters: pinning an interface whose value cannot be read has to fail before
// the aggregate knob is cleared. Clearing it anyway would drop that interface
// from max(all, dev) to whatever dev happens to be, which is the one way this
// function can weaken a filter rather than preserve it.
func TestClearTCAggregateRPFilterRejectsUnparsableInterface(t *testing.T) {
	// ReadDir returns entries in name order, so aaa0 is pinned before zzz0 fails.
	newTestSysctlRoot(t, map[string]string{
		"aaa0":        "0",
		"all":         "2",
		"sbd00010001": "0",
		"zzz0":        "corrupt",
	})

	states, err := clearTCAggregateRPFilter("sbd00010001")
	if err == nil {
		t.Fatalf("an unparsable interface value was accepted, recording %+v", states)
	}
	if states != nil {
		t.Fatalf("states recorded on the failure path: %+v", states)
	}
	// The aggregate must still be enabled: nothing was allowed to lower it.
	assertSysctl(t, "all", "2")
	// The interface pinned before the failure must be back where it started, so
	// this round leaves no sysctl behind.
	assertSysctl(t, "aaa0", "0")
	assertSysctl(t, "zzz0", "corrupt")
	assertSysctl(t, "sbd00010001", "0")
}

// TestClearTCAggregateRPFilterSkipsVanishedInterface keeps the one error the
// loop is allowed to swallow: a directory whose rp_filter is gone belongs to an
// interface that disappeared between listing and reading.
func TestClearTCAggregateRPFilterSkipsVanishedInterface(t *testing.T) {
	root := newTestSysctlRoot(t, map[string]string{
		"all":         "2",
		"wlan0":       "0",
		"sbd00010001": "0",
	})
	if err := os.MkdirAll(filepath.Join(root, "gone0"), 0o755); err != nil {
		t.Fatalf("create gone0: %v", err)
	}

	states, err := clearTCAggregateRPFilter("sbd00010001")
	if err != nil {
		t.Fatalf("a vanished interface should be skipped: %v", err)
	}
	assertSysctl(t, "all", "0")
	assertSysctl(t, "wlan0", "2")

	if err = restoreTCSysctlStates(states); err != nil {
		t.Fatalf("restore sysctl states: %v", err)
	}
	assertSysctl(t, "all", "2")
	assertSysctl(t, "wlan0", "0")
}

func TestPinTCInterfaceRPFilterRejectsUnparsableValue(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{"wlan0": "corrupt"})

	state, changed, err := pinTCInterfaceRPFilter("wlan0", 2)
	if err == nil {
		t.Fatal("an unparsable value was reported as needing no change")
	}
	if changed {
		t.Fatalf("a change was reported on the failure path: %+v", state)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the failure looks like a vanished interface and would be skipped: %v", err)
	}
	assertSysctl(t, "wlan0", "corrupt")
}

func TestPinTCInterfaceRPFilterLeavesStrongerInterfaceAlone(t *testing.T) {
	newTestSysctlRoot(t, map[string]string{"wlan0": "2"})

	_, changed, err := pinTCInterfaceRPFilter("wlan0", 1)
	if err != nil {
		t.Fatalf("pin rp_filter: %v", err)
	}
	if changed {
		t.Fatal("an interface already above the aggregate was rewritten")
	}
	assertSysctl(t, "wlan0", "2")
}
