//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// testSharedRewriteDevice builds a netlink.Link that carries only the attributes
// reconcile reads, so the attach paths can be driven without a kernel.
func testSharedRewriteDevice(name string, index int) netlink.Link {
	attributes := netlink.NewLinkAttrs()
	attributes.Name = name
	attributes.Index = index
	return &netlink.Device{LinkAttrs: attributes}
}

type testSharedRewriteHarness struct {
	// failures maps an interface name to the number of consecutive attach calls
	// that should fail before one succeeds.
	failures    map[string]int
	attachCalls map[string]int
	enableCalls []bool
	enableErr   error
	purgeCalls  int
	dataPlane   *sharedRewriteDataPlane
}

func newTestSharedRewriteHarness(t *testing.T, failures map[string]int) *testSharedRewriteHarness {
	t.Helper()
	harness := &testSharedRewriteHarness{
		failures:    failures,
		attachCalls: make(map[string]int),
	}
	harness.dataPlane = &sharedRewriteDataPlane{
		attachments: make(map[string]*sharedRewriteAttachment),
		priority:    defaultTCPriority,
		hooks: &sharedRewriteDataPlaneHooks{
			attach:      harness.attach,
			setEnabled:  harness.setEnabled,
			purgeUDPNat: harness.purgeUDPNat,
		},
	}
	return harness
}

func (h *testSharedRewriteHarness) attach(
	device netlink.Link,
	_ *commonEBPF.SharedNetworkBackend,
	_ uint16,
) (*sharedRewriteAttachment, error) {
	name := device.Attrs().Name
	h.attachCalls[name]++
	if h.failures[name] > 0 {
		h.failures[name]--
		return nil, E.New("synthetic attach failure for ", name)
	}
	return &sharedRewriteAttachment{
		interfaceName:  name,
		interfaceIndex: device.Attrs().Index,
		attachmentType: "clsact",
	}, nil
}

func (h *testSharedRewriteHarness) setEnabled(enabled bool) error {
	h.enableCalls = append(h.enableCalls, enabled)
	return h.enableErr
}

func (h *testSharedRewriteHarness) purgeUDPNat() {
	h.purgeCalls++
}

// attached seeds an attachment the way a previous reconcile would have left it.
func (h *testSharedRewriteHarness) attached(name string, index int) {
	h.dataPlane.attachments[name] = &sharedRewriteAttachment{interfaceName: name, interfaceIndex: index}
	h.dataPlane.enabled = true
}

// apply runs the attach pass and then the cleanup reconcile defers, so the test
// sees the state a caller would.
func (h *testSharedRewriteHarness) apply(names []string, desired map[string]netlink.Link) error {
	err := h.dataPlane.applyAttachmentsLocked(names, desired)
	h.dataPlane.purgeInvalidatedFlowsLocked()
	return err
}

// TestApplyAttachmentsRestoresReplacedInterfaceAfterTransientFailure covers the
// interface whose attachment was found unhealthy: it is released so a
// replacement can be built, the replacement fails once, and the immediate retry
// puts an attachment back rather than leaving the interface bare.
func TestApplyAttachmentsRestoresReplacedInterfaceAfterTransientFailure(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, map[string]int{"eth0": 1})
	harness.attached("eth0", 2)

	desired := map[string]netlink.Link{"eth0": testSharedRewriteDevice("eth0", 2)}
	if err := harness.apply([]string{"eth0"}, desired); err == nil {
		t.Fatal("expected the failed attach to be reported")
	}
	if harness.dataPlane.attachments["eth0"] == nil {
		t.Fatal("eth0 was left without an attachment after a transient failure")
	}
	if harness.attachCalls["eth0"] != 2 {
		t.Fatalf("attach called %d times for eth0, want 2", harness.attachCalls["eth0"])
	}
	if !harness.dataPlane.enabled {
		t.Fatal("backend disabled even though eth0 ended up attached")
	}
	if harness.purgeCalls != 1 {
		t.Fatalf("udpNat purged %d times, want 1: detaching eth0 dropped its kernel flows",
			harness.purgeCalls)
	}
}

// TestApplyAttachmentsReportsPersistentReplacementFailure is the honest limit of
// the immediate retry: when the second attempt fails too, the interface stays
// unattached and the error has to say so, because nothing in this data plane
// retries again before the next netlink event.
func TestApplyAttachmentsReportsPersistentReplacementFailure(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, map[string]int{"eth0": 2})
	harness.attached("eth0", 2)

	desired := map[string]netlink.Link{"eth0": testSharedRewriteDevice("eth0", 2)}
	if err := harness.apply([]string{"eth0"}, desired); err == nil {
		t.Fatal("expected the persistent failure to be reported")
	}
	if harness.attachCalls["eth0"] != 2 {
		t.Fatalf("attach called %d times for eth0, want 2", harness.attachCalls["eth0"])
	}
	if attachment := harness.dataPlane.attachments["eth0"]; attachment != nil {
		t.Fatalf("eth0 unexpectedly kept an attachment: %+v", attachment)
	}
	// The data plane started enabled, so this proves the sync ran rather than
	// observing a flag that was already false.
	if harness.dataPlane.enabled {
		t.Fatal("backend left enabled with no attachment in place")
	}
	if len(harness.enableCalls) != 1 || harness.enableCalls[0] {
		t.Fatalf("enable calls = %v, want a single disable", harness.enableCalls)
	}
	if harness.purgeCalls != 1 {
		t.Fatalf("udpNat purged %d times, want 1", harness.purgeCalls)
	}
}

// TestApplyAttachmentsPurgesAfterDetachFailure covers the exit the flow flag
// exists for: the detach that releases the old attachment already purged the
// kernel flows, then reported an error before anything was recorded as changed.
// The userspace NAT still has to be purged.
func TestApplyAttachmentsPurgesAfterDetachFailure(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, nil)
	harness.attached("eth0", 2)
	// A lock whose Close fails makes detachLocked report an error after it has
	// already invalidated the flows.
	harness.dataPlane.attachments["eth0"].lock = failingCloser{}

	desired := map[string]netlink.Link{"eth0": testSharedRewriteDevice("eth0", 2)}
	if err := harness.apply([]string{"eth0"}, desired); err == nil {
		t.Fatal("expected the detach failure to be reported")
	}
	if harness.attachCalls["eth0"] != 0 {
		t.Fatalf("attach called %d times, want 0: the detach failed first", harness.attachCalls["eth0"])
	}
	if harness.purgeCalls != 1 {
		t.Fatalf("udpNat purged %d times, want 1 after a detach that dropped kernel flows",
			harness.purgeCalls)
	}
}

// TestApplyAttachmentsPurgesWhenEnableSyncFails covers the other exit: the
// attachments changed, the backend refused to follow, and the NAT purge still
// has to happen.
func TestApplyAttachmentsPurgesWhenEnableSyncFails(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, map[string]int{"eth0": 2})
	harness.attached("eth0", 2)
	harness.enableErr = E.New("synthetic disable failure")

	desired := map[string]netlink.Link{"eth0": testSharedRewriteDevice("eth0", 2)}
	if err := harness.apply([]string{"eth0"}, desired); err == nil {
		t.Fatal("expected the failure to be reported")
	}
	// The disable did not take effect, so the flag has to keep saying enabled;
	// recording false here would claim a teardown that never happened.
	if !harness.dataPlane.enabled {
		t.Fatal("enabled was cleared even though the backend refused the disable")
	}
	if len(harness.enableCalls) != 1 || harness.enableCalls[0] {
		t.Fatalf("enable calls = %v, want a single attempted disable", harness.enableCalls)
	}
	if harness.purgeCalls != 1 {
		t.Fatalf("udpNat purged %d times, want 1 even though the enable sync failed",
			harness.purgeCalls)
	}
}

// TestApplyAttachmentsKeepsEarlierReplacementOnLaterFailure covers the mixed
// case: eth0 is replaced successfully and eth1 then fails. Tearing eth0 down
// again would reopen the very gap the two-phase reconcile exists to close, so it
// keeps its fresh attachment.
func TestApplyAttachmentsKeepsEarlierReplacementOnLaterFailure(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, map[string]int{"eth1": 2})
	harness.attached("eth0", 2)
	harness.attached("eth1", 3)

	desired := map[string]netlink.Link{
		"eth0": testSharedRewriteDevice("eth0", 2),
		"eth1": testSharedRewriteDevice("eth1", 3),
	}
	if err := harness.apply([]string{"eth0", "eth1"}, desired); err == nil {
		t.Fatal("expected the eth1 failure to be reported")
	}
	attachment := harness.dataPlane.attachments["eth0"]
	if attachment == nil {
		t.Fatal("eth0 lost its attachment because a later interface failed")
	}
	if attachment.attachmentType != "clsact" {
		t.Fatalf("eth0 kept the stale attachment %+v, want the replacement", attachment)
	}
	if harness.dataPlane.attachments["eth1"] != nil {
		t.Fatal("eth1 unexpectedly reported an attachment")
	}
	// eth0 is still attached, so the backend stays enabled.
	if !harness.dataPlane.enabled {
		t.Fatal("backend disabled while eth0 is still attached")
	}
}

// TestApplyAttachmentsRollsBackNewInterfaceOnLaterFailure covers an interface
// that was not attached on entry: it is genuinely new work this round, so a
// later failure undoes it instead of leaving a half-applied topology.
func TestApplyAttachmentsRollsBackNewInterfaceOnLaterFailure(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, map[string]int{"eth1": 2})

	desired := map[string]netlink.Link{
		"eth0": testSharedRewriteDevice("eth0", 2),
		"eth1": testSharedRewriteDevice("eth1", 3),
	}
	if err := harness.apply([]string{"eth0", "eth1"}, desired); err == nil {
		t.Fatal("expected the eth1 failure to be reported")
	}
	if len(harness.dataPlane.attachments) != 0 {
		t.Fatalf("attachments = %v, want the newly added eth0 rolled back", harness.dataPlane.attachments)
	}
	if harness.dataPlane.enabled {
		t.Fatal("backend left enabled with no attachment in place")
	}
	if harness.purgeCalls != 1 {
		t.Fatalf("udpNat purged %d times, want 1", harness.purgeCalls)
	}
}

func TestApplyAttachmentsEnablesBackendForNewInterfaces(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, nil)

	desired := map[string]netlink.Link{
		"eth0": testSharedRewriteDevice("eth0", 2),
		"eth1": testSharedRewriteDevice("eth1", 3),
	}
	if err := harness.apply([]string{"eth0", "eth1"}, desired); err != nil {
		t.Fatalf("apply attachments: %v", err)
	}
	if len(harness.dataPlane.attachments) != 2 {
		t.Fatalf("attachments = %v, want eth0 and eth1", harness.dataPlane.attachments)
	}
	if err := harness.dataPlane.syncEnabledLocked(); err != nil {
		t.Fatalf("sync enabled: %v", err)
	}
	if !harness.dataPlane.enabled {
		t.Fatal("backend not enabled after attaching two interfaces")
	}
	if len(harness.enableCalls) != 1 || !harness.enableCalls[0] {
		t.Fatalf("enable calls = %v, want a single enable", harness.enableCalls)
	}
}

func TestPurgeInvalidatedFlowsRunsOnlyWhenInvalidated(t *testing.T) {
	harness := newTestSharedRewriteHarness(t, nil)

	harness.dataPlane.purgeInvalidatedFlowsLocked()
	if harness.purgeCalls != 0 {
		t.Fatalf("udpNat purged %d times with nothing invalidated", harness.purgeCalls)
	}
	harness.dataPlane.flowsInvalidated = true
	harness.dataPlane.purgeInvalidatedFlowsLocked()
	harness.dataPlane.purgeInvalidatedFlowsLocked()
	if harness.purgeCalls != 1 {
		t.Fatalf("udpNat purged %d times, want exactly 1 per invalidation", harness.purgeCalls)
	}
}

type failingCloser struct{}

func (failingCloser) Close() error { return E.New("synthetic close failure") }
