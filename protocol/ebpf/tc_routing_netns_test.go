//go:build with_ebpf && (linux || android)

package ebpf

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// testNetworkNamespace holds the thread state enterTestNetworkNamespace has to
// undo. The thread stays locked to this goroutine for as long as its network
// namespace is not the one the runtime handed out.
type testNetworkNamespace struct {
	original     *os.File
	originalLink string
	isolatedLink string
	restored     bool
}

// enterTestNetworkNamespace moves the calling goroutine's thread into a fresh
// network namespace and proves it landed there before the caller writes
// anything.
//
// The namespace is created here rather than by the caller passing an
// environment variable, because an environment variable only says what someone
// intended: a host whose rule table happens to look untouched would satisfy it
// just as well. Comparing the thread's network namespace inode before and after
// the unshare is direct evidence, and every exit before that evidence exists is
// a skip, so a kernel or a container that refuses the unshare never reaches a
// write.
//
// A handle to the original namespace is taken before the unshare, because
// restoring it is what makes unlocking the thread safe: runtime.UnlockOSThread
// returns the thread to the scheduler, and any goroutine that later runs on it
// inherits its network namespace. restore puts the thread back first and only
// unlocks once that is confirmed.
func enterTestNetworkNamespace(t *testing.T) *testNetworkNamespace {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("creating a network namespace requires root")
	}
	runtime.LockOSThread()
	unlockOnSkip := true
	defer func() {
		if unlockOnSkip {
			runtime.UnlockOSThread()
		}
	}()

	originalLink, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Skipf("cannot read the thread's network namespace: %v", err)
	}
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Skipf("cannot hold the thread's network namespace open: %v", err)
	}
	if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = original.Close()
		t.Skipf("cannot create a private network namespace: %v", err)
	}
	// From here the thread is polluted, so it must not be unlocked by the skip
	// path above, and the restore has to be registered before anything else can
	// fail: every exit below is now covered, and it is also what closes the
	// namespace handle.
	unlockOnSkip = false
	namespace := &testNetworkNamespace{original: original, originalLink: originalLink}
	t.Cleanup(func() { namespace.restore(t) })

	isolatedLink, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatalf("cannot confirm the new network namespace: %v", err)
	}
	if originalLink == isolatedLink {
		t.Fatalf("unshare reported success but the namespace is unchanged (%s); refusing to touch it", isolatedLink)
	}
	namespace.isolatedLink = isolatedLink
	t.Logf("isolated: network namespace %s -> %s", originalLink, isolatedLink)

	// A fresh namespace carries only the three default rules. Anything else means
	// the sockets below would not be talking to the namespace just created.
	//
	// The local rule sits at priority 0, and the kernel omits FRA_PRIORITY for
	// it, so netlink.NewRule's -1 sentinel survives the read back. Both spellings
	// are accepted here.
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatalf("list policy rules in the new namespace: %v", err)
	}
	for _, rule := range rules {
		switch rule.Priority {
		case -1, 0, 32766, 32767:
		default:
			t.Fatalf("unexpected rule in a supposedly fresh namespace: %+v", rule)
		}
	}
	return namespace
}

// restore returns the thread to the namespace it started in and only then
// unlocks it. A thread whose namespace could not be restored is deliberately
// left locked: the goroutine that owns it is about to exit, and the Go runtime
// terminates a thread whose locked goroutine exits, which disposes of it instead
// of handing a modified network namespace to the scheduler.
func (n *testNetworkNamespace) restore(t *testing.T) {
	t.Helper()
	if n == nil || n.restored {
		return
	}
	n.restored = true
	defer n.original.Close()

	if err := unix.Setns(int(n.original.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Errorf("cannot restore the thread's network namespace, leaving the thread locked so the runtime discards it: %v", err)
		return
	}
	current, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Errorf("cannot confirm the restored network namespace, leaving the thread locked so the runtime discards it: %v", err)
		return
	}
	if current != n.originalLink {
		t.Errorf("thread left in namespace %s, want %s; leaving the thread locked so the runtime discards it",
			current, n.originalLink)
		return
	}
	runtime.UnlockOSThread()
}

func testTCPolicyRouting(family int) *tcPolicyRouting {
	return &tcPolicyRouting{
		mark:     tcTestRoutingMark,
		table:    tcPolicyRoutingTable,
		priority: tcPolicyRoutingPriority,
		families: []int{family},
	}
}

// TestTCPolicyRuleKernelOwnsOnlyItsOwn covers the full create, read back,
// classify and reclaim cycle against a real kernel.
func TestTCPolicyRuleKernelOwnsOnlyItsOwn(t *testing.T) {
	enterTestNetworkNamespace(t)
	family := unix.AF_INET
	expected := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)

	if err := netlink.RuleAdd(expected); err != nil {
		t.Fatalf("add policy rule: %v", err)
	}
	entries, err := listTCPolicyRules(family, *expected)
	if err != nil {
		t.Fatalf("list policy rules: %v", err)
	}
	owned := 0
	for _, rule := range entries {
		if rule.owned {
			owned++
		}
	}
	if owned != 1 {
		t.Fatalf("recognised %d rules as ours, want 1; entries %+v", owned, entries)
	}

	// The real reclaim path finds it and removes it.
	routing := testTCPolicyRouting(family)
	stale, err := inspectTCPolicyRoutingFamily(1, family, routing)
	if err != nil {
		t.Fatalf("inspect policy routing: %v", err)
	}
	if stale.rule == nil {
		t.Fatal("the leftover rule was not offered for reclaim")
	}
	if err = removeStaleTCPolicyRouting(stale); err != nil {
		t.Fatalf("remove stale policy routing: %v", err)
	}
	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("list policy rules after reclaim: %v", err)
	}
	for _, rule := range rules {
		if rule.Priority == tcPolicyRoutingPriority {
			t.Fatalf("the reclaimed rule survived: %+v", rule)
		}
	}
}

// TestTCPolicyRuleKernelRejectsSamePriorityCondition is the case the priority+1
// variant could not reach: a third-party rule with the identical priority,
// table, fwmark and mask, differing only by an extra condition. It must not be
// claimed, must not be deleted, and must stop startup rather than being treated
// as this process's rule already in place.
func TestTCPolicyRuleKernelRejectsSamePriorityCondition(t *testing.T) {
	enterTestNetworkNamespace(t)
	family := unix.AF_INET
	expected := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)

	foreign := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)
	foreign.IifName = "lo"
	if err := netlink.RuleAdd(foreign); err != nil {
		t.Fatalf("add third-party policy rule: %v", err)
	}

	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("list policy rules: %v", err)
	}
	found := false
	for _, rule := range rules {
		if rule.Priority != tcPolicyRoutingPriority {
			continue
		}
		found = true
		if rule.IifName != "lo" {
			t.Fatalf("the kernel did not report the incoming interface: %+v", rule)
		}
	}
	if !found {
		t.Fatal("the third-party rule was not listed")
	}
	entries, err := listTCPolicyRules(family, *expected)
	if err != nil {
		t.Fatalf("list policy rules: %v", err)
	}
	for _, rule := range entries {
		if rule.owned {
			t.Fatalf("a rule restricted to iif lo was claimed as ours: %+v", rule)
		}
	}

	// Startup must refuse rather than adopt or delete it.
	routing := testTCPolicyRouting(family)
	stale, err := inspectTCPolicyRoutingFamily(1, family, routing)
	if err == nil {
		t.Fatalf("inspect accepted a conflicting rule, offering %+v for reclaim", stale.rule)
	}
	if !strings.Contains(err.Error(), "referenced by another policy rule") {
		t.Fatalf("unexpected conflict error: %v", err)
	}
	if stale.rule != nil {
		t.Fatalf("a conflicting rule was offered for reclaim: %+v", stale.rule)
	}

	// And it is still there.
	rules, err = netlink.RuleList(family)
	if err != nil {
		t.Fatalf("list policy rules after inspect: %v", err)
	}
	for _, rule := range rules {
		if rule.Priority == tcPolicyRoutingPriority && rule.IifName == "lo" {
			return
		}
	}
	t.Fatal("the third-party rule was removed")
}

// TestTCPolicyRuleKernelRejectsForeignAction is the counterexample for the claim
// that a routing table implies FR_ACT_TO_TBL. The kernel stores the action and
// the table independently and dumps FRA_TABLE either way, so a blackhole rule
// can report exactly the priority, table, fwmark and mask this process uses. The
// rule listing cannot see the difference, which is why ownership consults the
// action from the dump header.
func TestTCPolicyRuleKernelRejectsForeignAction(t *testing.T) {
	enterTestNetworkNamespace(t)
	family := unix.AF_INET
	expected := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)

	blackhole := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)
	blackhole.Type = unix.FR_ACT_BLACKHOLE
	if err := netlink.RuleAdd(blackhole); err != nil {
		t.Skipf("this kernel refused a blackhole rule carrying a table: %v", err)
	}

	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("list policy rules: %v", err)
	}
	entries, err := listTCPolicyRules(family, *expected)
	if err != nil {
		t.Fatalf("list policy rules: %v", err)
	}

	listed := false
	for _, rule := range rules {
		if rule.Priority != tcPolicyRoutingPriority {
			continue
		}
		listed = true
		// The premise this whole check rests on: the kernel reports the table for
		// a rule whose action is not "look up a table", so nothing netlink.Rule
		// exposes distinguishes it from the rule this process installs.
		if rule.Table != tcPolicyRoutingTable {
			t.Fatalf("the kernel did not report the table for a blackhole rule: %+v", rule)
		}
		if rule.Mark != tcTestRoutingMark || rule.Mask != int(tcTestRoutingMark) {
			t.Fatalf("the kernel did not report our fwmark for a blackhole rule: %+v", rule)
		}
	}
	if !listed {
		t.Fatal("the blackhole rule was not listed")
	}
	claimed := false
	for _, rule := range entries {
		if rule.priority == tcPolicyRoutingPriority && rule.owned {
			claimed = true
		}
	}
	if claimed {
		t.Fatalf("a blackhole rule was claimed as ours: %+v", entries)
	}

	// Startup must refuse instead of assuming its own rule is already installed.
	routing := testTCPolicyRouting(family)
	if _, err = inspectTCPolicyRoutingFamily(1, family, routing); err == nil {
		t.Fatal("inspect treated a blackhole rule as this process's own")
	}

	rules, err = netlink.RuleList(family)
	if err != nil {
		t.Fatalf("list policy rules after inspect: %v", err)
	}
	for _, rule := range rules {
		if rule.Priority == tcPolicyRoutingPriority {
			return
		}
	}
	t.Fatal("the blackhole rule was removed")
}

// TestTestNetworkNamespaceRestoresThread verifies the exit path, not just the
// entry: the thread has to be back in the namespace it started in before it is
// handed to the scheduler, or a later goroutine inherits the isolated one.
func TestTestNetworkNamespaceRestoresThread(t *testing.T) {
	namespace := enterTestNetworkNamespace(t)

	during, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatalf("read the isolated namespace: %v", err)
	}
	if during != namespace.isolatedLink {
		t.Fatalf("thread is in %s, want the isolated %s", during, namespace.isolatedLink)
	}
	if during == namespace.originalLink {
		t.Fatal("the isolated namespace is the original one")
	}

	namespace.restore(t)
	if !namespace.restored {
		t.Fatal("restore did not record that it ran")
	}
	after, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatalf("read the restored namespace: %v", err)
	}
	if after != namespace.originalLink {
		t.Fatalf("thread left in %s, want the original %s", after, namespace.originalLink)
	}
	// The deferred cleanup runs restore again; it must be a no-op rather than
	// unlocking the thread a second time.
	namespace.restore(t)
}

// TestTCPolicyRuleKernelSurvivesSnapshotReplacement covers the join that reading
// fields and action from two separate dumps would have got wrong: a blackhole
// rule is replaced by a conditional routing rule at the same priority between
// observations. Neither is this process's rule, so no observation may report one.
func TestTCPolicyRuleKernelSurvivesSnapshotReplacement(t *testing.T) {
	enterTestNetworkNamespace(t)
	family := unix.AF_INET
	expected := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)

	// First state: our exact five fields, but a blackhole action.
	blackhole := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)
	blackhole.Type = unix.FR_ACT_BLACKHOLE
	if err := netlink.RuleAdd(blackhole); err != nil {
		t.Skipf("this kernel refused a blackhole rule carrying a table: %v", err)
	}
	entries, err := listTCPolicyRules(family, *expected)
	if err != nil {
		t.Fatalf("list policy rules before replacement: %v", err)
	}
	for _, rule := range entries {
		if rule.owned {
			t.Fatalf("the blackhole rule was claimed before replacement: %+v", entries)
		}
	}

	// Second state: same priority, routing action, but restricted by interface.
	if err = netlink.RuleDel(blackhole); err != nil {
		t.Fatalf("remove the blackhole rule: %v", err)
	}
	conditional := tcPolicyRuleFor(family, tcTestRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)
	conditional.IifName = "lo"
	if err = netlink.RuleAdd(conditional); err != nil {
		t.Fatalf("add the conditional rule: %v", err)
	}
	entries, err = listTCPolicyRules(family, *expected)
	if err != nil {
		t.Fatalf("list policy rules after replacement: %v", err)
	}
	for _, rule := range entries {
		if rule.owned {
			t.Fatalf("the conditional rule was claimed after replacement: %+v", entries)
		}
	}

	// Startup refuses either way, and removes neither.
	routing := testTCPolicyRouting(family)
	if _, err = inspectTCPolicyRoutingFamily(1, family, routing); err == nil {
		t.Fatal("inspect accepted a rule that belongs to neither observation")
	}
	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("list policy rules after inspect: %v", err)
	}
	for _, rule := range rules {
		if rule.Priority == tcPolicyRoutingPriority && rule.IifName == "lo" {
			return
		}
	}
	t.Fatal("the conditional rule was removed")
}
