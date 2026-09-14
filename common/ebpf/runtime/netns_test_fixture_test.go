//go:build with_ebpf && (linux || android)

package runtime

import (
	"os"
	goRuntime "runtime"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

type testNetworkNamespace struct {
	original     *os.File
	originalLink string
	isolatedLink string
	restored     bool
}

func enterTestNetworkNamespace(t *testing.T) *testNetworkNamespace {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("creating a network namespace requires root")
	}
	goRuntime.LockOSThread()
	unlockOnSkip := true
	defer func() {
		if unlockOnSkip {
			goRuntime.UnlockOSThread()
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
		t.Errorf("thread left in namespace %s, want %s; leaving the thread locked so the runtime discards it", current, n.originalLink)
		return
	}
	goRuntime.UnlockOSThread()
}
