//go:build with_ebpf && (linux || android)

package ebpf

import (
	"strings"
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/sys/unix"
)

// deliveryPairLeftBehind names the delivery veth ends still present, using the
// prefixes nextTCVethNames allocates from.
func deliveryPairLeftBehind(t *testing.T) []string {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("list the links in the namespace: %v", err)
	}
	var leftBehind []string
	for _, device := range links {
		name := device.Attrs().Name
		if strings.HasPrefix(name, "sbt") || strings.HasPrefix(name, "sbd") {
			leftBehind = append(leftBehind, name)
		}
	}
	return leftBehind
}

// TestCreateTCDeliveryLinkRemovesThePairWhenTheLookupFails covers the step
// between creating the delivery veth and having a handle on it.
//
// LinkAdd has already put the pair in the kernel by then. If the lookup that
// follows fails, the cleanup is the only thing that can remove it, and it can
// only remove what the delivery link holds — so the pair has to belong to the
// delivery link from the moment it exists rather than from the moment the
// lookup returns.
//
// The lookup is substituted; everything else is the real thing in a private
// network namespace.
func TestCreateTCDeliveryLinkRemovesThePairWhenTheLookupFails(t *testing.T) {
	enterTestNetworkNamespace(t)
	if leftBehind := deliveryPairLeftBehind(t); len(leftBehind) != 0 {
		t.Fatalf("a fresh namespace already carries delivery links %v", leftBehind)
	}
	dataPlane := &tcDataPlane{
		backend:  &commonEBPF.TCBackend{},
		priority: defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			// Not a "not found" error: the pair was just created, so a lookup
			// failing here is the kernel refusing to answer, not the link
			// being absent.
			linkByName: func(string) (netlink.Link, error) { return nil, unix.ENOBUFS },
		},
	}

	delivery, err := dataPlane.createTCDeliveryLink()
	if err == nil {
		t.Fatalf("a failed lookup was reported as success: %+v", delivery)
	}
	if !strings.Contains(err.Error(), "find TC eBPF redirect link") {
		t.Fatalf("error = %v, want the redirect lookup failure", err)
	}
	if leftBehind := deliveryPairLeftBehind(t); len(leftBehind) != 0 {
		t.Fatalf("the delivery pair %v was left behind with nothing owning it", leftBehind)
	}
}

// TestCreateTCDeliveryLinkRemovesThePairWhenAttachingFails covers the same
// property later in the same function, where the handles are already held, the
// sysctls have already been changed, and clsact has already been ensured: an
// empty backend has no delivery program loaded, so attachTCFilter is what
// fails, with "TC eBPF program is unavailable".
//
// Asserting that exact message, rather than just that err is non-nil, is what
// pins this test to the filter-attach step. Without it, an earlier step
// failing instead — the sysctl writes or ensureTCClsact, which this same
// function also runs before reaching the filter — would still turn the test
// green while covering none of what the comment above claims.
func TestCreateTCDeliveryLinkRemovesThePairWhenAttachingFails(t *testing.T) {
	enterTestNetworkNamespace(t)
	dataPlane := &tcDataPlane{backend: &commonEBPF.TCBackend{}, priority: defaultTCPriority}

	delivery, err := dataPlane.createTCDeliveryLink()
	if err == nil {
		t.Fatalf("attaching with no program loaded was reported as success: %+v", delivery)
	}
	if !strings.Contains(err.Error(), "TC eBPF program is unavailable") {
		t.Fatalf("error = %v, want the filter attach to be what failed", err)
	}
	if leftBehind := deliveryPairLeftBehind(t); len(leftBehind) != 0 {
		t.Fatalf("the delivery pair %v was left behind with nothing owning it", leftBehind)
	}
}
