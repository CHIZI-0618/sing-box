//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

// TestTCLocalFilterHealthCheckDetectsAndRepairsExternalDeletion covers the
// ordinary local filter independently of the optional FakeIP ICMP filter.
func TestTCLocalFilterHealthCheckDetectsAndRepairsExternalDeletion(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newLoopbackTestTCBackend(t)

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbtclocalh0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbtclocalh1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbtclocalh0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(self); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}

	const priority = 2 // force clsact
	lock, err := acquireTCInterfaceLock("sbtclocalh0", self.Attrs().Index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		"sbtclocalh0",
		tcAttachmentState{
			index:   self.Attrs().Index,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{local: true},
		},
		false,
		priority,
		lock,
		true,
	)
	if err != nil {
		t.Fatalf("attach the interface: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.localFilter == nil {
		t.Fatal("the local egress filter was not attached")
	}
	if attachment.localICMPFilter != nil {
		t.Fatal("fakeip_icmp is disabled on this backend; its filter must not have been attached")
	}

	attached, err := attachment.filtersAttached(priority, backend)
	if err != nil {
		t.Fatalf("filtersAttached before breaking anything: %v", err)
	}
	if !attached {
		t.Fatal("filtersAttached reported unhealthy before anything was broken")
	}

	// Simulate the ordinary local egress filter itself vanishing on its
	// own -- an external `tc filter del`, or a kernel event this package
	// never observed -- leaving the Go-side pointer exactly as it is,
	// matching what a real external deletion actually leaves behind (it has
	// no way to reach into this process and clear it).
	if err = detachTCFilter(attachment.localFilter); err != nil {
		t.Fatalf("detach the local egress filter to simulate drift: %v", err)
	}

	attached, err = attachment.filtersAttached(priority, backend)
	if err != nil {
		t.Fatalf("filtersAttached: %v", err)
	}
	if attached {
		t.Fatal("filtersAttached reported this attachment healthy with the local egress filter missing")
	}

	staleFilter := attachment.localFilter
	dataPlane := &tcDataPlane{backend: backend, attachments: []*tcInterfaceAttachment{attachment}, priority: priority}
	if err = dataPlane.reconcile("sbtclocalh0", nil, nil); err != nil {
		t.Fatalf("reconcile did not repair the missing local egress filter: %v", err)
	}
	repaired := dataPlane.attachments[0]
	if repaired.localFilter == nil {
		t.Fatal("repair did not restore the local egress filter")
	}
	if repaired.localFilter == staleFilter {
		t.Fatal("repair kept the stale filter reference instead of replacing it with a freshly attached one")
	}
	attached, err = repaired.filtersAttached(priority, backend)
	if err != nil {
		t.Fatalf("filtersAttached after repair: %v", err)
	}
	if !attached {
		t.Fatal("filtersAttached still reports unhealthy immediately after repair")
	}
}
