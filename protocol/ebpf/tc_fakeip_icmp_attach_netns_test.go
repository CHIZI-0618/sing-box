//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

// newRealFakeIPICMPBackend prepares a real TC eBPF backend with fakeip_icmp
// enabled, the way protocol/ebpf's own startup does — no injected hooks, no
// substituted maps, so a failure here means the real Go-to-kernel path is
// broken, not a test double.
func newRealFakeIPICMPBackend(t *testing.T) *commonEBPF.TCBackend {
	t.Helper()
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{
		EnableTCP:  true,
		FakeIPIPv4: netip.MustParsePrefix("198.18.0.0/15"),
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort:    23456,
		EnableLocal:     true,
		EnableShared:    true,
		EnableIPv4:      true,
		EnableTCP:       true,
		Policy:          policy,
		FakeIPICMPReply: true,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	return backend
}

// TestAttachTCInterfaceAddsTheFakeIPICMPFilterWhenEnabled attaches to a real
// veth in a private network namespace with a real fakeip_icmp-enabled
// backend, and checks by real netlink filter list — not by inspecting the Go
// struct — that both the ordinary local filter and the fakeip_icmp local
// reply filter land on the interface, and that closing the attachment
// removes both along with the interface lock.
//
// Priority 2 forces the clsact path deterministically: attachTCInterfaceWithLock
// only attempts TCX at priority 1, and this test means to check the filter
// list, not whichever of the two paths this kernel happens to prefer.
func TestAttachTCInterfaceAddsTheFakeIPICMPFilterWhenEnabled(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	const priority = 2
	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbicmp0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbicmp1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	link, err := netlink.LinkByName("sbicmp0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}

	lock, err := acquireTCInterfaceLock("sbicmp0", link.Attrs().Index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		"sbicmp0",
		tcAttachmentState{
			index:   link.Attrs().Index,
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

	attached, err := tcFilterAttached(link, netlink.HANDLE_MIN_EGRESS, "sb_tc_local", tcLocalFilterHandle, priority)
	if err != nil {
		t.Fatalf("inspect the local filter: %v", err)
	}
	if !attached {
		t.Fatal("the ordinary local egress filter was not attached")
	}
	icmpAttached, err := tcFilterAttached(link, netlink.HANDLE_MIN_EGRESS, "sb_icmp_local", tcLocalICMPReplyFilterHandle, priority)
	if err != nil {
		t.Fatalf("inspect the fakeip_icmp local reply filter: %v", err)
	}
	if !icmpAttached {
		t.Fatal("the fakeip_icmp local reply filter was not attached alongside the ordinary one")
	}

	if err = attachment.Close(); err != nil {
		t.Fatalf("close the attachment: %v", err)
	}
	if attached, err = tcFilterAttached(link, netlink.HANDLE_MIN_EGRESS, "sb_tc_local", tcLocalFilterHandle, priority); err != nil {
		t.Fatalf("inspect the local filter after close: %v", err)
	} else if attached {
		t.Fatal("the ordinary local egress filter survived Close")
	}
	if icmpAttached, err = tcFilterAttached(link, netlink.HANDLE_MIN_EGRESS, "sb_icmp_local", tcLocalICMPReplyFilterHandle, priority); err != nil {
		t.Fatalf("inspect the fakeip_icmp local reply filter after close: %v", err)
	} else if icmpAttached {
		t.Fatal("the fakeip_icmp local reply filter survived Close")
	}
	if tcLockHeld(t, link.Attrs().Index) {
		t.Fatal("the interface lock survived Close")
	}
}

// TestAttachTCInterfaceSkipsTheFakeIPICMPFilterWhenDisabled is the control:
// the same real attach, against a backend that never requested
// fakeip_icmp=reply, adds only the ordinary filter.
func TestAttachTCInterfaceSkipsTheFakeIPICMPFilterWhenDisabled(t *testing.T) {
	enterTestNetworkNamespace(t)
	policy, err := commonEBPF.CompilePolicy(commonEBPF.PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort: 23457,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	const priority = 2
	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbicmp2"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbicmp3"}
	if err = netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	link, err := netlink.LinkByName("sbicmp2")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}
	lock, err := acquireTCInterfaceLock("sbicmp2", link.Attrs().Index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		"sbicmp2",
		tcAttachmentState{
			index:   link.Attrs().Index,
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

	if icmpAttached, err := tcFilterAttached(link, netlink.HANDLE_MIN_EGRESS, "sb_icmp_local", tcLocalICMPReplyFilterHandle, priority); err != nil {
		t.Fatalf("inspect the fakeip_icmp local reply filter: %v", err)
	} else if icmpAttached {
		t.Fatal("the fakeip_icmp local reply filter was attached without fakeip_icmp=reply configured")
	}
}
