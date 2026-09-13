//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"

	"github.com/sagernet/netlink"
)

// TestInterfaceHasGlobalIPv6Route drives interfaceHasGlobalIPv6Route against a
// real veth in a private network namespace: link-local only, then a global
// address plus a real default route, so the two states this check actually
// has to distinguish (fakeip_icmp will or will not reach the wire) are both
// exercised against the real kernel routing table rather than a mock.
func TestInterfaceHasGlobalIPv6Route(t *testing.T) {
	enterTestNetworkNamespace(t)

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbicmprt0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbicmprt1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbicmprt0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(self); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}

	// A fresh veth carries only its auto-assigned link-local address and no
	// routes beyond the link-local /64 the kernel installs automatically;
	// that link-local-only route must not count as "routable".
	routable, err := interfaceHasGlobalIPv6Route(self)
	if err != nil {
		t.Fatalf("inspect routes before any global route exists: %v", err)
	}
	if routable {
		t.Fatal("interfaceHasGlobalIPv6Route = true with only a link-local route present")
	}

	globalAddress := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}}
	if err = netlink.AddrAdd(self, globalAddress); err != nil {
		t.Fatalf("assign a global address: %v", err)
	}
	// The address's own /64 is itself a global-scope route, not just a
	// default route, confirming the check does not require specifically a
	// default route (Dst == nil) to recognize a usable path.
	routable, err = interfaceHasGlobalIPv6Route(self)
	if err != nil {
		t.Fatalf("inspect routes after a global address exists: %v", err)
	}
	if !routable {
		t.Fatal("interfaceHasGlobalIPv6Route = false with a global-scope route present")
	}

	if err = netlink.AddrDel(self, globalAddress); err != nil {
		t.Fatalf("remove the global address: %v", err)
	}
	defaultRoute := &netlink.Route{
		LinkIndex: self.Attrs().Index,
		Gw:        net.ParseIP("fe80::1"),
	}
	if err = netlink.RouteAdd(defaultRoute); err != nil {
		t.Fatalf("add a default route: %v", err)
	}
	// A plain default route (Dst == nil) is exactly what ordinary IPv4 FakeIP
	// interception already relies on; IPv6 must accept the same shape.
	routable, err = interfaceHasGlobalIPv6Route(self)
	if err != nil {
		t.Fatalf("inspect routes after a default route exists: %v", err)
	}
	if !routable {
		t.Fatal("interfaceHasGlobalIPv6Route = false with a default route present")
	}
}
