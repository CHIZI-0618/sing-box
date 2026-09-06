//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// TestCheckRedirectRouteConflictSeesARouteOnAnotherInterface proves the
// conflict check actually inspects routes system-wide, not just on the
// loopback interface it also inspects addresses on — the case
// netlink.RouteList(nil, family)'s interface-index-zero filtering silently
// hid (see redirect_route.go's own comment on the fix).
func TestCheckRedirectRouteConflictSeesARouteOnAnotherInterface(t *testing.T) {
	enterTestNetworkNamespace(t)

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback: %v", err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("bring up loopback: %v", err)
	}

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "sbredirect0"
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: "sbredirect1"}
	if err = netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName("sbredirect0")
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	if err = netlink.LinkSetUp(self); err != nil {
		t.Fatalf("bring up veth: %v", err)
	}

	candidate := redirectIPv6Candidates[0]
	conflicting := &netlink.Route{
		LinkIndex: self.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IP(candidate.Addr().AsSlice()),
			Mask: net.CIDRMask(candidate.Bits(), candidate.Addr().BitLen()),
		},
	}
	if err = netlink.RouteAdd(conflicting); err != nil {
		t.Fatalf("add a conflicting route on a non-loopback interface: %v", err)
	}

	if err = checkRedirectRouteConflict(loopback.Attrs().Index, unix.AF_INET6, candidate); err == nil {
		t.Fatalf("checkRedirectRouteConflict missed a route on interface %s conflicting with %s", self.Attrs().Name, candidate)
	}
}
