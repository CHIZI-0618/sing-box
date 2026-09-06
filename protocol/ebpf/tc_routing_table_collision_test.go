//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// TestAllocateTCPolicyIdentifiersAvoidsARouteOnlyTable proves
// allocateTCPolicyIdentifiers actually sees a table that is in use only
// through a route, with no corresponding ip rule — the case its RuleList
// half was never going to catch, and its RouteList half could not either
// while it was scoped to interface index 0 and the main table only (see
// tc_routing.go's own comment on the fix).
func TestAllocateTCPolicyIdentifiersAvoidsARouteOnlyTable(t *testing.T) {
	enterTestNetworkNamespace(t)

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback: %v", err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("bring up loopback: %v", err)
	}

	occupied := &netlink.Route{
		LinkIndex: loopback.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(203, 0, 113, 0).To4(), Mask: net.CIDRMask(24, 32)},
		Table:     tcPolicyRoutingTable,
	}
	if err = netlink.RouteAdd(occupied); err != nil {
		t.Fatalf("occupy the default candidate table with a plain route: %v", err)
	}

	identifiers, err := allocateTCPolicyIdentifiers(loopback.Attrs().Index, []int{unix.AF_INET})
	if err != nil {
		t.Fatalf("allocate TC policy identifiers: %v", err)
	}
	if identifiers.table == tcPolicyRoutingTable {
		t.Fatalf(
			"allocateTCPolicyIdentifiers picked table %d, which a route (not just an ip rule) already occupies",
			tcPolicyRoutingTable,
		)
	}
}
