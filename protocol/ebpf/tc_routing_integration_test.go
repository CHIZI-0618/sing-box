//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"os"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

func TestTCPolicyRoutingIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_INTEGRATION=1 to run eBPF integration tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("eBPF integration test requires root")
	}
	routing, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = routing.Close()
		}
	})
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		// routing.{table,mark,priority} are what allocateTCPolicyIdentifiers
		// actually picked for this run, not necessarily the preferred
		// defaults (tcPolicyRoutingTable/commonEBPF.DefaultTCRoutingMark):
		// the mark allocator in particular starts from its own highest bit
		// (30) and only reaches DefaultTCRoutingMark's bit (29) if 30 is
		// already taken by something else, which on a clean host it never
		// is. Asserting against the fixed defaults instead of the values
		// startTCPolicyRouting actually returned is what let this test pass
		// while checking properties of a rule that was never installed.
		expectedRoutes := tcPolicyRoutesForTable(loopback.Attrs().Index, family, routing.table)
		routes, listErr := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: routing.table},
			netlink.RT_FILTER_TABLE,
		)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(routes) != len(expectedRoutes) {
			t.Fatalf("unexpected route count for family %d: %d", family, len(routes))
		}
		for _, route := range routes {
			if !matchesTCPolicyRoute(route, expectedRoutes) {
				t.Fatalf("unexpected route for family %d: %+v", family, route)
			}
		}
		entries, listErr := listTCPolicyRules(family, *tcPolicyRuleFor(family, routing.mark, routing.table, routing.priority))
		if listErr != nil {
			t.Fatal(listErr)
		}
		matched := false
		for _, entry := range entries {
			if entry.owned {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("missing policy rule for family %d", family)
		}
	}
	if err = netlink.RouteDel(&routing.routes[0]); err != nil {
		t.Fatal(err)
	}
	if err = netlink.RuleDel(routing.rules[0]); err != nil {
		t.Fatal(err)
	}
	changed, err := routing.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("missing policy routing state was not restored")
	}
	changed, err = routing.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("complete policy routing state was changed")
	}
	if err = routing.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, listErr := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: routing.table},
			netlink.RT_FILTER_TABLE,
		)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(routes) != 0 {
			t.Fatalf("policy routes remain for family %d", family)
		}
	}
}
