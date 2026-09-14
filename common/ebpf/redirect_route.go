//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"slices"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// LocalRouteSet owns the local-table routes created for redirect token
// prefixes. Routes which already existed are validated but are not owned or
// removed by the set.
type LocalRouteSet struct {
	routes []netlink.Route
}

// SelectRedirectPrefix returns the first candidate which does not overlap an
// excluded prefix, interface address, or existing route. All candidates must
// belong to the address family selected by family.
func SelectRedirectPrefix(family int, candidates []netip.Prefix, excluded []netip.Prefix) (netip.Prefix, error) {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return netip.Prefix{}, E.Cause(err, "find loopback interface")
	}
	var conflictErr error
	for _, candidate := range candidates {
		if candidateFamily(candidate) != family {
			return netip.Prefix{}, E.New("redirect prefix address family mismatch: ", candidate)
		}
		var excludedConflict netip.Prefix
		for _, prefix := range excluded {
			if prefixesOverlap(candidate, prefix) {
				excludedConflict = prefix
				break
			}
		}
		if excludedConflict.IsValid() {
			conflictErr = E.Errors(conflictErr, E.New(
				"eBPF redirect address ", candidate,
				" conflicts with excluded range ", excludedConflict,
			))
			continue
		}
		if err = checkRedirectRouteConflict(loopback.Attrs().Index, family, candidate); err != nil {
			conflictErr = E.Errors(conflictErr, err)
			continue
		}
		return candidate, nil
	}
	if conflictErr == nil {
		return netip.Prefix{}, E.New("no redirect prefix candidates")
	}
	return netip.Prefix{}, conflictErr
}

// NewLocalRouteSet installs local-table routes for prefixes and returns their
// owner. On failure it removes every route installed by this call.
func NewLocalRouteSet(prefixes []netip.Prefix) (*LocalRouteSet, error) {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, E.Cause(err, "find loopback interface")
	}
	set := &LocalRouteSet{routes: make([]netlink.Route, 0, len(prefixes))}
	for _, prefix := range prefixes {
		route, owned, routeErr := addLocalRoute(loopback.Attrs().Index, prefix)
		if routeErr != nil {
			return nil, E.Errors(routeErr, set.Close())
		}
		if owned {
			set.routes = append(set.routes, route)
		}
	}
	return set, nil
}

// Close removes only routes owned by the set. Failed removals remain owned so
// a later Close call can retry them.
func (s *LocalRouteSet) Close() error {
	if s == nil || len(s.routes) == 0 {
		return nil
	}
	remaining := make([]netlink.Route, 0, len(s.routes))
	var routeErr error
	for index := len(s.routes) - 1; index >= 0; index-- {
		route := s.routes[index]
		err := netlink.RouteDel(&route)
		if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			routeErr = E.Errors(routeErr, err)
			remaining = append(remaining, route)
		}
	}
	slices.Reverse(remaining)
	s.routes = remaining
	return routeErr
}

// IsClosed reports whether the set has released all routes it owns.
func (s *LocalRouteSet) IsClosed() bool {
	return s == nil || len(s.routes) == 0
}

func addLocalRoute(loopbackIndex int, prefix netip.Prefix) (netlink.Route, bool, error) {
	family := candidateFamily(prefix)
	if family == unix.AF_UNSPEC {
		return netlink.Route{}, false, E.New("invalid eBPF redirect prefix: ", prefix)
	}
	route := netlink.Route{
		LinkIndex: loopbackIndex,
		Family:    family,
		Dst:       prefixIPNet(prefix),
		Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
	}
	if err := checkRedirectRouteConflict(loopbackIndex, family, prefix); err != nil {
		return netlink.Route{}, false, err
	}
	exists, err := localRouteExists(family, prefix)
	if err != nil {
		return netlink.Route{}, false, err
	}
	if exists {
		return route, false, nil
	}
	if err = netlink.RouteAdd(&route); err != nil {
		if errors.Is(err, unix.EEXIST) {
			exists, listErr := localRouteExists(family, prefix)
			if listErr == nil && exists {
				return route, false, nil
			}
		}
		return netlink.Route{}, false, E.Cause(err, "add local route for ", prefix)
	}
	return route, true, nil
}

func checkRedirectRouteConflict(loopbackIndex int, family int, prefix netip.Prefix) error {
	addresses, err := netlink.AddrList(nil, family)
	if err != nil {
		return E.Cause(err, "list interface addresses for eBPF redirect route")
	}
	for _, address := range addresses {
		if address.LinkIndex == loopbackIndex && prefix.Addr().Is4() {
			continue
		}
		addressPrefix, loaded := prefixFromIPNet(address.IPNet)
		if loaded && prefixesOverlap(prefix, addressPrefix) {
			return E.New("eBPF redirect address ", prefix,
				" conflicts with interface address ", addressPrefix)
		}
	}
	// This has to see every table, not just the main one. RT_FILTER_TABLE with
	// RT_TABLE_UNSPEC requests all tables and avoids RouteList's implicit output
	// interface filter.
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return E.Cause(err, "list routes for eBPF redirect address")
	}
	minimumRouteBits := 8
	if prefix.Addr().Is6() {
		minimumRouteBits = 7
	}
	for _, route := range routes {
		if route.LinkIndex == loopbackIndex && prefix.Addr().Is4() {
			continue
		}
		routePrefix, loaded := prefixFromIPNet(route.Dst)
		if !loaded || routePrefix.Bits() < minimumRouteBits {
			continue
		}
		if route.LinkIndex == loopbackIndex && route.Type == unix.RTN_LOCAL && routePrefix == prefix {
			continue
		}
		if prefixesOverlap(prefix, routePrefix) {
			return E.New("eBPF redirect address ", prefix,
				" conflicts with route ", routePrefix)
		}
	}
	return nil
}

func localRouteExists(family int, prefix netip.Prefix) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: unix.RT_TABLE_LOCAL},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return false, E.Cause(err, "list local routes")
	}
	for _, route := range routes {
		if route.Type == unix.RTN_LOCAL && routePrefixContains(route.Dst, prefix) {
			return true, nil
		}
	}
	return false, nil
}

func candidateFamily(prefix netip.Prefix) int {
	if !prefix.IsValid() {
		return unix.AF_UNSPEC
	}
	if prefix.Addr().Is4() {
		return unix.AF_INET
	}
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		return unix.AF_INET6
	}
	return unix.AF_UNSPEC
}

func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	prefix = prefix.Masked()
	return &net.IPNet{
		IP:   net.IP(prefix.Addr().AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func routePrefixContains(destination *net.IPNet, prefix netip.Prefix) bool {
	destinationPrefix, loaded := prefixFromIPNet(destination)
	if !loaded {
		return false
	}
	prefix = prefix.Masked()
	if destinationPrefix.Addr().BitLen() != prefix.Addr().BitLen() || destinationPrefix.Bits() > prefix.Bits() {
		return false
	}
	return destinationPrefix.Contains(prefix.Addr())
}

func prefixFromIPNet(network *net.IPNet) (netip.Prefix, bool) {
	if network == nil {
		return netip.Prefix{}, false
	}
	bits, addressBits := network.Mask.Size()
	address, loaded := netip.AddrFromSlice(network.IP)
	if !loaded || bits < 0 {
		return netip.Prefix{}, false
	}
	address = address.Unmap()
	if address.BitLen() != addressBits {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, bits).Masked(), true
}

func prefixesOverlap(left netip.Prefix, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() {
		return false
	}
	left = left.Masked()
	right = right.Masked()
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}
