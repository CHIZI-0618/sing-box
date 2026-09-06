//go:build with_ebpf && (linux || android)

package ebpf

import (
	"github.com/sagernet/netlink"

	E "github.com/sagernet/sing/common/exceptions"
)

// warnIfLocalFakeIPICMPIPv6Unroutable is a diagnostic only: fakeip_icmp=reply
// for local IPv6 depends on ordinary routing actually sending an IPv6 packet
// out the local TC interface for local_reply's egress classifier to see it
// at all (see docs/configuration/inbound/ebpf.md's fakeip_icmp section).
// Without any non-link-local IPv6 route on that interface — not necessarily
// one that matches the FakeIP prefix itself, a default route already
// satisfies this, the same way it does for IPv4 — a local ping to the FakeIP
// range fails at the kernel's own route lookup before ever reaching this
// object, and would otherwise look like an unexplained timeout with nothing
// in the log to point at the real cause. This never blocks startup or
// reconciliation: unlike local.data_plane=cgroup, which can never support
// fakeip_icmp regardless of the network, missing IPv6 connectivity here is
// ordinary transient network state that can resolve itself.
func (i *Inbound) warnIfLocalFakeIPICMPIPv6Unroutable(localInterface string) {
	if localInterface == "" || !i.fakeIPICMPReply || !i.localIPv6 || !i.fakeIPIPv6Prefix.IsValid() {
		return
	}
	link, err := netlink.LinkByName(localInterface)
	if err != nil {
		// The topology warning already covers a local interface that cannot
		// be resolved; this check has nothing further to add.
		return
	}
	routable, err := interfaceHasGlobalIPv6Route(link)
	if err != nil {
		i.interfaceWarnings.fakeIPICMPRoute.warn(
			i.logger, "inspect local IPv6 route for fakeip_icmp on interface ", localInterface, ": ", err,
		)
		return
	}
	if !routable {
		i.interfaceWarnings.fakeIPICMPRoute.warn(
			i.logger,
			"fakeip_icmp=reply has no IPv6 route out local interface ", localInterface,
			"; a local IPv6 ping to the FakeIP range will not be answered until this host has real IPv6 connectivity",
		)
	}
}

// interfaceHasGlobalIPv6Route reports whether the given interface carries at
// least one IPv6 route that is not confined to the link-local scope,
// including a plain default route (Dst == nil, exactly as ordinary IPv4
// FakeIP interception already relies on). It deliberately does not require a
// route matching the FakeIP prefix specifically: FakeIP addresses are never
// treated specially by the host's own routing, so whatever route would carry
// any other globally-routed IPv6 destination out this interface is exactly
// what a FakeIP destination would follow too.
//
// The interface is passed as a resolved netlink.Link, not an index, so this
// filters server-side through netlink.RouteList's own link argument.
// netlink.RouteList(nil, family) looks like it should list every route
// regardless of interface, but its filter mask always includes RT_FILTER_OIF
// even when the link argument is nil, which then compares against a zero
// LinkIndex — silently returning next to nothing instead of everything.
func interfaceHasGlobalIPv6Route(link netlink.Link) (bool, error) {
	routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
	if err != nil {
		return false, E.Cause(err, "list IPv6 routes")
	}
	for _, route := range routes {
		if route.Dst == nil {
			return true, nil
		}
		prefix, loaded := prefixFromIPNet(route.Dst)
		if !loaded {
			continue
		}
		if !prefix.Addr().IsLinkLocalUnicast() && !prefix.Addr().IsLinkLocalMulticast() {
			return true, nil
		}
	}
	return false, nil
}
