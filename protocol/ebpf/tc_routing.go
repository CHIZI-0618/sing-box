//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	// Preferred values keep diagnostics stable; allocation below always checks
	// the live policy database before using them.
	tcPolicyRoutingTable    = 2027
	tcPolicyRoutingPriority = 8999
	tcPolicyTableMin        = 2000
	tcPolicyTableMax        = 32766
	tcPolicyPriorityMin     = 8000
	tcPolicyPriorityMax     = 32000
)

type tcPolicyRouting struct {
	lock     io.Closer
	mark     uint32
	table    int
	priority int
	families []int
	routes   []netlink.Route
	rules    []*netlink.Rule
}

type tcStalePolicyRouting struct {
	routes []netlink.Route
	rule   *netlink.Rule
}

func startTCPolicyRouting(enableIPv6 bool) (*tcPolicyRouting, error) {
	lock, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: "@sing-box-ebpf-tc-routing",
		Net:  "unixgram",
	})
	if err != nil {
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, E.New("TC eBPF policy routing is already managed by another inbound")
		}
		return nil, E.Cause(err, "lock TC eBPF policy routing")
	}
	routing := &tcPolicyRouting{lock: lock}
	cleanup := func(startErr error) (*tcPolicyRouting, error) {
		closeErr := routing.Close()
		if !routing.IsClosed() {
			return routing, E.Errors(startErr, closeErr)
		}
		return nil, E.Errors(startErr, closeErr)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return cleanup(E.Cause(err, "find loopback interface for TC eBPF policy routing"))
	}
	families := []int{unix.AF_INET}
	if enableIPv6 {
		families = append(families, unix.AF_INET6)
	}
	routing.families = families
	identifiers, err := allocateTCPolicyIdentifiers(loopback.Attrs().Index, families)
	if err != nil {
		return cleanup(err)
	}
	routing.mark = identifiers.mark
	routing.table = identifiers.table
	routing.priority = identifiers.priority
	staleRouting := make([]tcStalePolicyRouting, 0, len(families))
	for _, family := range families {
		stale, inspectErr := inspectTCPolicyRoutingFamily(loopback.Attrs().Index, family, routing)
		if inspectErr != nil {
			return cleanup(inspectErr)
		}
		staleRouting = append(staleRouting, stale)
	}
	for _, stale := range staleRouting {
		if err = removeStaleTCPolicyRouting(stale); err != nil {
			return cleanup(err)
		}
	}
	for _, family := range families {
		for _, route := range tcPolicyRoutesForTable(loopback.Attrs().Index, family, routing.table) {
			if err = netlink.RouteAdd(&route); err != nil {
				return cleanup(E.Cause(err, "add TC eBPF local route ", route.Dst))
			}
			routing.routes = append(routing.routes, route)
		}
	}
	for _, family := range families {
		rule := tcPolicyRuleFor(family, routing.mark, routing.table, routing.priority)
		if err = netlink.RuleAdd(rule); err != nil {
			return cleanup(E.Cause(err, "add TC eBPF policy rule"))
		}
		routing.rules = append(routing.rules, rule)
	}
	return routing, nil
}

func (r *tcPolicyRouting) ensure() (bool, error) {
	if r == nil {
		return false, E.New("TC eBPF policy routing is unavailable")
	}
	changed := false
	for _, family := range r.families {
		expectedRoutes := make([]netlink.Route, 0, len(r.routes))
		for _, route := range r.routes {
			if route.Family == family {
				expectedRoutes = append(expectedRoutes, route)
			}
		}
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: r.table},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return changed, E.Cause(err, "inspect TC eBPF routing table")
		}
		for _, route := range routes {
			if !matchesTCPolicyRoute(route, expectedRoutes) {
				return changed, E.New("TC eBPF routing table ", r.table, " is already in use")
			}
		}
		for index := range expectedRoutes {
			expected := &expectedRoutes[index]
			if slices.ContainsFunc(routes, func(route netlink.Route) bool {
				return matchesTCPolicyRoute(route, []netlink.Route{*expected})
			}) {
				continue
			}
			if err = netlink.RouteAdd(expected); err != nil {
				return changed, E.Cause(err, "restore TC eBPF local route ", expected.Dst)
			}
			changed = true
		}

		expectedRule := tcPolicyRuleFor(family, r.mark, r.table, r.priority)
		entries, err := listTCPolicyRules(family, *expectedRule)
		if err != nil {
			return changed, E.Cause(err, "inspect TC eBPF policy rules")
		}
		rulePresent := false
		for _, rule := range entries {
			if rule.owned {
				rulePresent = true
				continue
			}
			if rule.table == r.table {
				return changed, E.New("TC eBPF routing table ", r.table, " is referenced by another policy rule")
			}
		}
		if !rulePresent {
			if err = netlink.RuleAdd(expectedRule); err != nil {
				return changed, E.Cause(err, "restore TC eBPF policy rule")
			}
			changed = true
		}
	}
	return changed, nil
}

func inspectTCPolicyRoutingFamily(loopbackIndex int, family int, routing *tcPolicyRouting) (tcStalePolicyRouting, error) {
	expectedRoutes := tcPolicyRoutesForTable(loopbackIndex, family, routing.table)
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: routing.table},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return tcStalePolicyRouting{}, E.Cause(err, "inspect TC eBPF routing table")
	}
	staleRoutes := make([]netlink.Route, 0, len(routes))
	for index := range routes {
		if !matchesTCPolicyRoute(routes[index], expectedRoutes) {
			return tcStalePolicyRouting{}, E.New("TC eBPF routing table ", routing.table, " is already in use")
		}
		staleRoutes = append(staleRoutes, routes[index])
	}
	expectedRule := tcPolicyRuleFor(family, routing.mark, routing.table, routing.priority)
	entries, err := listTCPolicyRules(family, *expectedRule)
	if err != nil {
		return tcStalePolicyRouting{}, E.Cause(err, "inspect TC eBPF policy rules")
	}
	staleRule := false
	for _, rule := range entries {
		if rule.owned {
			staleRule = true
			continue
		}
		if rule.table == routing.table {
			return tcStalePolicyRouting{}, E.New("TC eBPF routing table ", routing.table, " is referenced by another policy rule")
		}
	}
	stale := tcStalePolicyRouting{routes: staleRoutes}
	if staleRule {
		stale.rule = expectedRule
	}
	return stale, nil
}

func removeStaleTCPolicyRouting(stale tcStalePolicyRouting) error {
	if stale.rule != nil {
		if err := netlink.RuleDel(stale.rule); !tcPolicyDeleteIgnored(err) {
			return E.Cause(err, "remove stale TC eBPF policy rule")
		}
	}
	for index := range slices.Backward(stale.routes) {
		if err := netlink.RouteDel(&stale.routes[index]); !tcPolicyDeleteIgnored(err) {
			return E.Cause(err, "remove stale TC eBPF local route")
		}
	}
	return nil
}

func tcPolicyRoutes(loopbackIndex int, family int) []netlink.Route {
	return tcPolicyRoutesForTable(loopbackIndex, family, tcPolicyRoutingTable)
}

func tcPolicyRoutesForTable(loopbackIndex int, family int, table int) []netlink.Route {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	if family == unix.AF_INET6 {
		prefixes = []netip.Prefix{
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		}
	}
	scope := netlink.Scope(unix.RT_SCOPE_HOST)
	if family == unix.AF_INET6 {
		scope = netlink.Scope(unix.RT_SCOPE_UNIVERSE)
	}
	routes := make([]netlink.Route, 0, len(prefixes))
	for _, prefix := range prefixes {
		routes = append(routes, netlink.Route{
			LinkIndex: loopbackIndex,
			Family:    family,
			Dst: &net.IPNet{
				IP:   net.IP(prefix.Addr().AsSlice()),
				Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
			},
			Scope:    scope,
			Table:    table,
			Type:     unix.RTN_LOCAL,
			Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC),
		})
	}
	return routes
}

func tcPolicyRule(family int) *netlink.Rule {
	return tcPolicyRuleFor(family, commonEBPF.DefaultTCRoutingMark, tcPolicyRoutingTable, tcPolicyRoutingPriority)
}

func tcPolicyRuleFor(family int, mark uint32, table, priority int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = priority
	rule.Family = family
	rule.Table = table
	rule.Mark = mark
	rule.MarkSet = true
	rule.Mask = int(mark)
	return rule
}

type tcPolicyIdentifiers struct {
	mark     uint32
	table    int
	priority int
}

func allocateTCPolicyIdentifiers(loopbackIndex int, families []int) (tcPolicyIdentifiers, error) {
	usedTables := make(map[int]bool)
	usedPriorities := make(map[int]bool)
	var usedMarkBits uint32
	allFamilies := []int{unix.AF_INET, unix.AF_INET6}
	for _, family := range allFamilies {
		// This has to see every table in use, not just the main one: the
		// candidate table numbers this function picks from never include the
		// main table, so a collision only ever exists in some other,
		// already-used table. netlink.RouteList(nil, family) looks like it
		// would show that, but two of its default behaviors work against it
		// here: its filter mask always includes RT_FILTER_OIF even without a
		// link argument, comparing against a zero LinkIndex and silently
		// returning next to nothing; and even past that, its default scope is
		// the main table only. RT_FILTER_TABLE with Table: RT_TABLE_UNSPEC
		// asks for every table instead, and a non-nil empty filter avoids a
		// nil-pointer panic routeHandle takes an actual nil filter into.
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		if err != nil {
			if family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)) {
				continue
			}
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF routes")
		}
		for _, route := range routes {
			if route.Table > 0 {
				usedTables[route.Table] = true
			}
		}
		rules, err := netlink.RuleList(family)
		if err != nil {
			if family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)) {
				continue
			}
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF policy rules")
		}
		for _, rule := range rules {
			if rule.Table > 0 {
				usedTables[rule.Table] = true
			}
			if rule.Priority > 0 {
				usedPriorities[rule.Priority] = true
			}
			usedMarkBits |= tcPolicyRuleMarkBits(rule)
		}
	}
	preferred := tcPolicyIdentifiers{
		mark:     commonEBPF.DefaultTCRoutingMark,
		table:    tcPolicyRoutingTable,
		priority: tcPolicyRoutingPriority,
	}
	managed := true
	managedStateFound := false
	for _, family := range families {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: preferred.table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF policy state")
		}
		expectedRoutes := tcPolicyRoutesForTable(loopbackIndex, family, preferred.table)
		for _, route := range routes {
			if !matchesTCPolicyRoute(route, expectedRoutes) {
				managed = false
				break
			}
			managedStateFound = true
		}
		entries, err := listTCPolicyRules(family, *tcPolicyRuleFor(family, preferred.mark, preferred.table, preferred.priority))
		if err != nil {
			return tcPolicyIdentifiers{}, E.Cause(err, "inspect TC eBPF policy state")
		}
		for _, rule := range entries {
			if rule.table != preferred.table {
				continue
			}
			if rule.owned {
				managedStateFound = true
				break
			}
			managed = false
			break
		}
	}
	if managed && managedStateFound {
		return preferred, nil
	}
	identifiers := tcPolicyIdentifiers{}
	identifiers.mark = selectTCPolicyMark(usedMarkBits)
	if identifiers.mark == 0 {
		return tcPolicyIdentifiers{}, E.New(
			"no unused TC eBPF routing mark is available (reserved mark bits 0x",
			strconv.FormatUint(uint64(usedMarkBits), 16), ")",
		)
	}
	for table := tcPolicyRoutingTable; table <= tcPolicyTableMax; table++ {
		if !usedTables[table] {
			identifiers.table = table
			break
		}
	}
	if identifiers.table == 0 {
		for table := tcPolicyTableMin; table < tcPolicyRoutingTable; table++ {
			if !usedTables[table] {
				identifiers.table = table
				break
			}
		}
	}
	if identifiers.table == 0 {
		return tcPolicyIdentifiers{}, E.New("no unused TC eBPF routing table is available")
	}
	for priority := tcPolicyRoutingPriority; priority <= tcPolicyPriorityMax; priority++ {
		if !usedPriorities[priority] {
			identifiers.priority = priority
			break
		}
	}
	if identifiers.priority == 0 {
		for priority := tcPolicyPriorityMin; priority < tcPolicyRoutingPriority; priority++ {
			if !usedPriorities[priority] {
				identifiers.priority = priority
				break
			}
		}
	}
	if identifiers.priority == 0 {
		return tcPolicyIdentifiers{}, E.New("no unused TC eBPF policy priority is available")
	}
	return identifiers, nil
}

func selectTCPolicyMark(usedMarkBits uint32) uint32 {
	// Keep the mark in the positive int range used by netlink.Rule.Mask on
	// 32-bit systems. Prefer the conventional high bits, then use lower bits
	// only when the host's policy rules already occupy all high bits.
	for bit := uint(30); ; bit-- {
		candidate := uint32(1) << bit
		if usedMarkBits&candidate == 0 {
			return candidate
		}
		if bit == 0 {
			break
		}
	}
	return 0
}

func tcPolicyRuleMarkBits(rule netlink.Rule) uint32 {
	if rule.Mask >= 0 {
		// Mark bits outside FRA_FWMASK do not participate in the rule match.
		return uint32(rule.Mask)
	}
	if rule.MarkSet || rule.Mark != 0 {
		// A fwmark rule without FRA_FWMASK matches the full mark value.
		return ^uint32(0)
	}
	return 0
}

func matchesTCPolicyRoute(route netlink.Route, expected []netlink.Route) bool {
	for _, candidate := range expected {
		if route.LinkIndex == candidate.LinkIndex &&
			route.Family == candidate.Family &&
			route.Table == candidate.Table &&
			route.Type == candidate.Type &&
			route.Scope == candidate.Scope &&
			routeDestination(route.Dst) == routeDestination(candidate.Dst) {
			return true
		}
	}
	return false
}

func routeDestination(destination *net.IPNet) netip.Prefix {
	if destination == nil {
		return netip.Prefix{}
	}
	bits, addressBits := destination.Mask.Size()
	address, loaded := netip.AddrFromSlice(destination.IP)
	if !loaded || bits < 0 {
		return netip.Prefix{}
	}
	address = address.Unmap()
	if address.BitLen() != addressBits {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(address, bits).Masked()
}

// tcPolicyRuleEntry is one rule as the kernel dumped it, carrying the two things
// the callers need: whether this process may claim it, and which table it points
// at so an unclaimable rule on this table can be reported as a conflict.
type tcPolicyRuleEntry struct {
	priority int
	table    int
	owned    bool
}

// tcPolicyRuleAttributeProtocol is FRA_PROTOCOL. The kernel records which
// program installed a rule and emits it for every rule; the vendored netlink
// constants do not name it.
const tcPolicyRuleAttributeProtocol = 21

// listTCPolicyRules dumps the policy rules of a family and decides ownership
// from each dump message on its own.
//
// netlink.RuleList cannot answer this. It drops the rule action:
// fib_rule_hdr.action overlays rtmsg.rtm_type in the message header and the list
// parser only walks attributes, so a blackhole rule reads back looking exactly
// like this process's own. Reading the action from a second dump and joining it
// to the first by priority is not a fix either — between the two dumps a rule
// can be replaced, and the fields of the old one would be joined to the action
// of the new one, which can manufacture an ownership claim over two rules that
// each should have been rejected. Fields and action therefore come out of the
// same message.
func listTCPolicyRules(family int, expected netlink.Rule) ([]tcPolicyRuleEntry, error) {
	request := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	request.AddData(nl.NewIfInfomsg(family))
	messages, err := request.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil {
		return nil, err
	}
	entries := make([]tcPolicyRuleEntry, 0, len(messages))
	for _, message := range messages {
		entry, ok, parseErr := parseTCPolicyRuleMessage(message, expected)
		if parseErr != nil {
			return nil, parseErr
		}
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// parseTCPolicyRuleMessage turns one RTM_NEWRULE message into an entry, and
// reports whether the message was long enough to be one at all.
//
// Ownership is decided by rejection: the message has to carry the action, the
// selector and the attributes this process installs, and nothing else. An
// attribute this code does not set is a condition someone else attached, and an
// attribute a future kernel adds is unknown rather than harmless, so both disown
// the rule. Values are compared as the kernel sent them, in uint32, so no
// sentinel has to survive a conversion to int — the reason a high-bit option
// cannot be mistaken for "absent" on a 32-bit build.
func parseTCPolicyRuleMessage(message []byte, expected netlink.Rule) (tcPolicyRuleEntry, bool, error) {
	if len(message) < unix.SizeofRtMsg {
		return tcPolicyRuleEntry{}, false, nil
	}
	native := nl.NativeEndian()
	header := nl.DeserializeRtMsg(message)
	attributes, err := nl.ParseRouteAttr(message[header.Len():])
	if err != nil {
		return tcPolicyRuleEntry{}, false, err
	}
	entry := tcPolicyRuleEntry{priority: -1, table: int(header.Table)}
	owned := int(header.Family) == expected.Family &&
		header.Type == nl.FR_ACT_TO_TBL &&
		header.Flags&netlink.FibRuleInvert == 0 &&
		header.Tos == 0 && header.Src_len == 0 && header.Dst_len == 0
	var mark, mask int64 = -1, -1
	// The attributes read below are 32-bit; a short one is malformed and reading
	// it would be out of bounds, so it disowns the rule instead.
	word := func(value []byte) (uint32, bool) {
		if len(value) < 4 {
			owned = false
			return 0, false
		}
		return native.Uint32(value[:4]), true
	}
	for _, attribute := range attributes {
		value := attribute.Value
		switch attribute.Attr.Type {
		case tcPolicyRuleAttributeProtocol:
			// Informational, present on every rule, and a single byte rather than
			// a word, so it is deliberately not length-checked here.
		case unix.RTA_TABLE:
			if table, ok := word(value); ok {
				entry.table = int(table)
			}
		case nl.FRA_PRIORITY:
			if priority, ok := word(value); ok {
				entry.priority = int(priority)
			}
		case nl.FRA_FWMARK:
			if fwmark, ok := word(value); ok {
				mark = int64(fwmark)
			}
		case nl.FRA_FWMASK:
			if fwmask, ok := word(value); ok {
				mask = int64(fwmask)
			}
		case nl.FRA_SUPPRESS_PREFIXLEN, nl.FRA_SUPPRESS_IFGROUP:
			// Emitted for every rule whether or not suppression is configured, so
			// presence means nothing and the value has to be read: anything other
			// than the all-ones sentinel is a real suppression setting.
			if suppress, ok := word(value); ok && suppress != ^uint32(0) {
				owned = false
			}
		default:
			owned = false
		}
	}
	entry.owned = owned &&
		entry.priority == expected.Priority &&
		entry.table == expected.Table &&
		mark == int64(expected.Mark) &&
		mask == int64(expected.Mask)
	return entry, true, nil
}

func tcPolicyDeleteIgnored(err error) bool {
	return err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
}

func (r *tcPolicyRouting) IsClosed() bool {
	return r == nil || len(r.rules) == 0 && len(r.routes) == 0 && r.lock == nil
}

func (r *tcPolicyRouting) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	for index := len(r.rules) - 1; index >= 0; index-- {
		if err := netlink.RuleDel(r.rules[index]); !tcPolicyDeleteIgnored(err) {
			closeErr = E.Errors(closeErr, err)
		} else {
			r.rules = slices.Delete(r.rules, index, index+1)
		}
	}
	if len(r.rules) != 0 {
		return closeErr
	}
	for index := len(r.routes) - 1; index >= 0; index-- {
		if err := netlink.RouteDel(&r.routes[index]); !tcPolicyDeleteIgnored(err) {
			closeErr = E.Errors(closeErr, err)
		} else {
			r.routes = slices.Delete(r.routes, index, index+1)
		}
	}
	if len(r.routes) != 0 {
		return closeErr
	}
	return E.Errors(closeErr, closeOwned(&r.lock))
}
