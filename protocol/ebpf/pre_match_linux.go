//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	snetlink "github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const defaultPreMatchQueue uint16 = 100

type preMatchController struct {
	access        sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	queueCancel   context.CancelFunc
	queue         *preMatchNFQueue
	routing       *tcPolicyRouting
	queueNumber   uint16
	listenerPort  uint16
	localIPv6     bool
	sharedIPv6    bool
	localEnabled  bool
	enableTCP     bool
	enableUDP     bool
	sharedEnabled bool
	bypassMark    uint32
	proxyMark     uint32
	rejectMark    uint32
	markMask      uint32
	localChain    string
	sharedRoot    string
	sharedChain   string
	localNAT      string
	sharedTPROXY  string
	filterChain   string
	families      []preMatchFamily
	shared        []string
	localCgroup   string
}

type preMatchFamily struct {
	ipv6 bool
	ipt  *iptables.IPTables
}

type preMatchNFQueue struct {
	queue       *nfqueue.Nfqueue
	router      adapter.Router
	inboundRef  *Inbound
	inbound     string
	inboundType string
	markMask    uint32
	bypassMark  uint32
	proxyMark   uint32
	rejectMark  uint32
	closed      bool
	access      sync.Mutex
	verdict     warningLimiter
	ctx         context.Context
}

func newPreMatchController(inbound *Inbound, routing *tcPolicyRouting, proxyMark, bypassMark uint32) (*preMatchController, error) {
	if proxyMark == 0 || bypassMark == 0 || proxyMark == bypassMark {
		return nil, E.New("invalid eBPF pre-match routing marks")
	}
	rejectMark, err := allocatePreMatchMark(proxyMark, bypassMark)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(inbound.ctx)
	local, shared, filter := preMatchChainNames(inbound.Tag())
	return &preMatchController{
		ctx: ctx, cancel: cancel, queueNumber: preMatchQueueNumber(inbound.Tag()),
		routing:      routing,
		listenerPort: inbound.listeners.selectedPort(),
		localIPv6:    inbound.localIPv6, sharedIPv6: inbound.sharedIPv6,
		enableTCP: inbound.enableTCP, enableUDP: inbound.enableUDP,
		sharedEnabled: inbound.sharedEnabled,
		bypassMark:    bypassMark, proxyMark: proxyMark, rejectMark: rejectMark,
		markMask:   bypassMark | proxyMark | rejectMark,
		localChain: local, sharedRoot: shared + "R", sharedChain: shared,
		localNAT: local + "N", sharedTPROXY: shared + "T", filterChain: filter,
	}, nil
}

func allocatePreMatchMark(reserved ...uint32) (uint32, error) {
	var used uint32
	for _, mark := range reserved {
		used |= mark
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := snetlink.RuleList(family)
		if err != nil {
			if family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)) {
				continue
			}
			return 0, E.Cause(err, "inspect policy rules for eBPF pre-match mark")
		}
		for _, rule := range rules {
			if rule.Mask >= 0 {
				used |= rule.Mark | uint32(rule.Mask)
			} else if rule.MarkSet || rule.Mark != 0 {
				used = ^uint32(0)
			}
		}
	}
	for bit := uint(30); bit >= 16; bit-- {
		candidate := uint32(1) << bit
		if used&candidate == 0 {
			return candidate, nil
		}
	}
	return 0, E.New("no unused eBPF pre-match mark is available")
}

func preMatchQueueNumber(tag string) uint16 {
	digest := sha256.Sum256([]byte(tag))
	return defaultPreMatchQueue + uint16((uint16(digest[0])<<8|uint16(digest[1]))%65435)
}

func preMatchChainNames(tag string) (string, string, string) {
	digest := sha256.Sum256([]byte(tag))
	suffix := strings.ToUpper(hex.EncodeToString(digest[:]))[:8]
	return "SBEP" + suffix + "L", "SBEP" + suffix + "S", "SBEP" + suffix + "F"
}

func (c *preMatchController) start(inbound *Inbound, local bool, shared []string) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.queue != nil {
		return E.New("eBPF pre-match controller is already started")
	}
	c.localEnabled = local
	if local {
		path, err := preMatchCgroupRulePath()
		if err != nil {
			return E.Cause(err, "resolve local eBPF pre-match cgroup exclusion")
		}
		if path == "." {
			return E.New("local eBPF pre-match requires a non-root cgroup v2")
		}
		c.localCgroup = path
	}
	if err := c.openFamilies(c.localIPv6 || c.sharedIPv6); err != nil {
		return err
	}
	if err := c.install(local, shared); err != nil {
		c.cleanupChains()
		return err
	}
	nfq, err := nfqueue.Open(&nfqueue.Config{
		NfQueue: c.queueNumber, MaxPacketLen: 0xffff, MaxQueueLen: 4096,
		Copymode: nfqueue.NfQnlCopyPacket, AfFamily: unix.AF_UNSPEC,
		Flags: nfqueue.NfQaCfgFlagGSO,
	})
	if err != nil {
		c.cleanupChains()
		return E.Cause(err, "open eBPF pre-match nfqueue")
	}
	if err = nfq.SetOption(netlink.NoENOBUFS, true); err != nil {
		nfq.Close()
		c.cleanupChains()
		return E.Cause(err, "configure eBPF pre-match nfqueue")
	}
	ctx, cancel := context.WithCancel(c.ctx)
	handler := &preMatchNFQueue{
		queue: nfq, router: inbound.router, inboundRef: inbound, inbound: inbound.Tag(), inboundType: inbound.Type(),
		markMask: c.markMask, bypassMark: c.bypassMark, proxyMark: c.proxyMark, rejectMark: c.rejectMark,
		ctx: ctx,
	}
	if err = nfq.RegisterWithErrorFunc(ctx, handler.handle, func(err error) int {
		if ctx.Err() != nil {
			return 1
		}
		inbound.logger.Error("eBPF pre-match nfqueue error: ", err)
		return 0
	}); err != nil {
		cancel()
		nfq.Close()
		c.cleanupChains()
		return E.Cause(err, "register eBPF pre-match nfqueue")
	}
	c.queue = handler
	c.queueCancel = cancel
	c.shared = append([]string(nil), shared...)
	return nil
}

func (c *preMatchController) openFamilies(enableIPv6 bool) error {
	ipt4, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return E.Cause(err, "open IPv4 iptables for eBPF pre-match")
	}
	c.families = append(c.families, preMatchFamily{ipt: ipt4})
	if enableIPv6 {
		ipt6, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv6))
		if err != nil {
			c.families = nil
			return E.Cause(err, "open IPv6 iptables for eBPF pre-match")
		}
		c.families = append(c.families, preMatchFamily{ipv6: true, ipt: ipt6})
	}
	return nil
}

func (c *preMatchController) install(local bool, shared []string) error {
	for _, family := range c.families {
		ipt := family.ipt
		for _, tableChain := range [][2]string{
			{"mangle", c.localChain}, {"mangle", c.sharedRoot}, {"mangle", c.sharedChain},
			{"mangle", c.sharedTPROXY}, {"nat", c.localNAT}, {"filter", c.filterChain},
		} {
			_ = ipt.ClearAndDeleteChain(tableChain[0], tableChain[1])
		}
		if local && (!family.ipv6 || c.localIPv6) {
			if err := ipt.NewChain("mangle", c.localChain); err != nil {
				return E.Cause(err, "create local eBPF pre-match chain")
			}
			if err := c.appendFlowRules(ipt, c.localChain, false); err != nil {
				return err
			}
			if err := ipt.AppendUnique("mangle", "OUTPUT", "-j", c.localChain); err != nil {
				return E.Cause(err, "attach local eBPF pre-match chain")
			}
			if !family.ipv6 || c.localIPv6 {
				if err := ipt.NewChain("nat", c.localNAT); err != nil {
					return E.Cause(err, "create local eBPF pre-match NAT chain")
				}
				if err := c.appendLocalNAT(ipt); err != nil {
					return err
				}
				if err := ipt.AppendUnique("nat", "OUTPUT", "-j", c.localNAT); err != nil {
					return E.Cause(err, "attach local eBPF pre-match NAT chain")
				}
			}
		}
		if c.sharedEnabled && (!family.ipv6 || c.sharedIPv6) {
			if err := ipt.NewChain("mangle", c.sharedRoot); err != nil {
				return E.Cause(err, "create shared eBPF pre-match chain")
			}
			if err := ipt.NewChain("mangle", c.sharedChain); err != nil {
				return E.Cause(err, "create shared eBPF pre-match flow chain")
			}
			for _, name := range shared {
				if err := ipt.Append("mangle", c.sharedRoot, "-i", name, "-j", c.sharedChain); err != nil {
					return E.Cause(err, "add shared eBPF pre-match interface")
				}
			}
			if err := c.appendFlowRules(ipt, c.sharedChain, true); err != nil {
				return err
			}
			if err := ipt.AppendUnique("mangle", "PREROUTING", "-j", c.sharedRoot); err != nil {
				return E.Cause(err, "attach shared eBPF pre-match chain")
			}
		}
		if c.sharedEnabled && (!family.ipv6 || c.sharedIPv6) {
			if err := ipt.NewChain("mangle", c.sharedTPROXY); err != nil {
				return E.Cause(err, "create eBPF pre-match TPROXY chain")
			}
			if err := c.appendSharedTPROXY(ipt); err != nil {
				return err
			}
			if err := ipt.AppendUnique("mangle", "PREROUTING", "-j", c.sharedTPROXY); err != nil {
				return E.Cause(err, "attach eBPF pre-match TPROXY chain")
			}
		}
		if err := ipt.NewChain("filter", c.filterChain); err != nil {
			return E.Cause(err, "create eBPF pre-match filter chain")
		}
		if err := ipt.Append("filter", c.filterChain, "-m", "mark", "--mark", c.mark(c.rejectMark), "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"); err != nil {
			return E.Cause(err, "add eBPF pre-match TCP reject rule")
		}
		if err := ipt.Append("filter", c.filterChain, "-m", "mark", "--mark", c.mark(c.rejectMark), "-j", "DROP"); err != nil {
			return E.Cause(err, "add eBPF pre-match drop rule")
		}
		for _, hook := range c.filterHooks() {
			if err := ipt.AppendUnique("filter", hook, "-j", c.filterChain); err != nil {
				return E.Cause(err, "attach eBPF pre-match filter chain")
			}
		}
	}
	return nil
}

func (c *preMatchController) filterHooks() []string {
	hooks := make([]string, 0, 3)
	if c.localEnabled {
		hooks = append(hooks, "OUTPUT")
	}
	if c.sharedEnabled {
		hooks = append(hooks, "INPUT", "FORWARD")
	}
	return hooks
}

func (c *preMatchController) appendFlowRules(ipt *iptables.IPTables, chain string, prerouting bool) error {
	if c.localCgroup != "" && !prerouting {
		if err := ipt.Append("mangle", chain, "-m", "cgroup", "--path", c.localCgroup, "-j", "RETURN"); err != nil {
			return E.Cause(err, "install local eBPF pre-match cgroup exclusion")
		}
	}
	if err := ipt.Append("mangle", chain, "-m", "connmark", "!", "--mark", "0x0/"+c.mask(), "-j", "CONNMARK", "--restore-mark", "--nfmask", c.mask(), "--ctmask", c.mask()); err != nil {
		return E.Cause(err, "restore eBPF pre-match connection mark")
	}
	if err := ipt.Append("mangle", chain, "-m", "mark", "!", "--mark", "0x0/"+c.mask(), "-j", "CONNMARK", "--save-mark", "--nfmask", c.mask(), "--ctmask", c.mask()); err != nil {
		return E.Cause(err, "save eBPF pre-match connection mark")
	}
	if err := ipt.Append("mangle", chain, "-m", "mark", "!", "--mark", "0x0/"+c.mask(), "-j", "RETURN"); err != nil {
		return E.Cause(err, "restore eBPF pre-match packet mark")
	}
	if err := ipt.Append("mangle", chain, "-p", "tcp", "!", "--tcp-flags", "SYN,ACK", "SYN", "-j", "RETURN"); err != nil {
		return E.Cause(err, "install eBPF pre-match TCP first-packet rule")
	}
	queue := []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(c.queueNumber)), "--queue-bypass"}
	for _, protocol := range c.protocols() {
		if err := ipt.Append("mangle", chain, append([]string{"-p", protocol}, queue...)...); err != nil {
			return E.Cause(err, "install eBPF pre-match "+protocol+" queue rule")
		}
	}
	return ipt.Append("mangle", chain, "-j", "RETURN")
}

func (c *preMatchController) appendLocalNAT(ipt *iptables.IPTables) error {
	for _, protocol := range c.protocols() {
		if err := ipt.Append("nat", c.localNAT, "-p", protocol, "-m", "mark", "--mark", c.mark(c.bypassMark), "-j", "RETURN"); err != nil {
			return err
		}
		if err := ipt.Append("nat", c.localNAT, "-p", protocol, "-m", "mark", "--mark", c.mark(c.rejectMark), "-j", "RETURN"); err != nil {
			return err
		}
		if err := ipt.Append("nat", c.localNAT, "-p", protocol, "-m", "mark", "--mark", c.mark(c.proxyMark), "-j", "REDIRECT", "--to-ports", strconv.Itoa(int(c.listenerPort))); err != nil {
			return E.Cause(err, "install eBPF pre-match local redirect rule")
		}
	}
	return nil
}

func (c *preMatchController) appendSharedTPROXY(ipt *iptables.IPTables) error {
	for _, protocol := range c.protocols() {
		if err := ipt.Append("mangle", c.sharedTPROXY, "-p", protocol, "-m", "mark", "--mark", c.mark(c.proxyMark), "-j", "TPROXY", "--on-port", strconv.Itoa(int(c.listenerPort)), "--tproxy-mark", c.mark(c.proxyMark)); err != nil {
			return E.Cause(err, "install eBPF pre-match TPROXY rule")
		}
	}
	return nil
}

func (c *preMatchController) mark(mark uint32) string {
	return "0x" + strconv.FormatUint(uint64(mark), 16) + "/0x" + strconv.FormatUint(uint64(c.markMask), 16)
}

func (c *preMatchController) protocols() []string {
	protocols := make([]string, 0, 2)
	if c.enableTCP {
		protocols = append(protocols, "tcp")
	}
	if c.enableUDP {
		protocols = append(protocols, "udp")
	}
	return protocols
}

func (c *preMatchController) mask() string {
	return "0x" + strconv.FormatUint(uint64(c.markMask), 16)
}

func (c *preMatchController) updateShared(interfaces []string) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.queue == nil || !c.sharedEnabled || slicesEqual(c.shared, interfaces) {
		return nil
	}
	previous := append([]string(nil), c.shared...)
	var additions []string
	for _, name := range interfaces {
		if !slices.Contains(previous, name) {
			additions = append(additions, name)
		}
	}
	var removals []string
	for _, name := range previous {
		if !slices.Contains(interfaces, name) {
			removals = append(removals, name)
		}
	}
	// Add new interface jumps before removing old ones. This keeps at least
	// one working rule for every interface during a network handoff.
	for _, family := range c.families {
		if family.ipv6 && !c.sharedIPv6 {
			continue
		}
		for _, name := range additions {
			if err := family.ipt.Append("mangle", c.sharedRoot, "-i", name, "-j", c.sharedChain); err != nil {
				return E.Errors(err, c.removeSharedInterfaceRules(additions), c.restoreSharedAll(previous))
			}
		}
	}
	for _, family := range c.families {
		if family.ipv6 && !c.sharedIPv6 {
			continue
		}
		for _, name := range removals {
			if err := family.ipt.Delete("mangle", c.sharedRoot, "-i", name, "-j", c.sharedChain); err != nil {
				return E.Errors(
					E.New("remove old eBPF pre-match shared interface rule for ", name, ": ", err),
					c.restoreSharedAll(previous),
				)
			}
		}
	}
	c.shared = append(c.shared[:0], interfaces...)
	return nil
}

func (c *preMatchController) removeSharedInterfaceRules(interfaces []string) error {
	var removeErr error
	for _, family := range c.families {
		if family.ipv6 && !c.sharedIPv6 {
			continue
		}
		for _, name := range interfaces {
			removeErr = E.Errors(removeErr, family.ipt.Delete("mangle", c.sharedRoot, "-i", name, "-j", c.sharedChain))
		}
	}
	return removeErr
}

func (c *preMatchController) restoreShared(ipt *iptables.IPTables, interfaces []string) error {
	if err := ipt.ClearChain("mangle", c.sharedRoot); err != nil {
		return err
	}
	for _, name := range interfaces {
		if err := ipt.Append("mangle", c.sharedRoot, "-i", name, "-j", c.sharedChain); err != nil {
			return err
		}
	}
	return nil
}

func (c *preMatchController) restoreSharedAll(interfaces []string) error {
	var restoreErr error
	for _, family := range c.families {
		if family.ipv6 && !c.sharedIPv6 {
			continue
		}
		restoreErr = E.Errors(restoreErr, c.restoreShared(family.ipt, interfaces))
	}
	return restoreErr
}

func (c *preMatchController) ensureRouting() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.queue == nil || c.routing == nil {
		return nil
	}
	_, err := c.routing.ensure()
	return err
}

func (c *preMatchController) close() error {
	if c == nil {
		return nil
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.queue != nil {
		c.queue.close()
		c.queue = nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.queueCancel != nil {
		c.queueCancel()
		c.queueCancel = nil
	}
	c.cleanupChains()
	if c.routing != nil {
		if err := c.routing.Close(); err != nil {
			return err
		}
		c.routing = nil
	}
	c.families = nil
	return nil
}

func (c *preMatchController) cleanupChains() {
	for _, family := range c.families {
		for _, hook := range []string{"OUTPUT", "PREROUTING"} {
			_ = family.ipt.Delete("mangle", hook, "-j", c.localChain)
			_ = family.ipt.Delete("mangle", hook, "-j", c.sharedRoot)
			_ = family.ipt.Delete("mangle", hook, "-j", c.sharedTPROXY)
		}
		_ = family.ipt.Delete("nat", "OUTPUT", "-j", c.localNAT)
		for _, hook := range c.filterHooks() {
			_ = family.ipt.Delete("filter", hook, "-j", c.filterChain)
		}
		for _, tableChain := range [][2]string{
			{"mangle", c.localChain}, {"mangle", c.sharedRoot}, {"mangle", c.sharedChain},
			{"mangle", c.sharedTPROXY}, {"nat", c.localNAT}, {"filter", c.filterChain},
		} {
			_ = family.ipt.ClearAndDeleteChain(tableChain[0], tableChain[1])
		}
	}
}

func preMatchCgroupRulePath() (string, error) {
	mount, err := commonEBPF.DetectCgroup2Root()
	if err != nil {
		return "", err
	}
	path, err := commonEBPF.DetectProcessCgroup2Path()
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(mount, path)
	if err != nil {
		return "", err
	}
	if relative == "" {
		return ".", nil
	}
	return relative, nil
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type preMatchPacket struct {
	protocol    uint8
	source      netip.AddrPort
	destination netip.AddrPort
	firstPacket []byte
}

func parsePreMatchPacket(packet []byte) (preMatchPacket, bool) {
	if len(packet) < 1 {
		return preMatchPacket{}, false
	}
	var protocol uint8
	var offset int
	var source, destination netip.Addr
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return preMatchPacket{}, false
		}
		ip := header.IPv4(packet)
		offset = int(ip.HeaderLength())
		totalLength := int(ip.TotalLength())
		if offset < header.IPv4MinimumSize || offset > len(packet) || totalLength < offset || totalLength > len(packet) || ip.More() || ip.FragmentOffset() != 0 {
			return preMatchPacket{}, false
		}
		protocol = uint8(ip.TransportProtocol())
		source, destination = ip.SourceAddr(), ip.DestinationAddr()
		packet = packet[:totalLength]
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return preMatchPacket{}, false
		}
		totalLength := header.IPv6MinimumSize + int(header.IPv6(packet).PayloadLength())
		if totalLength < header.IPv6MinimumSize || totalLength > len(packet) {
			return preMatchPacket{}, false
		}
		packet = packet[:totalLength]
		var ok bool
		protocol, offset, ok = parsePreMatchIPv6Transport(packet)
		if !ok {
			return preMatchPacket{}, false
		}
		ip := header.IPv6(packet)
		source, destination = ip.SourceAddr(), ip.DestinationAddr()
	default:
		return preMatchPacket{}, false
	}
	transport := packet[offset:]
	parsed := preMatchPacket{protocol: protocol}
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return preMatchPacket{}, false
		}
		tcp := header.TCP(transport)
		flags := tcp.Flags()
		if !flags.Contains(header.TCPFlagSyn) || flags.Contains(header.TCPFlagAck) {
			return preMatchPacket{}, false
		}
		parsed.source = netip.AddrPortFrom(source, tcp.SourcePort())
		parsed.destination = netip.AddrPortFrom(destination, tcp.DestinationPort())
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return preMatchPacket{}, false
		}
		udp := header.UDP(transport)
		length := int(udp.Length())
		if length < header.UDPMinimumSize || length > len(transport) {
			return preMatchPacket{}, false
		}
		parsed.source = netip.AddrPortFrom(source, udp.SourcePort())
		parsed.destination = netip.AddrPortFrom(destination, udp.DestinationPort())
		parsed.firstPacket = udp.Payload()
	case uint8(header.ICMPv4ProtocolNumber):
		if !source.Is4() || len(transport) < header.ICMPv4MinimumSize {
			return preMatchPacket{}, false
		}
		icmp := header.ICMPv4(transport)
		if icmp.Type() != header.ICMPv4Echo || icmp.Code() != 0 {
			return preMatchPacket{}, false
		}
		identifier := icmp.Ident()
		parsed.source = netip.AddrPortFrom(source, identifier)
		parsed.destination = netip.AddrPortFrom(destination, identifier)
	case uint8(header.ICMPv6ProtocolNumber):
		if !source.Is6() || len(transport) < header.ICMPv6MinimumSize {
			return preMatchPacket{}, false
		}
		icmp := header.ICMPv6(transport)
		if icmp.Type() != header.ICMPv6EchoRequest || icmp.Code() != 0 {
			return preMatchPacket{}, false
		}
		identifier := icmp.Ident()
		parsed.source = netip.AddrPortFrom(source, identifier)
		parsed.destination = netip.AddrPortFrom(destination, identifier)
	default:
		return preMatchPacket{}, false
	}
	return parsed, true
}

func parsePreMatchIPv6Transport(packet []byte) (uint8, int, bool) {
	next := header.IPv6(packet).NextHeader()
	offset := header.IPv6MinimumSize
	for depth := 0; depth < 16; depth++ {
		switch header.IPv6ExtensionHeaderIdentifier(next) {
		case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier:
			if len(packet) < offset+2 {
				return 0, 0, false
			}
			next = packet[offset]
			length := (int(packet[offset+1]) + 1) * 8
			if len(packet) < offset+length {
				return 0, 0, false
			}
			offset += length
		case header.IPv6FragmentExtHdrIdentifier:
			if len(packet) < offset+header.IPv6FragmentHeaderSize {
				return 0, 0, false
			}
			fragment := header.IPv6Fragment(packet[offset:])
			if fragment.More() || fragment.FragmentOffset() != 0 {
				return 0, 0, false
			}
			next = fragment.NextHeader()
			offset += header.IPv6FragmentHeaderSize
		case header.IPv6ExtensionHeaderIdentifier(51):
			if len(packet) < offset+2 {
				return 0, 0, false
			}
			next = packet[offset]
			length := (int(packet[offset+1]) + 2) * 4
			if len(packet) < offset+length {
				return 0, 0, false
			}
			offset += length
		case header.IPv6NoNextHeaderIdentifier:
			return 0, 0, false
		default:
			return next, offset, true
		}
	}
	return 0, 0, false
}

func (h *preMatchNFQueue) handle(attr nfqueue.Attribute) int {
	if attr.PacketID == nil || attr.Payload == nil {
		return 0
	}
	packet, ok := parsePreMatchPacket(*attr.Payload)
	if !ok {
		h.set(attr, nfqueue.NfAccept, 0)
		return 0
	}
	if h.inboundRef.preMatchPolicyBypass(attr, packet) {
		h.set(attr, nfqueue.NfRepeat, h.bypassMark)
		return 0
	}
	verdict := adapter.JudgeFlow(h.router, h.inbound, h.inboundType, packet.protocol, packet.source, packet.destination, packet.firstPacket)
	switch verdict.Action {
	case tun.ActionAccept, tun.ActionBypass:
		if h.inboundRef.preMatchFakeIP(packet.destination.Addr()) {
			h.set(attr, nfqueue.NfRepeat, h.proxyMark)
		} else {
			h.set(attr, nfqueue.NfRepeat, h.bypassMark)
		}
	case tun.ActionFlow, tun.ActionHijackDNS:
		h.set(attr, nfqueue.NfRepeat, h.proxyMark)
	case tun.ActionReject:
		h.set(attr, nfqueue.NfRepeat, h.rejectMark)
	case tun.ActionDrop:
		h.set(attr, nfqueue.NfDrop, 0)
	default:
		h.set(attr, nfqueue.NfRepeat, h.bypassMark)
	}
	return 0
}

func (i *Inbound) preMatchPolicyBypass(attr nfqueue.Attribute, packet preMatchPacket) bool {
	if attr.Hook == nil {
		return true
	}
	local := *attr.Hook == 3
	if !local && *attr.Hook != 0 {
		return true
	}
	if local && !i.localEnabled || !local && !i.sharedEnabled {
		return true
	}

	if i.preMatchFakeIP(packet.destination.Addr()) {
		return false
	}
	dnsMode := i.sharedDNSMode
	if local {
		dnsMode = i.localDNSMode
	}
	if packet.destination.Port() == 53 && dnsMode == dnsModeOff {
		return true
	}
	if packet.destination.Port() == 53 && dnsMode == dnsModeHijack {
		return false
	}

	if local {
		if attr.UID == nil {
			if i.localPolicy.IncludeUIDConfigured {
				return true
			}
		} else {
			uid := *attr.UID
			if containsUID(i.localPolicy.ExcludeUID, uid) ||
				(i.localPolicy.IncludeUIDConfigured && !containsUID(i.localPolicy.IncludeUID, uid)) {
				return true
			}
		}
	} else {
		if !i.preMatchSourceSelected(packet.source.Addr()) || !i.preMatchMACSelected(attr) {
			return true
		}
	}

	if packet.destination.Port() == 53 && dnsMode == dnsModeRespectPolicy {
		return false
	}
	ports := i.sharedBypassPort
	if local {
		ports = i.localBypassPort
	}
	if containsPort(ports, packet.destination.Port()) {
		return true
	}
	i.preMatchHostAccess.RLock()
	for _, address := range i.preMatchHostAddresses {
		if address == packet.destination.Addr() {
			i.preMatchHostAccess.RUnlock()
			return true
		}
	}
	i.preMatchHostAccess.RUnlock()
	if i.localPolicy.BypassPrivateAddress && local && preMatchPrivateAddress(packet.destination.Addr()) {
		return true
	}
	if i.sharedBypassPrivate && !local && preMatchPrivateAddress(packet.destination.Addr()) {
		return true
	}
	i.bypassRuleSetAccess.Lock()
	bypassRuleSet := i.bypassRuleSetPolicy
	i.bypassRuleSetAccess.Unlock()
	return bypassRuleSet.Contains(packet.destination.Addr())
}

func (i *Inbound) updatePreMatchHostAddresses() {
	addresses := i.hostAddresses()
	i.preMatchHostAccess.Lock()
	i.preMatchHostAddresses = addresses
	i.preMatchHostAccess.Unlock()
}

func (i *Inbound) preMatchFakeIP(address netip.Addr) bool {
	address = address.Unmap()
	return (i.fakeIPIPv4Prefix.IsValid() && address.Is4() && i.fakeIPIPv4Prefix.Contains(address)) ||
		(i.fakeIPIPv6Prefix.IsValid() && address.Is6() && i.fakeIPIPv6Prefix.Contains(address))
}

func (i *Inbound) preMatchSourceSelected(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range i.sharedOptions.ExcludeSourceCIDR {
		if prefix.Contains(address) {
			return false
		}
	}
	if len(i.sharedOptions.IncludeSourceCIDR) == 0 {
		return true
	}
	for _, prefix := range i.sharedOptions.IncludeSourceCIDR {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (i *Inbound) preMatchMACSelected(attr nfqueue.Attribute) bool {
	if len(i.sharedIncludeMAC) == 0 && len(i.sharedExcludeMAC) == 0 {
		return true
	}
	if attr.HwAddr == nil || len(*attr.HwAddr) < 6 {
		return false
	}
	var address commonEBPF.MACAddress
	copy(address[:], (*attr.HwAddr)[:6])
	for _, excluded := range i.sharedExcludeMAC {
		if excluded == address {
			return false
		}
	}
	if len(i.sharedIncludeMAC) == 0 {
		return true
	}
	for _, included := range i.sharedIncludeMAC {
		if included == address {
			return true
		}
	}
	return false
}

func containsUID(ranges []commonEBPF.UIDRange, uid uint32) bool {
	for _, current := range ranges {
		if uid >= current.Start && uid <= current.End {
			return true
		}
	}
	return false
}

func containsPort(ranges []commonEBPF.PortRange, port uint16) bool {
	for _, current := range ranges {
		if port >= current.Start && port <= current.End {
			return true
		}
	}
	return false
}

func preMatchPrivateAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is4() {
		bytes := address.As4()
		return bytes[0] == 0 || bytes[0] == 10 || bytes[0] == 127 || bytes[0] >= 224 ||
			(bytes[0] == 100 && bytes[1]&0xc0 == 0x40) ||
			(bytes[0] == 169 && bytes[1] == 254) ||
			(bytes[0] == 172 && bytes[1]&0xf0 == 0x10) ||
			(bytes[0] == 192 && bytes[1] == 168)
	}
	if address.Is6() {
		bytes := address.As16()
		return bytes[0] == 0xff || bytes[0]&0xfe == 0xfc ||
			(bytes[0] == 0xfe && bytes[1]&0xc0 == 0x80)
	}
	return false
}

func (h *preMatchNFQueue) set(attr nfqueue.Attribute, verdict int, mark uint32) {
	h.access.Lock()
	defer h.access.Unlock()
	if h.closed || attr.PacketID == nil || h.queue == nil {
		return
	}
	packetMark := mark
	if attr.Mark != nil {
		packetMark = (*attr.Mark &^ h.markMask) | mark
	}
	var err error
	if mark == 0 {
		err = h.queue.SetVerdict(*attr.PacketID, verdict)
	} else {
		err = h.queue.SetVerdictWithOption(*attr.PacketID, verdict, nfqueue.WithMark(packetMark))
	}
	if err != nil && h.inboundRef != nil && h.inboundRef.logger != nil && h.ctx != nil && h.ctx.Err() == nil {
		allowed, suppressed := h.verdict.allow(time.Now())
		if allowed {
			if suppressed > 0 {
				h.inboundRef.logger.Trace("eBPF pre-match NFQUEUE verdict failed: ", err, " (", suppressed, " similar errors suppressed)")
			} else {
				h.inboundRef.logger.Trace("eBPF pre-match NFQUEUE verdict failed: ", err)
			}
		}
	}
}

func (h *preMatchNFQueue) close() {
	h.access.Lock()
	defer h.access.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	if h.queue != nil {
		h.queue.Close()
		h.queue = nil
	}
}
