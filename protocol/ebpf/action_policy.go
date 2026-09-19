//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// eBPFPrivateDestinationPrefixes mirrors the data-plane safety/private ranges
// as final pass decisions. The eBPF library receives only these decisions; it
// does not interpret them as a private-address policy.
var eBPFPrivateDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func (i *Inbound) compileActionPolicy() (commonEBPF.CompiledPolicy, error) {
	policy := commonEBPF.ActionPolicy{
		EnableTCP: i.enableTCP,
		EnableUDP: i.enableUDP,
		Local: commonEBPF.ActionScope{
			Default: commonEBPF.DecisionIntercept,
		},
		Shared: commonEBPF.ActionScope{
			Default: commonEBPF.DecisionIntercept,
		},
	}
	if i.localPolicy.IncludeUIDConfigured {
		policy.Local.Default = commonEBPF.DecisionPass
		for _, uid := range i.localPolicy.IncludeUID {
			policy.Local.UID = append(policy.Local.UID, commonEBPF.UIDDecision{
				Start: uid.Start, End: uid.End, Action: commonEBPF.DecisionIntercept,
			})
		}
	}
	for _, uid := range i.localPolicy.ExcludeUID {
		policy.Local.UID = append(policy.Local.UID, commonEBPF.UIDDecision{
			Start: uid.Start, End: uid.End, Action: commonEBPF.DecisionPass,
		})
	}
	if i.localPolicy.BypassPrivateAddress {
		for _, prefix := range eBPFPrivateDestinationPrefixes {
			policy.Local.DestinationCIDR = append(policy.Local.DestinationCIDR, commonEBPF.CIDRDecision{
				Prefix: prefix, Action: commonEBPF.DecisionPass,
			})
		}
	}
	if i.fakeIPIPv4Prefix.IsValid() {
		policy.Local.DestinationCIDR = append(policy.Local.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv4Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	if i.fakeIPIPv6Prefix.IsValid() {
		policy.Local.DestinationCIDR = append(policy.Local.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv6Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	appendPortDecisions(&policy.Local, i.localBypassPort, i.localDNSMode, i.enableTCP, i.enableUDP)

	for _, prefix := range i.sharedOptions.IncludeSourceCIDR {
		policy.Shared.SourceCIDR = append(policy.Shared.SourceCIDR, commonEBPF.CIDRDecision{
			Prefix: prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	for _, prefix := range i.sharedOptions.ExcludeSourceCIDR {
		policy.Shared.SourceCIDR = append(policy.Shared.SourceCIDR, commonEBPF.CIDRDecision{
			Prefix: prefix, Action: commonEBPF.DecisionPass,
		})
	}
	for _, address := range i.sharedIncludeMAC {
		policy.Shared.SourceMAC = append(policy.Shared.SourceMAC, commonEBPF.MACDecision{
			Address: address, Action: commonEBPF.DecisionIntercept,
		})
	}
	for _, address := range i.sharedExcludeMAC {
		policy.Shared.SourceMAC = append(policy.Shared.SourceMAC, commonEBPF.MACDecision{
			Address: address, Action: commonEBPF.DecisionPass,
		})
	}
	if i.sharedBypassPrivate {
		for _, prefix := range eBPFPrivateDestinationPrefixes {
			policy.Shared.DestinationCIDR = append(policy.Shared.DestinationCIDR, commonEBPF.CIDRDecision{
				Prefix: prefix, Action: commonEBPF.DecisionPass,
			})
		}
	}
	if i.fakeIPIPv4Prefix.IsValid() {
		policy.Shared.DestinationCIDR = append(policy.Shared.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv4Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	if i.fakeIPIPv6Prefix.IsValid() {
		policy.Shared.DestinationCIDR = append(policy.Shared.DestinationCIDR, commonEBPF.CIDRDecision{
			Prefix: i.fakeIPIPv6Prefix, Action: commonEBPF.DecisionIntercept,
		})
	}
	appendPortDecisions(&policy.Shared, i.sharedBypassPort, i.sharedDNSMode, i.enableTCP, i.enableUDP)
	return commonEBPF.CompileActionPolicy(policy)
}

func appendPortDecisions(scope *commonEBPF.ActionScope, bypass []commonEBPF.PortRange, dnsMode string, enableTCP, enableUDP bool) {
	for _, portRange := range bypass {
		for port := portRange.Start; port <= portRange.End; port++ {
			if port == 53 && dnsMode != dnsModeOff {
				continue
			}
			if enableTCP {
				scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{
					Protocol: commonEBPF.ProtocolTCP, Port: port, Action: commonEBPF.DecisionPass,
				})
			}
			if enableUDP {
				scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{
					Protocol: commonEBPF.ProtocolUDP, Port: port, Action: commonEBPF.DecisionPass,
				})
			}
			if port == portRange.End {
				break
			}
		}
	}
	if dnsMode == dnsModeHijack {
		if enableTCP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolTCP, Port: 53, Action: commonEBPF.DecisionIntercept})
		}
		if enableUDP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolUDP, Port: 53, Action: commonEBPF.DecisionIntercept})
		}
	} else if dnsMode == dnsModeOff {
		if enableTCP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolTCP, Port: 53, Action: commonEBPF.DecisionPass})
		}
		if enableUDP {
			scope.DestinationPort = append(scope.DestinationPort, commonEBPF.PortDecision{Protocol: commonEBPF.ProtocolUDP, Port: 53, Action: commonEBPF.DecisionPass})
		}
	}
}
