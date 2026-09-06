//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	i.bypassRuleSetCallbacks = make([]*list.Element[adapter.RuleSetUpdateCallback], 0, len(i.bypassRuleSet))
	for _, ruleSet := range i.bypassRuleSet {
		ruleSet.IncRef()
		i.bypassRuleSetCallbacks = append(i.bypassRuleSetCallbacks, ruleSet.RegisterCallback(i.updateBypassRuleSet))
	}
	i.bypassRuleSetStarted = true
	err := i.refreshBypassRuleSetsLocked(true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	for ruleSetIndex, ruleSet := range i.bypassRuleSet {
		if ruleSetIndex < len(i.bypassRuleSetCallbacks) {
			ruleSet.UnregisterCallback(i.bypassRuleSetCallbacks[ruleSetIndex])
		}
		ruleSet.DecRef()
	}
	i.bypassRuleSetCallbacks = nil
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	err := i.refreshBypassRuleSetsLocked(false)
	if err != nil {
		i.policyWarnings.warn(i.logger, "refresh TC eBPF bypass_rule_set; keeping previous policy: ", err)
		// A rule-set update is the only thing that would otherwise ever ask
		// for a retry: nothing about this ruleset is guaranteed to change
		// again. retryBypassRuleSetIfNeededLocked, driven by the same
		// scheduler that already retries other TC failures without needing
		// a new event, picks this back up instead of leaving it to whatever
		// the next unrelated rule-set change happens to be.
		i.bypassRuleSetNeedsRetry = true
		return
	}
	i.bypassRuleSetNeedsRetry = false
}

// retryBypassRuleSetIfNeededLocked is updateTCInterfaces' hook into the
// bypass_rule_set half of this file: it does nothing (and reports settled)
// unless a previous refreshBypassRuleSetsLocked call actually failed, so a
// healthy bypass_rule_set costs this per-round pass nothing beyond the lock
// acquisition and the boolean check.
func (i *Inbound) retryBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted || !i.bypassRuleSetNeedsRetry {
		return tcSharedRewriteSettled
	}
	if err := i.refreshBypassRuleSetsLocked(false); err != nil {
		i.policyWarnings.warn(i.logger, "retry TC eBPF bypass_rule_set refresh; keeping previous policy: ", err)
		return tcSharedRewriteRecoverable
	}
	i.bypassRuleSetNeedsRetry = false
	return tcSharedRewriteSettled
}

func (i *Inbound) refreshBypassRuleSetsLocked(startup bool) error {
	var prefixes []netip.Prefix
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if startup && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		for _, ipSet := range ipSets {
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	policy, err := i.compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return err
	}
	if backend := i.tcBackend(); backend != nil {
		if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
			return err
		}
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
			return err
		}
	}
	if i.sharedRewrite != nil {
		if backend := i.sharedRewrite.sharedBackendInstance(); backend != nil {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
				if err = backend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
					return err
				}
			} else if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
				return err
			}
		}
	}
	i.bypassRuleSetPolicy = policy
	return nil
}

func (i *Inbound) compileBypassCIDRPolicy(prefixes []netip.Prefix) (commonEBPF.BypassCIDRPolicy, error) {
	policy, err := commonEBPF.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return policy, E.Cause(err, "compile TC eBPF bypass CIDR policy")
	}
	return policy, nil
}
