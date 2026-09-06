//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strings"

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
		// refreshBypassRuleSetsLocked has already reverted every backend it
		// could; the message below only ever names the update failure
		// itself, since a revert that also failed is reported separately,
		// by name, at the point it happened.
		i.policyWarnings.warn(i.logger, "refresh TC eBPF bypass_rule_set: ", err)
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
		// Same reasoning as updateBypassRuleSet's warning: refreshBypassRuleSetsLocked
		// already reverted what it could, and reports what it couldn't separately.
		i.policyWarnings.warn(i.logger, "retry TC eBPF bypass_rule_set refresh: ", err)
		return tcSharedRewriteRecoverable
	}
	i.bypassRuleSetNeedsRetry = false
	return tcSharedRewriteSettled
}

// bypassCIDRAppliedBackend is one backend applyBypassCIDRPolicyLocked has
// already moved to the new policy, along with how to move it back to the
// policy that was live before this refresh, should a later backend in the
// same pass fail.
type bypassCIDRAppliedBackend struct {
	name   string
	revert func() error
}

// revertBypassCIDRBackends reverts every already-applied backend, most
// recently applied first, and reports the name of each one whose own revert
// call also failed. It always attempts every entry rather than stopping at
// the first failure, so one backend refusing to revert does not leave an
// earlier one stuck on the new policy for no reason -- each backend's revert
// is independent of the others', exactly like its forward update was.
func revertBypassCIDRBackends(applied []bypassCIDRAppliedBackend, warn func(name string, err error)) []string {
	var failed []string
	for index := len(applied) - 1; index >= 0; index-- {
		if err := applied[index].revert(); err != nil {
			failed = append(failed, applied[index].name)
			warn(applied[index].name, err)
		}
	}
	return failed
}

// refreshBypassRuleSetsLocked compiles the current bypass_rule_set contents
// into one policy and hands it to applyBypassCIDRPolicyLocked.
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
	return i.applyBypassCIDRPolicyLocked(policy)
}

// applyBypassCIDRPolicyLocked applies one compiled policy to every backend
// this inbound has: TC, cgroup, and (unless it mirrors cgroup's own map)
// shared-network. These are independent native objects with independent
// maps, so one succeeding while a later one fails leaves them disagreeing
// about which destinations bypass the proxy -- silently, since nothing else
// notices a map that still holds the previous policy.
//
// This is a best-effort compensating rollback, not an atomic switch: each
// backend's own UpdateCompiledBypassCIDR/SetBypassCIDRState call is already
// crash-safe on its own (see common/ebpf's per-backend rollback-on-map-error
// handling), so unwinding a partially-applied pass here just means calling
// the same per-backend operation again with the previous policy, which each
// backend computes its own diff against exactly as it would for any other
// update. If a per-backend revert itself fails, that backend's actual state
// is now unknown relative to i.bypassRuleSetPolicy, and this reports exactly
// which backend by name rather than claiming a global "kept previous policy"
// that would no longer be true for it; bypassRuleSetInconsistent records the
// anomaly for diagnostics until a later call applies cleanly everywhere.
func (i *Inbound) applyBypassCIDRPolicyLocked(policy commonEBPF.BypassCIDRPolicy) error {
	previous := i.bypassRuleSetPolicy
	previousVersion := i.bypassRuleSetVersion
	version := previousVersion + 1
	i.bypassRuleSetVersion = version
	var applied []bypassCIDRAppliedBackend
	fail := func(cause error) error {
		failedPaths := revertBypassCIDRBackends(applied, func(name string, err error) {
			i.policyWarnings.warn(i.logger, "bypass_rule_set: revert ", name, " to the previous policy: ", err)
		})
		if len(failedPaths) > 0 {
			i.bypassRuleSetInconsistent = true
			return E.Cause(cause, "bypass_rule_set left inconsistent on: "+strings.Join(failedPaths, ", "))
		}
		return cause
	}
	var err error
	if backend := i.tcBackend(); backend != nil {
		if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
			return fail(err)
		}
		i.bypassRuleSetTCVersion = version
		applied = append(applied, bypassCIDRAppliedBackend{
			name: "TC",
			revert: func() error {
				_, revertErr := backend.UpdateCompiledBypassCIDR(previous)
				if revertErr == nil {
					i.bypassRuleSetTCVersion = previousVersion
				}
				return revertErr
			},
		})
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
			return fail(err)
		}
		i.bypassRuleSetCgroupVersion = version
		applied = append(applied, bypassCIDRAppliedBackend{
			name: "cgroup",
			revert: func() error {
				_, revertErr := backend.UpdateCompiledBypassCIDR(previous)
				if revertErr == nil {
					i.bypassRuleSetCgroupVersion = previousVersion
				}
				return revertErr
			},
		})
	}
	if i.sharedRewrite != nil {
		if backend := i.sharedRewrite.sharedBackendInstance(); backend != nil {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
				if err = backend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
					return fail(err)
				}
				i.bypassRuleSetSharedVersion = version
				previousIPv4Count, previousIPv6Count := previous.Counts()
				applied = append(applied, bypassCIDRAppliedBackend{
					name: "shared",
					revert: func() error {
						revertErr := backend.SetBypassCIDRState(previousIPv4Count, previousIPv6Count)
						if revertErr == nil {
							i.bypassRuleSetSharedVersion = previousVersion
						}
						return revertErr
					},
				})
			} else if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
				return fail(err)
			} else {
				i.bypassRuleSetSharedVersion = version
				applied = append(applied, bypassCIDRAppliedBackend{
					name: "shared",
					revert: func() error {
						_, revertErr := backend.UpdateCompiledBypassCIDR(previous)
						if revertErr == nil {
							i.bypassRuleSetSharedVersion = previousVersion
						}
						return revertErr
					},
				})
			}
		}
	}
	i.bypassRuleSetPolicy = policy
	i.bypassRuleSetInconsistent = false
	return nil
}

func (i *Inbound) compileBypassCIDRPolicy(prefixes []netip.Prefix) (commonEBPF.BypassCIDRPolicy, error) {
	policy, err := commonEBPF.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return policy, E.Cause(err, "compile TC eBPF bypass CIDR policy")
	}
	return policy, nil
}
