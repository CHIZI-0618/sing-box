//go:build with_ebpf && (linux || android)

package ebpf

import (
	"fmt"
	"runtime"
	"slices"

	CiliumEBPF "github.com/cilium/ebpf"
)

type KernelProbeMode string

const (
	KernelProbeModeAll    KernelProbeMode = "all"
	KernelProbeModeLocal  KernelProbeMode = "local"
	KernelProbeModeShared KernelProbeMode = "shared"
)

// KernelProbeDataPlane identifies one concrete eBPF inbound backend. An empty
// value means that the corresponding local or shared path is disabled.
type KernelProbeDataPlane string

const (
	KernelProbeDataPlaneTC            KernelProbeDataPlane = "tc"
	KernelProbeDataPlaneCgroup        KernelProbeDataPlane = "cgroup"
	KernelProbeDataPlaneSocketAssign  KernelProbeDataPlane = "socket_assign"
	KernelProbeDataPlanePacketRewrite KernelProbeDataPlane = "packet_rewrite"
)

type KernelProbeStatus string

const (
	KernelProbePass    KernelProbeStatus = "PASS"
	KernelProbeWarn    KernelProbeStatus = "WARN"
	KernelProbeFail    KernelProbeStatus = "FAIL"
	KernelProbeUnknown KernelProbeStatus = "UNKNOWN"
)

type KernelProbeImportance string

const (
	KernelProbeRequired    KernelProbeImportance = "required"
	KernelProbePerformance KernelProbeImportance = "performance"
)

type KernelProbeOptions struct {
	Mode                KernelProbeMode
	LocalDataPlane      KernelProbeDataPlane
	SharedDataPlane     KernelProbeDataPlane
	Network             []string
	InterfaceNames      []string
	EnableIPv6          bool
	NeedLPMPolicy       bool
	NeedProcessTracking bool
	// VerifyObjectLoad loads and immediately closes the exact generated
	// programs selected by the requested data planes. It never attaches a
	// program or changes qdiscs, routes, sysctls, or traffic.
	VerifyObjectLoad bool
	// FakeIPICMPReply probes the fakeip_icmp object's own helper requirements.
	// Left false (the default), nothing about this feature is probed, the
	// same way nothing about it is loaded when TCConfig.FakeIPICMPReply is
	// false.
	FakeIPICMPReply bool
}

type kernelProbePlan struct {
	localTC             bool
	localCgroup         bool
	sharedSocketAssign  bool
	sharedPacketRewrite bool
	enableTCP           bool
	enableUDP           bool
	enableIPv6          bool
	needLPMPolicy       bool
	needProcessTracking bool
	fakeIPICMPReply     bool
	interfaceNames      []string
}

func newKernelProbePlan(
	localPlane, sharedPlane KernelProbeDataPlane,
	enableTCP, enableUDP bool,
	options KernelProbeOptions,
) kernelProbePlan {
	return kernelProbePlan{
		localTC:             localPlane == KernelProbeDataPlaneTC,
		localCgroup:         localPlane == KernelProbeDataPlaneCgroup,
		sharedSocketAssign:  sharedPlane == KernelProbeDataPlaneSocketAssign,
		sharedPacketRewrite: sharedPlane == KernelProbeDataPlanePacketRewrite,
		enableTCP:           enableTCP,
		enableUDP:           enableUDP,
		enableIPv6:          options.EnableIPv6,
		needLPMPolicy:       options.NeedLPMPolicy,
		needProcessTracking: options.NeedProcessTracking,
		fakeIPICMPReply:     options.FakeIPICMPReply,
		interfaceNames:      slices.Clone(options.InterfaceNames),
	}
}

func (p kernelProbePlan) needsSocketAssignment() bool {
	return p.localTC || p.sharedSocketAssign
}

func (p kernelProbePlan) needsTCProgram() bool {
	return p.needsSocketAssignment() || p.sharedPacketRewrite
}

type KernelProbeFinding struct {
	Status     KernelProbeStatus     `json:"status"`
	Scope      string                `json:"scope"`
	Importance KernelProbeImportance `json:"importance"`
	Feature    string                `json:"feature"`
	Detail     string                `json:"detail"`
}

type KernelProbeProgram struct {
	ID       CiliumEBPF.ProgramID
	Name     string
	Type     CiliumEBPF.ProgramType
	MapCount int
}

type KernelProbeReport struct {
	Platform        string
	KernelRelease   string
	Architecture    string
	Mode            KernelProbeMode
	LocalDataPlane  KernelProbeDataPlane
	SharedDataPlane KernelProbeDataPlane
	Network         []string
	IPv6            bool
	Findings        []KernelProbeFinding
	ActivePrograms  []KernelProbeProgram
	ActiveStateErr  error
	ExactObjectLoad bool
}

func (r *KernelProbeReport) Add(
	status KernelProbeStatus,
	scope string,
	importance KernelProbeImportance,
	feature string,
	detail string,
) {
	r.Findings = append(r.Findings, KernelProbeFinding{
		Status:     status,
		Scope:      scope,
		Importance: importance,
		Feature:    feature,
		Detail:     detail,
	})
}

func (r *KernelProbeReport) RequiredFailures() int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Status == KernelProbeFail && finding.Importance == KernelProbeRequired {
			count++
		}
	}
	return count
}

func (r *KernelProbeReport) RequiredUnknowns() int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Status == KernelProbeUnknown && finding.Importance == KernelProbeRequired {
			count++
		}
	}
	return count
}

func (r *KernelProbeReport) RequiredIssues() int {
	return r.RequiredFailures() + r.RequiredUnknowns()
}

func (r *KernelProbeReport) RequiredError() error {
	for _, finding := range r.Findings {
		if finding.Importance != KernelProbeRequired || (finding.Status != KernelProbeFail && finding.Status != KernelProbeUnknown) {
			continue
		}
		return fmt.Errorf("eBPF capability %s: %s (%s)", finding.Status, finding.Feature, finding.Detail)
	}
	return nil
}

func (r *KernelProbeReport) Counts() map[KernelProbeStatus]int {
	counts := make(map[KernelProbeStatus]int, 4)
	for _, finding := range r.Findings {
		counts[finding.Status]++
	}
	return counts
}

func ProbeKernel(options KernelProbeOptions) (*KernelProbeReport, error) {
	if options.Mode == "" {
		options.Mode = KernelProbeModeAll
	}
	switch options.Mode {
	case KernelProbeModeAll, KernelProbeModeLocal, KernelProbeModeShared:
	default:
		return nil, fmt.Errorf("invalid eBPF probe mode: %s", options.Mode)
	}
	enableTCP, enableUDP, network, err := parseKernelProbeNetwork(options.Network)
	if err != nil {
		return nil, err
	}
	localPlane, sharedPlane, err := normalizeProbeDataPlanes(options)
	if err != nil {
		return nil, err
	}
	reportMode := options.Mode
	switch {
	case localPlane != "" && sharedPlane != "":
		reportMode = KernelProbeModeAll
	case localPlane != "":
		reportMode = KernelProbeModeLocal
	default:
		reportMode = KernelProbeModeShared
	}
	memlockErr := raiseMemlockLimit()
	plan := newKernelProbePlan(localPlane, sharedPlane, enableTCP, enableUDP, options)

	report := &KernelProbeReport{
		Platform:        kernelProbePlatform(),
		KernelRelease:   kernelProbeRelease(),
		Architecture:    runtime.GOARCH,
		Mode:            reportMode,
		LocalDataPlane:  localPlane,
		SharedDataPlane: sharedPlane,
		Network:         network,
		IPv6:            options.EnableIPv6,
	}
	probeCommonCapabilities(report, memlockErr, plan)
	if localPlane != "" {
		probeLocalCapabilities(report, localPlane, plan.enableTCP, plan.enableUDP)
	}
	if sharedPlane != "" {
		probeSharedCapabilities(report, sharedPlane, plan.interfaceNames)
	}
	if plan.fakeIPICMPReply {
		probeFakeIPICMPCapabilities(report)
	}
	if options.VerifyObjectLoad {
		probeSelectedObjectLoads(report, plan)
		report.ExactObjectLoad = true
	}
	report.ActivePrograms, report.ActiveStateErr = probeActivePrograms()
	return report, nil
}

func normalizeProbeDataPlanes(options KernelProbeOptions) (KernelProbeDataPlane, KernelProbeDataPlane, error) {
	local, shared := options.LocalDataPlane, options.SharedDataPlane
	if local == "" && shared == "" {
		switch options.Mode {
		case KernelProbeModeAll:
			local, shared = KernelProbeDataPlaneCgroup, KernelProbeDataPlanePacketRewrite
		case KernelProbeModeLocal:
			local = KernelProbeDataPlaneCgroup
		case KernelProbeModeShared:
			shared = KernelProbeDataPlanePacketRewrite
		}
	}
	switch local {
	case "", KernelProbeDataPlaneTC, KernelProbeDataPlaneCgroup:
	default:
		return "", "", fmt.Errorf("invalid eBPF local data plane: %s", local)
	}
	switch shared {
	case "", KernelProbeDataPlaneSocketAssign, KernelProbeDataPlanePacketRewrite:
	default:
		return "", "", fmt.Errorf("invalid eBPF shared data plane: %s", shared)
	}
	if local == "" && shared == "" {
		return "", "", fmt.Errorf("at least one eBPF data plane must be selected")
	}
	return local, shared, nil
}
