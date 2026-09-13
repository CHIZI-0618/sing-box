//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

func probeSelectedObjectLoads(report *KernelProbeReport, plan kernelProbePlan) {
	if plan.needsSocketAssignment() {
		detail, err := loadTCProbeObject(plan)
		reportObjectLoadResult(report, "tc", "selected TC eBPF object", detail, err)
	}
	if plan.localCgroup {
		detail, err := loadCgroupProbeObject(plan)
		reportObjectLoadResult(report, "local", "selected cgroup eBPF object", detail, err)
	}
	if plan.sharedPacketRewrite {
		detail, err := loadSharedNetworkProbeObject(plan)
		reportObjectLoadResult(report, "shared", "selected packet-rewrite eBPF object", detail, err)
	}
	if plan.fakeIPICMPReply {
		detail, err := loadFakeIPICMPProbeObject(plan)
		reportObjectLoadResult(report, "fakeip_icmp", "selected FakeIP ICMP eBPF object", detail, err)
	}
}

func reportObjectLoadResult(report *KernelProbeReport, scope string, feature string, detail string, err error) {
	status := classifyKernelProbeError(err)
	if err != nil {
		detail += " Load failed: " + shortProbeError(err)
	}
	report.Add(status, scope, KernelProbeRequired, feature, detail)
}

func loadTCProbeObject(plan kernelProbePlan) (string, error) {
	backend, err := PrepareTC(TCConfig{
		ListenerPort:      1,
		EnableLocal:       plan.localTC,
		EnableShared:      plan.sharedSocketAssign,
		EnableIPv4:        true,
		EnableLocalIPv6:   plan.localTC && plan.enableIPv6,
		EnableSharedIPv6:  plan.sharedSocketAssign && plan.enableIPv6,
		EnableTCP:         plan.enableTCP,
		EnableUDP:         plan.enableUDP,
		DeliveryInterface: 1,
		RoutingMark:       DefaultTCRoutingMark,
	})
	if err != nil {
		return "Loads the generated TC programs and their real map specifications without attaching a classifier.", err
	}
	detail := "Loaded the generated TC programs and their real map specifications without attaching a classifier."
	if plan.enableTCP {
		if backend.tcpListenerMap {
			detail += " The preferred SOCKMAP TCP path loaded."
		} else {
			detail += " The kernel selected the legacy direct-listener TCP fallback."
		}
	}
	return detail, backend.Close()
}

func loadCgroupProbeObject(plan kernelProbePlan) (string, error) {
	selfBypass, err := NewSelfBypass()
	if err != nil {
		return "Loads the generated cgroup programs without attaching cgroup hooks.", err
	}
	runtimeState := &cgroupRuntime{
		maps:                     make(map[string]*CiliumEBPF.Map),
		programs:                 make([]*CiliumEBPF.Program, cgroupProgramCount),
		enable_tcp:               plan.enableTCP,
		enable_udp:               plan.enableUDP,
		coarse_time_supported:    plan.enableUDP && features.HaveProgramHelper(CiliumEBPF.CGroupSockAddr, asm.FnKtimeGetCoarseNs) == nil,
		socket_storage_supported: plan.enableUDP && probeCgroupSocketStorageSupport(),
	}
	backend := &CgroupBackend{
		runtime:      runtimeState,
		redirectIPv4: netip.MustParsePrefix("127.0.0.0/8"),
		enableIPv6:   plan.enableIPv6,
	}
	if plan.enableIPv6 {
		backend.redirectIPv6 = netip.MustParsePrefix("fd00::/64")
	}
	if err = prepareCgroupMaps(runtimeState, DefaultCgroupMapCapacity(), 0, selfBypass.Map()); err == nil {
		runtimeState.programs, err = backend.loadCgroupObjectPrograms()
	}
	detail := "Loaded the generated cgroup programs and their real map specifications without attaching cgroup hooks."
	if err == nil {
		if runtimeState.coarse_time_supported {
			detail += " The coarse-time UDP variant loaded."
		}
		if runtimeState.socket_storage_supported {
			detail += " The socket-storage UDP variant loaded."
		}
	}
	return detail, errors.Join(err, backend.Close(), selfBypass.Close())
}

func loadSharedNetworkProbeObject(plan kernelProbePlan) (string, error) {
	config := SharedNetworkConfig{
		ListenerPort: 1,
		EnableTCP:    plan.enableTCP,
		EnableUDP:    plan.enableUDP,
		RedirectIPv4: netip.MustParsePrefix("127.0.0.0/8"),
		MapCapacity:  DefaultSharedNetworkMapCapacities(),
		UDPTimeout:   5 * time.Minute,
	}
	if plan.enableIPv6 {
		config.RedirectIPv6 = netip.MustParsePrefix("fd00::/64")
	}
	backend, err := PrepareSharedNetwork(nil, config)
	if err != nil {
		return "Loads the generated shared packet-rewrite programs and their real map specifications without attaching a classifier.", err
	}
	return "Loaded the generated shared packet-rewrite programs and their real map specifications without attaching a classifier.", backend.Close()
}

func loadFakeIPICMPProbeObject(plan kernelProbePlan) (string, error) {
	backend, err := PrepareFakeIPICMP(
		true,
		plan.localTC && plan.enableIPv6,
		(plan.sharedSocketAssign || plan.sharedPacketRewrite) && plan.enableIPv6,
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("fc00::/18"),
	)
	if err != nil {
		return "Loads the generated FakeIP ICMP programs without attaching a classifier.", err
	}
	return "Loaded the generated FakeIP ICMP programs without attaching a classifier.", backend.Close()
}
