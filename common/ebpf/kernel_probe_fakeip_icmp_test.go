//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// TestProbeKernelFakeIPICMPOnlyWhenRequested confirms the probe report gains
// fakeip_icmp findings only when asked, and that on a real kernel (this is
// not a table of assumed results — ProbeKernel runs the real
// features.HaveProgramHelper checks) every helper the object needs comes
// back supported, matching the real verifier-accepted load proven in
// tc_fakeip_icmp_test.go and the real attach proven in
// protocol/ebpf's netns tests.
func TestProbeKernelFakeIPICMPOnlyWhenRequested(t *testing.T) {
	without, err := ProbeKernel(KernelProbeOptions{Mode: KernelProbeModeLocal, LocalDataPlane: KernelProbeDataPlaneTC})
	if err != nil {
		t.Fatalf("probe without fakeip_icmp: %v", err)
	}
	for _, finding := range without.Findings {
		if finding.Scope == "fakeip_icmp" {
			t.Fatalf("found a fakeip_icmp finding (%+v) without asking for one", finding)
		}
	}

	with, err := ProbeKernel(KernelProbeOptions{
		Mode: KernelProbeModeLocal, LocalDataPlane: KernelProbeDataPlaneTC,
		FakeIPICMPReply: true,
	})
	if err != nil {
		t.Fatalf("probe with fakeip_icmp: %v", err)
	}
	found := 0
	foundPerCPUScratch := false
	foundPacketWrite := false
	for _, finding := range with.Findings {
		if finding.Scope != "fakeip_icmp" {
			continue
		}
		found++
		switch finding.Feature {
		case "BPF map type " + CiliumEBPF.PerCPUArray.String():
			foundPerCPUScratch = true
		case "bpf_skb_store_bytes for SchedCLS":
			foundPacketWrite = true
		}
		if finding.Status == KernelProbeFail {
			t.Fatalf("fakeip_icmp finding reported unsupported on this kernel: %+v", finding)
		}
	}
	if found == 0 {
		t.Fatal("no fakeip_icmp findings were reported after asking for them")
	}
	if !foundPerCPUScratch || !foundPacketWrite {
		t.Fatalf("fakeip_icmp object requirements are incomplete: per_cpu_array=%v skb_store_bytes=%v", foundPerCPUScratch, foundPacketWrite)
	}
}
