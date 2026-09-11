//go:build with_ebpf && linux && ebpf_integration

package ebpf

import "testing"

func TestSelectedObjectLoadProbeIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load the selected eBPF objects without attaching them")
	tests := []struct {
		name string
		load func() (string, error)
	}{
		{
			name: "tc",
			load: func() (string, error) {
				return loadTCProbeObject(kernelProbePlan{
					localTC: true, sharedSocketAssign: true,
					enableTCP: true, enableUDP: true, enableIPv6: true,
				})
			},
		},
		{
			name: "cgroup",
			load: func() (string, error) {
				return loadCgroupProbeObject(kernelProbePlan{
					localCgroup: true, enableTCP: true, enableUDP: true, enableIPv6: true,
				})
			},
		},
		{
			name: "packet_rewrite",
			load: func() (string, error) {
				return loadSharedNetworkProbeObject(kernelProbePlan{
					sharedPacketRewrite: true, enableTCP: true, enableUDP: true, enableIPv6: true,
				})
			},
		},
		{
			name: "fakeip_icmp",
			load: func() (string, error) {
				return loadFakeIPICMPProbeObject(kernelProbePlan{
					localTC: true, enableIPv6: true,
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.load(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
