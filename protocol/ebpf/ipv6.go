//go:build with_ebpf && (linux || android)

package ebpf

func (i *Inbound) cgroupIPv6Enabled() bool {
	return i.localEnabled && i.localDataPlane == localDataPlaneCgroup && i.localIPv6 && i.redirectIPv6Prefix.IsValid()
}

func (i *Inbound) requiresIPv6Redirect() bool {
	return i.localEnabled && i.localDataPlane == localDataPlaneCgroup && i.localIPv6 ||
		i.sharedEnabled && i.sharedDataPlane == sharedDataPlanePacketRewrite && i.sharedIPv6
}

func (i *Inbound) sharedRewriteIPv6Enabled() bool {
	return i.sharedEnabled && i.sharedDataPlane == sharedDataPlanePacketRewrite && i.sharedIPv6 && i.redirectIPv6Prefix.IsValid()
}
