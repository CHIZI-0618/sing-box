//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
)

// fakeip_icmp answers ICMP Echo Request packets destined to the configured
// FakeIP prefixes with a locally synthesized Echo Reply. It is a separate
// native object from tc.bpf.c (see native/fakeip_icmp.bpf.c for why), loaded
// and torn down alongside the TC backend but tracked through its own runtime
// and its own small control map rather than sb_tc_control's.
const (
	tcFakeIPICMPProgramLocalEthernet = iota
	tcFakeIPICMPProgramLocalRawIP
	tcFakeIPICMPProgramSharedEthernet
	tcFakeIPICMPProgramSharedRawIP
	tcFakeIPICMPProgramCount
)

const (
	fakeIPICMPFlagEnabled    = 1 << 0
	fakeIPICMPFlagIPv4       = 1 << 1
	fakeIPICMPFlagLocalIPv6  = 1 << 2
	fakeIPICMPFlagSharedIPv6 = 1 << 3
	fakeIPICMPFlagFakeIPv4   = 1 << 4
	fakeIPICMPFlagFakeIPv6   = 1 << 5
)

// fakeIPICMPControl mirrors struct sb_fakeip_icmp_control in
// native/fakeip_icmp.bpf.c field for field; the _Static_assert in that file
// is this struct's ABI contract.
type fakeIPICMPControl struct {
	Flags            uint32
	FakeIPIPv4Prefix [4]byte
	FakeIPIPv4Mask   [4]byte
	FakeIPIPv6Prefix [16]byte
	FakeIPIPv6Mask   [16]byte
}

// loadFakeIPICMPResources loads the object's one map and four programs. The
// map is kept even though this object has no config-shaped sizing to do,
// because loadObjectMaps drops any map not named in its overrides — the
// override here exists to rename and place it, not to resize it.
func loadFakeIPICMPResources() (map[string]*CiliumEBPF.Map, []*CiliumEBPF.Program, error) {
	mapOverrides := map[string]mapSpecOverride{
		"fakeip_icmp_control": {name: "sb_icmp_ctl", mapType: CiliumEBPF.Array, maxEntries: 1},
	}
	maps, err := loadObjectMaps(loadFakeIPICMP, mapOverrides)
	if err != nil {
		return nil, nil, err
	}
	selections := []programSelection{
		{section: "classifier/fakeip_icmp_local_reply_ethernet", name: "sb_icmp_lcl_e"},
		{section: "classifier/fakeip_icmp_local_reply_raw_ip", name: "sb_icmp_lcl_r"},
		{section: "classifier/fakeip_icmp_shared_reply_ethernet", name: "sb_icmp_shr_e"},
		{section: "classifier/fakeip_icmp_shared_reply_raw_ip", name: "sb_icmp_shr_r"},
	}
	programs, err := loadObjectPrograms(loadFakeIPICMP, maps, selections)
	if err != nil {
		return nil, nil, E.Errors(err, closeMaps(maps))
	}
	return maps, programs, nil
}

// enableFakeIPICMPLocked loads the fakeip_icmp object and populates its
// control map from the same compiled FakeIP prefixes and address-family
// toggles prepareTC already computed for sb_tc_control — not a second copy
// of that computation. Called at most once, from prepareTC, only when
// fakeip_icmp=reply is configured; a backend built without it never touches
// this object at all, so turning the feature off costs nothing beyond the
// config check itself.
func (b *TCBackend) enableFakeIPICMPLocked(config TCConfig, fakeIPIPv4, fakeIPIPv6 netip.Prefix) error {
	maps, programs, err := loadFakeIPICMPResources()
	if err != nil {
		return E.Cause(err, "load fakeip_icmp eBPF resources")
	}
	control := fakeIPICMPControl{}
	if config.EnableIPv4 {
		control.Flags |= fakeIPICMPFlagIPv4
	}
	if config.EnableLocalIPv6 {
		control.Flags |= fakeIPICMPFlagLocalIPv6
	}
	if config.EnableSharedIPv6 {
		control.Flags |= fakeIPICMPFlagSharedIPv6
	}
	if fakeIPIPv4.IsValid() {
		control.Flags |= fakeIPICMPFlagFakeIPv4
		control.FakeIPIPv4Prefix = fakeIPIPv4.Addr().As4()
		control.FakeIPIPv4Mask = prefixMask4(fakeIPIPv4.Bits())
	}
	if fakeIPIPv6.IsValid() {
		control.Flags |= fakeIPICMPFlagFakeIPv6
		control.FakeIPIPv6Prefix = fakeIPIPv6.Addr().As16()
		control.FakeIPIPv6Mask = prefixMask16(fakeIPIPv6.Bits())
	}
	if control.Flags&(fakeIPICMPFlagFakeIPv4|fakeIPICMPFlagFakeIPv6) == 0 {
		// prepareCgroupBackend-adjacent validation is expected to have refused
		// this already; refusing again here means a caller that reaches this
		// point some other way still cannot end up with a live object that can
		// never match anything.
		closeErr := E.Errors(closePrograms(programs), closeMaps(maps))
		return E.Errors(E.New("fakeip_icmp requires a configured FakeIP prefix"), closeErr)
	}
	control.Flags |= fakeIPICMPFlagEnabled
	controlFD := maps["fakeip_icmp_control"].FD()
	zero := uint32(0)
	if err = updateMap(controlFD, unsafe.Pointer(&zero), unsafe.Pointer(&control)); err != nil {
		closeErr := E.Errors(closePrograms(programs), closeMaps(maps))
		return E.Errors(E.Cause(err, "populate fakeip_icmp eBPF control"), closeErr)
	}
	b.fakeipICMPRuntime = &tcRuntime{maps: maps, programs: programs}
	b.fakeipICMPControlFD = controlFD
	return nil
}

// FakeIPICMPEnabled reports whether this backend loaded the fakeip_icmp
// object. protocol/ebpf's TC data plane uses this to decide whether to
// attach the extra local/shared reply filters at all.
func (b *TCBackend) FakeIPICMPEnabled() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fakeipICMPRuntime != nil
}

func (b *TCBackend) fakeIPICMPProgramFD(index int) int {
	b.access.RLock()
	defer b.access.RUnlock()
	if b.fakeipICMPRuntime == nil || index < 0 || index >= len(b.fakeipICMPRuntime.programs) ||
		b.fakeipICMPRuntime.programs[index] == nil {
		return -1
	}
	return b.fakeipICMPRuntime.programs[index].FD()
}

func (b *TCBackend) fakeIPICMPProgram(index int) *CiliumEBPF.Program {
	b.access.RLock()
	defer b.access.RUnlock()
	if b.fakeipICMPRuntime == nil || index < 0 || index >= len(b.fakeipICMPRuntime.programs) {
		return nil
	}
	return b.fakeipICMPRuntime.programs[index]
}

func (b *TCBackend) FakeIPICMPLocalReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.fakeIPICMPProgramFD(tcFakeIPICMPProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.fakeIPICMPProgramFD(tcFakeIPICMPProgramLocalRawIP)
	default:
		return -1
	}
}

func (b *TCBackend) FakeIPICMPLocalReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.fakeIPICMPProgram(tcFakeIPICMPProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.fakeIPICMPProgram(tcFakeIPICMPProgramLocalRawIP)
	default:
		return nil
	}
}

func (b *TCBackend) FakeIPICMPSharedReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.fakeIPICMPProgramFD(tcFakeIPICMPProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.fakeIPICMPProgramFD(tcFakeIPICMPProgramSharedRawIP)
	default:
		return -1
	}
}

func (b *TCBackend) FakeIPICMPSharedReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.fakeIPICMPProgram(tcFakeIPICMPProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.fakeIPICMPProgram(tcFakeIPICMPProgramSharedRawIP)
	default:
		return nil
	}
}

// closeFakeIPICMPLocked releases the object's maps and programs. Called from
// TCBackend.Close while b.access is already held; a nil runtime (the feature
// was never enabled) is a no-op.
func (b *TCBackend) closeFakeIPICMPLocked() error {
	if b.fakeipICMPRuntime == nil {
		return nil
	}
	closeErr := E.Errors(
		closePrograms(b.fakeipICMPRuntime.programs),
		closeMaps(b.fakeipICMPRuntime.maps),
	)
	b.fakeipICMPRuntime = nil
	b.fakeipICMPControlFD = -1
	return closeErr
}
