//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// FakeIPICMPBackend answers ICMP Echo Request packets destined to the
// configured FakeIP prefixes with a locally synthesized Echo Reply. It is a
// standalone backend, independent of TCBackend and SharedNetworkBackend,
// because fakeip_icmp.bpf.c is its own native object with its own control
// map (see that file's own comment for why it is not folded into either
// tc.bpf.c or shared_network.bpf.c) and because more than one caller needs
// to host it: TCBackend does, for local TC and shared socket_assign, and so
// does shared.data_plane: packet_rewrite, which has no TCBackend of its own
// at all. Prior to this type existing, only TCBackend could load this
// object, which meant a packet_rewrite-only inbound (no local interception,
// no socket_assign) had nothing to host the responder on even though the
// native object itself has always supported a "shared reply" path.
type FakeIPICMPBackend struct {
	access    sync.RWMutex
	runtime   *tcRuntime
	controlFD int
	closed    bool
}

const (
	fakeIPICMPProgramLocalEthernet = iota
	fakeIPICMPProgramLocalRawIP
	fakeIPICMPProgramSharedEthernet
	fakeIPICMPProgramSharedRawIP
	fakeIPICMPProgramCount
)

const (
	fakeIPICMPFlagEnabled    = 1 << 0
	fakeIPICMPFlagIPv4       = 1 << 1
	fakeIPICMPFlagLocalIPv6  = 1 << 2
	fakeIPICMPFlagSharedIPv6 = 1 << 3
	fakeIPICMPFlagFakeIPv4   = 1 << 4
	fakeIPICMPFlagFakeIPv6   = 1 << 5
)

// These three mirror native/fakeip_icmp.bpf.c's SB_FAKEIP_ICMP_STAT_* indices
// and SB_FAKEIP_ICMP_STAT_COUNT field for field; there is no generated
// binding for either side's constants, so this comment is the ABI contract
// between them. See that file's own comment on fakeip_icmp_stats for why
// ordinary non-ICMP traffic on the same interface is never counted here at
// all: PassThrough only ever counts an ICMP/ICMPv6 Echo Request this object
// examined and declined to answer.
const (
	fakeIPICMPStatReply          uint32 = 0
	fakeIPICMPStatPassThrough    uint32 = 1
	fakeIPICMPStatRewriteFailure uint32 = 2
	fakeIPICMPStatCount                 = 3
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

// loadFakeIPICMPResources loads the object's two maps and four programs. The
// maps are kept even though this object has no config-shaped sizing to do,
// because loadObjectMaps drops any map not named in its overrides — the
// overrides here exist to rename and place them, not to resize them.
func loadFakeIPICMPResources() (map[string]*CiliumEBPF.Map, []*CiliumEBPF.Program, error) {
	mapOverrides := map[string]mapSpecOverride{
		"fakeip_icmp_control": {name: "sb_icmp_ctl", mapType: CiliumEBPF.Array, maxEntries: 1},
		"fakeip_icmp_stats":   {name: "sb_icmp_stat", mapType: CiliumEBPF.PerCPUArray, maxEntries: fakeIPICMPStatCount},
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

// PrepareFakeIPICMP loads the fakeip_icmp object and populates its control
// map. ipv4Enabled, localIPv6Enabled, and sharedIPv6Enabled mirror the same
// address-family toggles the caller's own backend (TCBackend or
// SharedNetworkBackend) was configured with — this object answers on
// whichever families and roles its caller actually intercepts, not a
// second, independently-configured policy. At least one of fakeIPIPv4 or
// fakeIPIPv6 must be valid; callers are expected to have already refused
// fakeip_icmp=reply with neither configured (see protocol/ebpf's config
// validation), but this is checked again here so a backend can never exist
// in a state that can never match anything.
func PrepareFakeIPICMP(
	ipv4Enabled bool,
	localIPv6Enabled bool,
	sharedIPv6Enabled bool,
	fakeIPIPv4 netip.Prefix,
	fakeIPIPv6 netip.Prefix,
) (*FakeIPICMPBackend, error) {
	if !fakeIPIPv4.IsValid() && !fakeIPIPv6.IsValid() {
		return nil, E.New("fakeip_icmp requires a configured FakeIP prefix")
	}
	maps, programs, err := loadFakeIPICMPResources()
	if err != nil {
		return nil, E.Cause(err, "load fakeip_icmp eBPF resources")
	}
	control := fakeIPICMPControl{}
	if ipv4Enabled {
		control.Flags |= fakeIPICMPFlagIPv4
	}
	if localIPv6Enabled {
		control.Flags |= fakeIPICMPFlagLocalIPv6
	}
	if sharedIPv6Enabled {
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
	control.Flags |= fakeIPICMPFlagEnabled
	controlFD := maps["fakeip_icmp_control"].FD()
	zero := uint32(0)
	if err = updateMap(controlFD, unsafe.Pointer(&zero), unsafe.Pointer(&control)); err != nil {
		closeErr := E.Errors(closePrograms(programs), closeMaps(maps))
		return nil, E.Errors(E.Cause(err, "populate fakeip_icmp eBPF control"), closeErr)
	}
	return &FakeIPICMPBackend{
		runtime:   &tcRuntime{maps: maps, programs: programs},
		controlFD: controlFD,
	}, nil
}

func (b *FakeIPICMPBackend) program(index int) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.closed || index < 0 || index >= len(b.runtime.programs) {
		return nil
	}
	return b.runtime.programs[index]
}

func (b *FakeIPICMPBackend) programFD(index int) int {
	program := b.program(index)
	if program == nil {
		return -1
	}
	return program.FD()
}

func (b *FakeIPICMPBackend) LocalReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(fakeIPICMPProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(fakeIPICMPProgramLocalRawIP)
	default:
		return -1
	}
}

func (b *FakeIPICMPBackend) LocalReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(fakeIPICMPProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.program(fakeIPICMPProgramLocalRawIP)
	default:
		return nil
	}
}

func (b *FakeIPICMPBackend) SharedReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(fakeIPICMPProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(fakeIPICMPProgramSharedRawIP)
	default:
		return -1
	}
}

func (b *FakeIPICMPBackend) SharedReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(fakeIPICMPProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.program(fakeIPICMPProgramSharedRawIP)
	default:
		return nil
	}
}

// ReplyCount, PassThroughCount, and RewriteFailureCount read
// fakeip_icmp_stats' three categories -- see that map's own doc comment in
// native/fakeip_icmp.bpf.c. Each is a full PERCPU_ARRAY sum, computed fresh
// on every call; callers polling frequently should cache accordingly.
func (b *FakeIPICMPBackend) ReplyCount() (uint64, error) {
	return b.stat(fakeIPICMPStatReply)
}

func (b *FakeIPICMPBackend) PassThroughCount() (uint64, error) {
	return b.stat(fakeIPICMPStatPassThrough)
}

func (b *FakeIPICMPBackend) RewriteFailureCount() (uint64, error) {
	return b.stat(fakeIPICMPStatRewriteFailure)
}

func (b *FakeIPICMPBackend) stat(index uint32) (uint64, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.closed {
		return 0, errBackendClosed
	}
	statsMap := b.runtime.maps["fakeip_icmp_stats"]
	if statsMap == nil {
		return 0, errBackendClosed
	}
	var perCPU []uint64
	if err := statsMap.Lookup(&index, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range perCPU {
		total += value
	}
	return total, nil
}

// Close releases the object's maps and programs. Safe to call on a nil
// receiver or more than once.
func (b *FakeIPICMPBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return E.Errors(
		closePrograms(b.runtime.programs),
		closeMaps(b.runtime.maps),
	)
}
