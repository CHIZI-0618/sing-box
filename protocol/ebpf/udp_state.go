//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	udpClientShardCount = 16
	udpReplyAliasLimit  = 64

	// udpReplySocketShardCapacity bounds each shard's transparent reply
	// sockets independently, so the pool's total footprint is bounded
	// (udpClientShardCount * udpReplySocketShardCapacity sockets/FDs) without
	// needing a cross-shard lock on every get(). One reply socket exists per
	// distinct original destination ever contacted through the non-cgroup
	// data planes, which without a bound grows for as long as the process
	// keeps running and clients keep reaching new destinations.
	udpReplySocketShardCapacity = 256

	// udpReplySocketIdleTimeout and udpReplySocketSweepInterval govern the
	// background reclaim in addition to the capacity-triggered one in get():
	// a socket unused for this long is closed even before its shard fills up,
	// so idle sockets do not simply wait for capacity pressure to be reclaimed.
	udpReplySocketIdleTimeout   = 5 * time.Minute
	udpReplySocketSweepInterval = time.Minute
)

type udpClientTable struct {
	clientShards [udpClientShardCount]udpClientShard
}

type udpClientShard struct {
	access  sync.RWMutex
	clients map[netip.AddrPort]*udpClientState
}

type udpClientState struct {
	access          sync.RWMutex
	sourceMAC       net.HardwareAddr
	socketCookie    uint64
	bindings        map[netip.AddrPort]udpRedirectBinding
	replyAliasCount uint16
	closed          bool
	cgroupDataPlane bool
	cgroupOriginals map[netip.Addr]commonEBPF.OriginalDestination
}

type udpRedirectBinding struct {
	replyAlias      bool
	redirectAddress netip.Addr
	packetInfo      []byte
	connected       bool
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	state, loaded := shard.clients[client]
	shard.access.RUnlock()
	return state, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if state, loaded := t.load(client); loaded {
		return state
	}
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[client]; loaded {
		return state
	}
	if shard.clients == nil {
		shard.clients = make(map[netip.AddrPort]*udpClientState)
	}
	state := &udpClientState{
		bindings:        make(map[netip.AddrPort]udpRedirectBinding),
		cgroupOriginals: make(map[netip.Addr]commonEBPF.OriginalDestination),
	}
	shard.clients[client] = state
	return state
}

func (t *udpClientTable) cachedCgroupOriginal(client netip.AddrPort, redirectAddress netip.Addr) (commonEBPF.OriginalDestination, bool) {
	state, loaded := t.load(client)
	if !loaded {
		return commonEBPF.OriginalDestination{}, false
	}
	state.access.RLock()
	original, loaded := state.cgroupOriginals[redirectAddress]
	state.access.RUnlock()
	return original, loaded
}

func (t *udpClientTable) setCgroupBinding(client netip.AddrPort, original commonEBPF.OriginalDestination, redirectAddress netip.Addr) {
	state := t.loadOrCreate(client)
	state.access.Lock()
	state.cgroupOriginals[redirectAddress] = original
	state.socketCookie = original.SocketCookie
	state.cgroupDataPlane = true
	state.bindings[original.Destination] = udpRedirectBinding{
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
		connected:       original.ConnectedUDP,
	}
	state.access.Unlock()
}

func (t *udpClientTable) setCgroupReplyBinding(client netip.AddrPort, expected *udpClientState, destination netip.AddrPort, redirectAddress netip.Addr) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.cgroupOriginals[redirectAddress] = commonEBPF.OriginalDestination{Destination: destination}
	expected.cgroupDataPlane = true
	expected.bindings[destination] = udpRedirectBinding{
		replyAlias:      true,
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
	}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) clientShard(client netip.AddrPort) *udpClientShard {
	return &t.clientShards[shardIndexForAddrPort(client, udpClientShardCount)]
}

// shardIndexForAddrPort distributes addr:port pairs across shardCount (a
// power of two) shards by hashing every address byte together with the
// port, not the port alone. A port-only key collapses onto a single shard
// whenever many distinct addresses happen to share one port -- exactly the
// common case for both callers of this function: UDP destinations
// overwhelmingly cluster on a handful of well-known ports (443, 53, ...)
// while varying in address, and independent client hosts can coincidentally
// reuse the same ephemeral source port for unrelated connections.
//
// This is a statistical improvement over the port-only key for realistic,
// naturally-varying traffic (see the package's shard-distribution tests),
// not a guarantee of even placement for every possible input set: FNV-1a is
// not a cryptographic hash, so a party able to choose destination addresses
// specifically to collide under it could still concentrate them onto one
// shard. This function only changes how inputs are distributed across
// shards; it does not change what happens once a shard fills. Of this
// function's two callers, only udpReplySocketPool enforces a per-shard
// capacity at all (udpReplySocketShardCapacity, with capacity-triggered
// eviction and rejection in get()) -- the client tables
// (udpClientTable/sharedUDPClientTable) have no capacity bound on a shard's
// map and grow with however many sessions are actually active. For the
// reply socket pool specifically: its usable total capacity before any
// single destination pattern hits a capacity rejection on its own shard
// still depends on how evenly that traffic happens to hash, not simply on
// udpClientShardCount * udpReplySocketShardCapacity -- that product is the
// pool's absolute ceiling under perfectly even placement, not a promised
// floor for every traffic shape.
func shardIndexForAddrPort(addrPort netip.AddrPort, shardCount int) int {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211
	hash := uint64(offset64)
	for _, b := range addrPort.Addr().As16() {
		hash ^= uint64(b)
		hash *= prime64
	}
	port := addrPort.Port()
	hash ^= uint64(port)
	hash *= prime64
	hash ^= uint64(port >> 8)
	hash *= prime64
	return int(hash & uint64(shardCount-1))
}

// count reports the number of tracked UDP clients, for diagnostics. It locks
// each shard in turn rather than all at once, so this is a point-in-time
// estimate under concurrent traffic, not a value consistent with any single
// instant -- adequate for a diagnostics counter, not for anything that would
// act on the exact number.
func (t *udpClientTable) count() int {
	total := 0
	for index := range t.clientShards {
		shard := &t.clientShards[index]
		shard.access.RLock()
		total += len(shard.clients)
		shard.access.RUnlock()
	}
	return total
}

func (t *udpClientTable) setDirectBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
	socketCookie uint64,
) {
	state := t.loadOrCreate(client)
	state.access.Lock()
	defer state.access.Unlock()
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.socketCookie = socketCookie
	state.bindings[destination] = udpRedirectBinding{}
}

func (t *udpClientTable) setDirectReplyBinding(
	client netip.AddrPort,
	expected *udpClientState,
	destination netip.AddrPort,
) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed {
		return false
	}
	if _, loaded := expected.bindings[destination]; loaded {
		return true
	}
	if expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.bindings[destination] = udpRedirectBinding{replyAlias: true}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) []netip.Addr {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expected {
		return nil
	}
	delete(shard.clients, client)
	expected.access.Lock()
	redirects := make([]netip.Addr, 0, len(expected.cgroupOriginals))
	for address := range expected.cgroupOriginals {
		redirects = append(redirects, address)
	}
	expected.closed = true
	clear(expected.bindings)
	clear(expected.cgroupOriginals)
	expected.cgroupDataPlane = false
	expected.replyAliasCount = 0
	expected.access.Unlock()
	return redirects
}

func (s *udpClientState) isCgroupDataPlane() bool {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.cgroupDataPlane
}

func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}

// udpReplySocketPool shares transparent reply sockets between all clients of
// an inbound. A socket bound to an original destination can send replies to any
// client, so keeping it at client-state scope needlessly multiplies sockets.
//
// Each shard is capacity-bounded (udpReplySocketShardCapacity) and idle
// sockets (unused for udpReplySocketIdleTimeout) are reclaimed by a
// background sweeper as well as opportunistically when a shard is full and a
// new destination needs a socket. get() marks the entry it returns as in use
// until the caller invokes the release func it also returns; eviction skips
// any entry still in use, so a send in flight is never handed a closed
// connection by a reclaim racing it from another goroutine. Full-pool
// close()/reset() are unconditional instead: those are deliberate,
// whole-pool lifecycle events (inbound shutdown, network change) the caller
// already treats a resulting write error as expected, not an eviction a send
// could be caught unaware by.
type udpReplySocketPool struct {
	shards      [udpClientShardCount]udpReplySocketShard
	closed      atomic.Bool
	stats       udpReplySocketPoolStats
	sweepAccess sync.Mutex
	sweepCancel context.CancelFunc
}

type udpReplySocketShard struct {
	access  sync.Mutex
	sockets map[netip.AddrPort]*udpReplySocketEntry
}

type udpReplySocketEntry struct {
	conn     *net.UDPConn
	lastUsed atomic.Int64 // UnixNano, updated on every get()
	inUse    atomic.Int32 // active senders; eviction skips entries > 0
}

// udpReplySocketPoolStats are the counters item 8 of the eBPF inbound
// reliability work exposes through diagnostics: current pressure (count vs.
// the fixed per-shard capacity), the high-water mark, and how many times
// this pool reclaimed or refused a socket.
type udpReplySocketPoolStats struct {
	count            atomic.Int64
	peak             atomic.Int64
	evicted          atomic.Int64
	capacityRejected atomic.Int64
}

// udpReplySocketPoolSnapshot is a point-in-time, non-atomic-together read of
// udpReplySocketPoolStats for diagnostics/logging.
type udpReplySocketPoolSnapshot struct {
	Count            int64 `json:"count"`
	Peak             int64 `json:"peak"`
	Evicted          int64 `json:"evicted"`
	CapacityRejected int64 `json:"capacity_rejected"`
}

func (p *udpReplySocketPool) snapshot() udpReplySocketPoolSnapshot {
	return udpReplySocketPoolSnapshot{
		Count:            p.stats.count.Load(),
		Peak:             p.stats.peak.Load(),
		Evicted:          p.stats.evicted.Load(),
		CapacityRejected: p.stats.capacityRejected.Load(),
	}
}

func (p *udpReplySocketPool) get(
	source netip.AddrPort,
	create func(netip.AddrPort) (*net.UDPConn, error),
) (*net.UDPConn, func(), error) {
	if p.closed.Load() {
		return nil, nil, net.ErrClosed
	}
	shard := &p.shards[p.shardIndex(source)]
	shard.access.Lock()
	if p.closed.Load() {
		shard.access.Unlock()
		return nil, nil, net.ErrClosed
	}
	if entry := shard.sockets[source]; entry != nil {
		entry.lastUsed.Store(time.Now().UnixNano())
		entry.inUse.Add(1)
		shard.access.Unlock()
		return entry.conn, releaseUDPReplySocketEntry(entry), nil
	}
	if len(shard.sockets) >= udpReplySocketShardCapacity && !p.evictOneIdleLocked(shard) {
		shard.access.Unlock()
		p.stats.capacityRejected.Add(1)
		return nil, nil, E.New(
			"UDP eBPF reply socket pool shard is at capacity (", udpReplySocketShardCapacity, "); ",
			"every socket in it is currently in use",
		)
	}
	socket, err := create(source)
	if err != nil {
		shard.access.Unlock()
		return nil, nil, err
	}
	entry := &udpReplySocketEntry{conn: socket}
	entry.lastUsed.Store(time.Now().UnixNano())
	entry.inUse.Store(1)
	if shard.sockets == nil {
		shard.sockets = make(map[netip.AddrPort]*udpReplySocketEntry)
	}
	shard.sockets[source] = entry
	shard.access.Unlock()
	p.addCount(1)
	return socket, releaseUDPReplySocketEntry(entry), nil
}

func releaseUDPReplySocketEntry(entry *udpReplySocketEntry) func() {
	return func() { entry.inUse.Add(-1) }
}

func (p *udpReplySocketPool) addCount(delta int64) {
	updated := p.stats.count.Add(delta)
	for {
		peak := p.stats.peak.Load()
		if updated <= peak || p.stats.peak.CompareAndSwap(peak, updated) {
			return
		}
	}
}

// evictOneIdleLocked closes and removes one entry with no sender currently
// using it, to make room for a new destination once a shard is full. Called
// with shard.access already held. Map iteration order is randomized rather
// than strictly least-recently-used, which is enough to keep the shard
// usable under sustained pressure without a second per-entry ordering
// structure to maintain.
func (p *udpReplySocketPool) evictOneIdleLocked(shard *udpReplySocketShard) bool {
	for source, entry := range shard.sockets {
		if entry.inUse.Load() > 0 {
			continue
		}
		_ = entry.conn.Close()
		delete(shard.sockets, source)
		p.stats.count.Add(-1)
		p.stats.evicted.Add(1)
		return true
	}
	return false
}

func (p *udpReplySocketPool) shardIndex(source netip.AddrPort) int {
	return shardIndexForAddrPort(source, udpClientShardCount)
}

// startSweeper starts the background idle-socket reclaim, tied to ctx so it
// stops on its own if the inbound's own context is ever canceled without an
// explicit stopSweeper call. A second call before stopSweeper is a no-op:
// the pool already has a sweeper running.
func (p *udpReplySocketPool) startSweeper(ctx context.Context) {
	p.sweepAccess.Lock()
	defer p.sweepAccess.Unlock()
	if p.sweepCancel != nil {
		return
	}
	sweepCtx, cancel := context.WithCancel(ctx)
	p.sweepCancel = cancel
	go p.runSweeper(sweepCtx)
}

// stopSweeper stops the background idle-socket reclaim. Safe to call even if
// startSweeper was never called, and safe to call more than once.
func (p *udpReplySocketPool) stopSweeper() {
	p.sweepAccess.Lock()
	cancel := p.sweepCancel
	p.sweepCancel = nil
	p.sweepAccess.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (p *udpReplySocketPool) runSweeper(ctx context.Context) {
	ticker := time.NewTicker(udpReplySocketSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.sweepIdle(udpReplySocketIdleTimeout)
		}
	}
}

// sweepIdle closes every socket that has been idle (unused, and not
// currently in use by an in-flight send) for at least idleTimeout, so a
// destination that stops being contacted does not simply hold its socket
// until the shard happens to fill up.
func (p *udpReplySocketPool) sweepIdle(idleTimeout time.Duration) {
	if p.closed.Load() {
		return
	}
	deadline := time.Now().Add(-idleTimeout).UnixNano()
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for source, entry := range shard.sockets {
			if entry.inUse.Load() > 0 || entry.lastUsed.Load() > deadline {
				continue
			}
			_ = entry.conn.Close()
			delete(shard.sockets, source)
			p.stats.count.Add(-1)
			p.stats.evicted.Add(1)
		}
		shard.access.Unlock()
	}
}

func (p *udpReplySocketPool) close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.closeSockets()
}

// reset closes sockets tied to the previous network path while keeping the
// pool usable for the next interface generation.
func (p *udpReplySocketPool) reset() error {
	if p == nil || p.closed.Load() {
		return nil
	}
	return p.closeSockets()
}

func (p *udpReplySocketPool) closeSockets() error {
	var closeErr error
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for source, entry := range shard.sockets {
			closeErr = errors.Join(closeErr, entry.conn.Close())
			delete(shard.sockets, source)
			p.stats.count.Add(-1)
		}
		shard.access.Unlock()
	}
	return closeErr
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) hasAddressFamily(ipv4 bool) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	for destination := range s.bindings {
		if destination.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}

func (s *udpClientState) processSocketCookie() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.socketCookie
}
