//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
)

type udpSessionScope uint8

const (
	udpSessionScopeLocalCgroup udpSessionScope = iota + 1
	udpSessionScopeLocalTC
	udpSessionScopeSharedTC
	udpSessionScopeSharedRewrite
)

// udpSessionKey keeps kernel identities which are stronger than the source
// address in the userspace association key. Source alone is ambiguous for
// SO_REUSEPORT sockets and when the same downstream address appears on more
// than one ingress interface.
type udpSessionKey struct {
	Source         netip.AddrPort
	Scope          udpSessionScope
	SocketCookie   uint64
	InterfaceIndex uint32
}

type udpNATPacketMetadata struct {
	key udpSessionKey
}

type udpNATContextKey struct{}

type udpNATContext struct {
	source   M.Socksaddr
	metadata udpNATPacketMetadata
}

func udpSessionKeyFromContext(ctx context.Context) (udpSessionKey, bool) {
	value, loaded := ctx.Value(udpNATContextKey{}).(udpNATContext)
	if !loaded {
		return udpSessionKey{}, false
	}
	return value.metadata.key, true
}

type udpNATSession struct {
	key           udpSessionKey
	alias         M.Socksaddr
	source        M.Socksaddr
	generation    uint64
	inFlight      int
	deletePending bool
}

// udpNATService adapts udpnat2's source-address cache to the stronger eBPF
// session key without carrying a private copy of sing's UDP NAT machinery.
// The synthetic address is only an internal cache key; handlers continue to
// receive the real source address through udpNATHandler.
type udpNATService struct {
	access   sync.Mutex
	sessions map[udpSessionKey]*udpNATSession
	nextID   uint64
	service  *udpnat.Service
	handler  N.UDPConnectionHandlerEx
	prepare  udpnat.PrepareFunc
}

func newUDPNATService(
	handler N.UDPConnectionHandlerEx,
	prepare udpnat.PrepareFunc,
	timeout time.Duration,
	shared bool,
) *udpNATService {
	service := &udpNATService{
		sessions: make(map[udpSessionKey]*udpNATSession),
		handler:  handler,
		prepare:  prepare,
	}
	service.service = udpnat.New(udpNATHandler{service}, service.prepareSession, timeout, shared)
	return service
}

func (s *udpNATService) NewPacket(
	key udpSessionKey,
	bufferSlices [][]byte,
	source M.Socksaddr,
	destination M.Socksaddr,
) {
	session := s.beginSession(key, source)
	defer s.endSession(session)
	s.service.NewPacket(
		bufferSlices,
		session.alias,
		destination,
		udpNATPacketMetadata{key: key},
	)
}

func (s *udpNATService) beginSession(key udpSessionKey, source M.Socksaddr) *udpNATSession {
	s.access.Lock()
	defer s.access.Unlock()
	session := s.sessions[key]
	if session == nil {
		s.nextID++
		if s.nextID == 0 {
			panic("eBPF UDP NAT session identifier exhausted")
		}
		var address [16]byte
		address[0] = 0xfd
		for index := 0; index < 8; index++ {
			address[15-index] = byte(s.nextID >> (index * 8))
		}
		session = &udpNATSession{
			key:    key,
			alias:  M.SocksaddrFromNetIP(netip.AddrPortFrom(netip.AddrFrom16(address), 1)),
			source: source,
		}
		s.sessions[key] = session
	}
	session.inFlight++
	return session
}

func (s *udpNATService) endSession(session *udpNATSession) {
	s.access.Lock()
	session.inFlight--
	if session.inFlight == 0 && session.deletePending && s.sessions[session.key] == session {
		delete(s.sessions, session.key)
	}
	s.access.Unlock()
}

func (s *udpNATService) prepareSession(
	_ M.Socksaddr,
	destination M.Socksaddr,
	userData any,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	metadata, loaded := userData.(udpNATPacketMetadata)
	if !loaded {
		return false, nil, nil, nil
	}
	s.access.Lock()
	session := s.sessions[metadata.key]
	if session == nil {
		s.access.Unlock()
		return false, nil, nil, nil
	}
	session.generation++
	generation := session.generation
	session.deletePending = false
	source := session.source
	s.access.Unlock()
	ok, ctx, writer, onClose := s.prepare(source, destination, metadata)
	if !ok {
		s.closeSession(session, generation)
		return false, nil, nil, nil
	}
	ctx = context.WithValue(ctx, udpNATContextKey{}, udpNATContext{source: source, metadata: metadata})
	onClose = N.AppendClose(onClose, func(error) {
		s.closeSession(session, generation)
	})
	return true, ctx, writer, onClose
}

func (s *udpNATService) closeSession(session *udpNATSession, generation uint64) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.sessions[session.key] != session || session.generation != generation {
		return
	}
	if session.inFlight > 0 {
		session.deletePending = true
		return
	}
	delete(s.sessions, session.key)
}

func (s *udpNATService) Purge() {
	s.service.Purge()
	s.access.Lock()
	clear(s.sessions)
	s.access.Unlock()
}

type udpNATHandler struct {
	service *udpNATService
}

func (h udpNATHandler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	_ M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	value, loaded := ctx.Value(udpNATContextKey{}).(udpNATContext)
	if !loaded {
		_ = conn.Close()
		if onClose != nil {
			onClose(context.Canceled)
		}
		return
	}
	h.service.handler.NewPacketConnectionEx(ctx, &udpNATPacketConn{
		PacketConn: conn,
		localAddr:  value.source.UDPAddr(),
	}, value.source, destination, onClose)
}

var _ N.UDPConnectionHandlerEx = udpNATHandler{}

// udpNATPacketConn keeps the synthetic cache address private while forwarding
// the optional udpnat2 fast paths and timeout control used by sing-box.
type udpNATPacketConn struct {
	N.PacketConn
	localAddr net.Addr
}

func (c *udpNATPacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *udpNATPacketConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	creator, loaded := c.PacketConn.(N.PacketBatchReadWaitCreator)
	if !loaded {
		return nil, false
	}
	return creator.CreatePacketBatchReadWaiter()
}

func (c *udpNATPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	creator, loaded := c.PacketConn.(N.PacketBatchWriteCreator)
	if !loaded {
		return nil, false
	}
	return creator.CreatePacketBatchWriter()
}

func (c *udpNATPacketConn) Timeout() time.Duration {
	timeoutConn, loaded := c.PacketConn.(canceler.PacketConn)
	if !loaded {
		return 0
	}
	return timeoutConn.Timeout()
}

func (c *udpNATPacketConn) SetTimeout(timeout time.Duration) bool {
	timeoutConn, loaded := c.PacketConn.(canceler.PacketConn)
	return loaded && timeoutConn.SetTimeout(timeout)
}

func (c *udpNATPacketConn) Upstream() any {
	return c.PacketConn
}

var (
	_ N.PacketBatchReadWaitCreator = (*udpNATPacketConn)(nil)
	_ N.PacketBatchWriteCreator    = (*udpNATPacketConn)(nil)
	_ canceler.PacketConn          = (*udpNATPacketConn)(nil)
)
