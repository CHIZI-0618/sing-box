//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpNATTestConnection struct {
	conn   N.PacketConn
	source M.Socksaddr
	key    udpSessionKey
}

type udpNATTestHandler struct {
	connections chan udpNATTestConnection
}

func (h *udpNATTestHandler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	source M.Socksaddr,
	_ M.Socksaddr,
	_ N.CloseHandlerFunc,
) {
	key, _ := udpSessionKeyFromContext(ctx)
	h.connections <- udpNATTestConnection{conn: conn, source: source, key: key}
}

type udpNATTestWriter struct{}

func (udpNATTestWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func TestUDPNATServiceSeparatesKernelIdentities(t *testing.T) {
	handler := &udpNATTestHandler{connections: make(chan udpNATTestConnection, 2)}
	service := newUDPNATService(handler, func(
		_ M.Socksaddr,
		_ M.Socksaddr,
		_ any,
	) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
		return true, context.Background(), udpNATTestWriter{}, nil
	}, time.Minute, false)
	t.Cleanup(service.Purge)

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	firstKey := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC, SocketCookie: 1}
	secondKey := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC, SocketCookie: 2}
	service.NewPacket(firstKey, [][]byte{[]byte("first")}, source, destination)
	service.NewPacket(secondKey, [][]byte{[]byte("second")}, source, destination)

	first := <-handler.connections
	second := <-handler.connections
	if first.conn == second.conn {
		t.Fatal("different eBPF identities shared one UDP NAT connection")
	}
	if first.source != source || second.source != source {
		t.Fatalf("synthetic UDP NAT key leaked to handler: %v %v", first.source, second.source)
	}
	if M.SocksaddrFromNet(first.conn.LocalAddr()) != source || M.SocksaddrFromNet(second.conn.LocalAddr()) != source {
		t.Fatalf("synthetic UDP NAT address leaked through LocalAddr: %v %v", first.conn.LocalAddr(), second.conn.LocalAddr())
	}
	if _, loaded := first.conn.(N.PacketBatchReadWaitCreator); !loaded {
		t.Fatal("key adapter hid udpnat2 batch read support")
	}
	if _, loaded := first.conn.(N.PacketBatchWriteCreator); !loaded {
		t.Fatal("key adapter hid udpnat2 batch write support")
	}
	keys := map[udpSessionKey]bool{first.key: true, second.key: true}
	if !keys[firstKey] || !keys[secondKey] {
		t.Fatalf("handler received unexpected session keys: %v %v", first.key, second.key)
	}
}
