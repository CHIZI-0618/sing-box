//go:build linux

package udpio

import (
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/buf"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func TestMMsgHdrABI(t *testing.T) {
	var header mmsghdr
	messageHeaderSize := unsafe.Sizeof(header.msgHdr)
	if offset := unsafe.Offsetof(header.msgLen); offset != messageHeaderSize {
		t.Fatalf("mmsghdr.msgLen offset=%d, want %d", offset, messageHeaderSize)
	}
	alignment := unsafe.Alignof(header.msgHdr)
	expectedSize := messageHeaderSize + unsafe.Sizeof(header.msgLen)
	expectedSize = (expectedSize + alignment - 1) &^ (alignment - 1)
	if size := unsafe.Sizeof(header); size != expectedSize {
		t.Fatalf("mmsghdr size=%d, want %d", size, expectedSize)
	}
}

func TestOOBBatchReadWriteIPv4(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err = enableIPv4PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reader, created := NewOOBBatchReader(receiver, 8, 256)
	if !created {
		t.Fatal("OOB batch reader was not created")
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	writer, created := NewOOBBatchWriter(sender)
	if !created {
		t.Fatal("OOB batch writer was not created")
	}
	sourceAddresses := []netip.Addr{
		netip.MustParseAddr("127.0.0.2"),
		netip.MustParseAddr("127.0.0.3"),
		netip.MustParseAddr("127.0.0.4"),
	}
	writeBuffers := make([]*buf.Buffer, len(sourceAddresses))
	oobs := make([][]byte, len(sourceAddresses))
	destinations := make([]netip.AddrPort, len(sourceAddresses))
	for index, source := range sourceAddresses {
		writeBuffers[index] = buf.As([]byte{byte(index + 1)}).ToOwned()
		oobs[index] = (&ipv4.ControlMessage{Src: net.IP(source.AsSlice())}).Marshal()
		destinations[index] = receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	defer buf.ReleaseMulti(writeBuffers)
	if err = writer.Write(writeBuffers, oobs, destinations); err != nil {
		t.Fatal(err)
	}

	readBuffers, readOOBs, sources, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(readBuffers)
	if len(readBuffers) != len(sourceAddresses) || len(readOOBs) != len(sourceAddresses) || len(sources) != len(sourceAddresses) {
		t.Fatalf("unexpected batch sizes: buffers=%d oobs=%d sources=%d", len(readBuffers), len(readOOBs), len(sources))
	}
	for index, buffer := range readBuffers {
		payloadIndex := int(buffer.Byte(0)) - 1
		if payloadIndex < 0 || payloadIndex >= len(sourceAddresses) {
			t.Fatalf("unexpected payload: %v", buffer.Bytes())
		}
		if sources[index].Addr != sourceAddresses[payloadIndex] {
			t.Fatalf("payload %d has source %v, want %v", payloadIndex, sources[index], sourceAddresses[payloadIndex])
		}
		if !containsIPv4PacketInfo(readOOBs[index]) {
			t.Fatalf("payload %d is missing IP_PKTINFO: %v", payloadIndex, readOOBs[index])
		}
	}
}

func TestOOBBatchReadWriteIPv6(t *testing.T) {
	receiver, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer receiver.Close()
	if err = enableIPv6PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reader, created := NewOOBBatchReader(receiver, 8, 256)
	if !created {
		t.Fatal("IPv6 OOB batch reader was not created")
	}
	sender, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	writer, created := NewOOBBatchWriter(sender)
	if !created {
		t.Fatal("IPv6 OOB batch writer was not created")
	}
	source := netip.IPv6Loopback()
	writeBuffers := []*buf.Buffer{
		buf.As([]byte("first")).ToOwned(),
		buf.As([]byte("second")).ToOwned(),
	}
	defer buf.ReleaseMulti(writeBuffers)
	packetInfo := (&ipv6.ControlMessage{Src: net.IP(source.AsSlice())}).Marshal()
	destination := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	if err = writer.Write(
		writeBuffers,
		[][]byte{packetInfo, packetInfo},
		[]netip.AddrPort{destination, destination},
	); err != nil {
		t.Fatal(err)
	}
	readBuffers, readOOBs, sources, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(readBuffers)
	if len(readBuffers) != 2 || len(readOOBs) != 2 || len(sources) != 2 {
		t.Fatalf("unexpected IPv6 batch sizes: %d/%d/%d", len(readBuffers), len(readOOBs), len(sources))
	}
	for index := range readBuffers {
		if sources[index].Addr != source || !containsIPv6PacketInfo(readOOBs[index]) {
			t.Fatalf("unexpected IPv6 message %d: source=%v oob=%v", index, sources[index], readOOBs[index])
		}
	}
}

func enableIPv4PacketInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err = rawConn.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	}); err != nil {
		return err
	}
	return socketErr
}

func enableIPv6PacketInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err = rawConn.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
	}); err != nil {
		return err
	}
	return socketErr
}

func containsIPv4PacketInfo(oob []byte) bool {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return false
	}
	for _, message := range messages {
		if message.Header.Level == unix.IPPROTO_IP && message.Header.Type == unix.IP_PKTINFO {
			return true
		}
	}
	return false
}

func containsIPv6PacketInfo(oob []byte) bool {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return false
	}
	for _, message := range messages {
		if message.Header.Level == unix.IPPROTO_IPV6 && message.Header.Type == unix.IPV6_PKTINFO {
			return true
		}
	}
	return false
}
