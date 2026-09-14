//go:build linux

package udpio

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

type mmsghdr struct {
	msgHdr unix.Msghdr
	msgLen uint32
}

type oobBatchReader struct {
	rawConn        syscall.RawConn
	batchSize      int
	oobSize        int
	readErr        error
	readN          int
	buffers        []*buf.Buffer
	oobs           [][]byte
	controlBuffers [][]byte
	sources        []M.Socksaddr
	names          []unix.RawSockaddrAny
	iovecs         []unix.Iovec
	messages       []mmsghdr
}

func newOOBBatchReader(conn *net.UDPConn, batchSize int, oobSize int) (OOBBatchReader, bool) {
	if conn == nil || batchSize <= 0 || oobSize <= 0 {
		return nil, false
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, false
	}
	return &oobBatchReader{
		rawConn:        rawConn,
		batchSize:      batchSize,
		oobSize:        oobSize,
		buffers:        make([]*buf.Buffer, batchSize),
		oobs:           make([][]byte, batchSize),
		controlBuffers: make([][]byte, batchSize),
		sources:        make([]M.Socksaddr, batchSize),
		names:          make([]unix.RawSockaddrAny, batchSize),
		iovecs:         make([]unix.Iovec, batchSize),
		messages:       make([]mmsghdr, batchSize),
	}, true
}

func (r *oobBatchReader) Read() (buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr, err error) {
	readFunc := func(fd uintptr) bool {
		r.prepare()
		for {
			var errno syscall.Errno
			r.readN, errno = mmsgSyscall(unix.SYS_RECVMMSG, int(fd), r.messages, 0)
			switch errno {
			case 0:
				r.readErr = nil
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				r.releaseBuffers()
				return false
			default:
				if errno == syscall.EWOULDBLOCK {
					r.releaseBuffers()
					return false
				}
				r.readErr = os.NewSyscallError("recvmmsg", errno)
			}
			break
		}
		if r.readN == 0 && r.readErr == nil {
			r.readErr = io.EOF
		}
		for index := 0; index < r.readN; index++ {
			message := &r.messages[index]
			if message.msgHdr.Flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
				r.readErr = errors.New("UDP payload or control message was truncated")
				break
			}
			buffer := r.buffers[index]
			buffer.Truncate(int(message.msgLen))
			oobLength := int(message.msgHdr.Controllen)
			if oobLength > len(r.controlBuffers[index]) {
				oobLength = len(r.controlBuffers[index])
			}
			r.oobs[index] = r.controlBuffers[index][:oobLength]
			r.sources[index] = M.SocksaddrFromRawSockaddrAny(&r.names[index]).Unwrap()
		}
		return true
	}
	if err = r.rawConn.Read(readFunc); err != nil {
		r.releaseBuffers()
		return nil, nil, nil, err
	}
	if r.readErr != nil {
		r.releaseBuffers()
		return nil, nil, nil, r.readErr
	}
	buffers = make([]*buf.Buffer, r.readN)
	copy(buffers, r.buffers[:r.readN])
	clear(r.buffers[:r.readN])
	oobs = r.oobs[:r.readN]
	sources = r.sources[:r.readN]
	r.readN = 0
	return
}

func (r *oobBatchReader) prepare() {
	for index := range r.messages {
		buffer := r.buffers[index]
		if buffer == nil {
			buffer = buf.NewPacket()
			r.buffers[index] = buffer
		} else {
			buffer.Reset()
		}
		controlBuffer := r.controlBuffers[index]
		if cap(controlBuffer) < r.oobSize {
			controlBuffer = make([]byte, r.oobSize)
			r.controlBuffers[index] = controlBuffer
		} else {
			controlBuffer = controlBuffer[:r.oobSize]
			r.controlBuffers[index] = controlBuffer
		}
		r.names[index] = unix.RawSockaddrAny{}
		r.iovecs[index] = buffer.Iovec(buffer.FreeLen())
		r.messages[index] = mmsghdr{}
		r.messages[index].msgHdr.Name = (*byte)(unsafe.Pointer(&r.names[index]))
		r.messages[index].msgHdr.Namelen = unix.SizeofSockaddrAny
		r.messages[index].msgHdr.Iov = &r.iovecs[index]
		r.messages[index].msgHdr.SetIovlen(1)
		r.messages[index].msgHdr.Control = &controlBuffer[0]
		r.messages[index].msgHdr.SetControllen(len(controlBuffer))
	}
}

func (r *oobBatchReader) releaseBuffers() {
	for index, buffer := range r.buffers {
		if buffer != nil {
			buffer.Release()
			r.buffers[index] = nil
		}
	}
	r.readN = 0
}

type oobBatchWriter struct {
	access   sync.Mutex
	rawConn  syscall.RawConn
	ipv6     bool
	names    []unix.RawSockaddrAny
	iovecs   []unix.Iovec
	messages []mmsghdr
}

func newOOBBatchWriter(conn *net.UDPConn) (OOBBatchWriter, bool) {
	if conn == nil {
		return nil, false
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, false
	}
	localAddress := M.SocksaddrFromNet(conn.LocalAddr())
	return &oobBatchWriter{rawConn: rawConn, ipv6: localAddress.Addr.Is6()}, true
}

func (w *oobBatchWriter) Write(buffers []*buf.Buffer, oobs [][]byte, destinations []netip.AddrPort) error {
	if len(buffers) == 0 || len(buffers) != len(oobs) || len(buffers) != len(destinations) {
		return os.ErrInvalid
	}
	w.access.Lock()
	defer w.access.Unlock()
	w.names = grow(w.names, len(buffers))
	w.iovecs = grow(w.iovecs, len(buffers))
	w.messages = grow(w.messages, len(buffers))
	defer func() {
		clear(w.iovecs)
		clear(w.messages)
		w.names = w.names[:0]
		w.iovecs = w.iovecs[:0]
		w.messages = w.messages[:0]
	}()
	for index, buffer := range buffers {
		w.names[index] = unix.RawSockaddrAny{}
		w.iovecs[index] = unix.Iovec{}
		w.messages[index] = mmsghdr{}
		w.messages[index].msgHdr.Name = (*byte)(unsafe.Pointer(&w.names[index]))
		w.messages[index].msgHdr.Namelen = M.AddrPortToRawSockaddrAny(
			&w.names[index],
			destinations[index],
			w.ipv6,
		)
		if !buffer.IsEmpty() {
			w.iovecs[index] = buffer.Iovec(buffer.Len())
			w.messages[index].msgHdr.Iov = &w.iovecs[index]
			w.messages[index].msgHdr.SetIovlen(1)
		}
		if len(oobs[index]) > 0 {
			w.messages[index].msgHdr.Control = &oobs[index][0]
			w.messages[index].msgHdr.SetControllen(len(oobs[index]))
		}
	}
	remaining := w.messages
	var innerErr syscall.Errno
	err := w.rawConn.Write(func(fd uintptr) bool {
		for len(remaining) > 0 {
			written, errno := mmsgSyscall(unix.SYS_SENDMMSG, int(fd), remaining, 0)
			switch errno {
			case 0:
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				return false
			default:
				if errno == syscall.EWOULDBLOCK {
					return false
				}
				innerErr = errno
				return true
			}
			if written == 0 {
				innerErr = syscall.EIO
				return true
			}
			remaining = remaining[written:]
		}
		return true
	})
	runtime.KeepAlive(buffers)
	runtime.KeepAlive(oobs)
	if innerErr != 0 {
		return os.NewSyscallError("sendmmsg", innerErr)
	}
	return err
}

func grow[T any](values []T, size int) []T {
	if cap(values) < size {
		return make([]T, size)
	}
	return values[:size]
}

func mmsgSyscall(trap uintptr, fd int, messages []mmsghdr, flags int) (int, syscall.Errno) {
	if len(messages) == 0 {
		return 0, syscall.EINVAL
	}
	result, _, errno := unix.Syscall6(
		trap,
		uintptr(fd),
		uintptr(unsafe.Pointer(&messages[0])),
		uintptr(len(messages)),
		uintptr(flags),
		0,
		0,
	)
	return int(result), errno
}
