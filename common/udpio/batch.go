package udpio

import (
	"net"
	"net/netip"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// OOBBatchReader transfers ownership of returned buffers to the caller. OOB
// slices remain valid until the next Read call and must be consumed
// synchronously.
type OOBBatchReader interface {
	Read() (buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr, err error)
}

// OOBBatchWriter does not take ownership of buffers or OOB slices.
type OOBBatchWriter interface {
	Write(buffers []*buf.Buffer, oobs [][]byte, destinations []netip.AddrPort) error
}

func NewOOBBatchReader(conn *net.UDPConn, batchSize int, oobSize int) (OOBBatchReader, bool) {
	return newOOBBatchReader(conn, batchSize, oobSize)
}

func NewOOBBatchWriter(conn *net.UDPConn) (OOBBatchWriter, bool) {
	return newOOBBatchWriter(conn)
}
