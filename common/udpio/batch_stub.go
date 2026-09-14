//go:build !linux

package udpio

import "net"

func newOOBBatchReader(*net.UDPConn, int, int) (OOBBatchReader, bool) {
	return nil, false
}

func newOOBBatchWriter(*net.UDPConn) (OOBBatchWriter, bool) {
	return nil, false
}
