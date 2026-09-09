//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	"fmt"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func countMapEntries(fd int, keySize uintptr, maxEntries uint32) (uint32, error) {
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return 0, err
	}
	mapInstance, err := CiliumEBPF.NewMapFromFD(dupFD)
	if err != nil {
		return 0, err
	}
	defer mapInstance.Close()
	if keySize == 0 || keySize > uintptr(^uint(0)>>1) {
		return 0, errors.New("invalid BPF map key size")
	}
	var key []byte
	var count uint32
	for {
		// NextKeyBytes treats "start of iteration" as a literal nil `any`
		// interface value. A nil []byte boxed into that parameter is not
		// the same thing -- a typed nil is a non-nil interface in Go -- so
		// passing `key` directly on the first call (where it is a nil
		// []byte, not an untyped nil) makes the library try to marshal an
		// empty key instead of starting the iteration, failing with
		// "doesn't marshal to N bytes" before a single key is read. Passing
		// a literal nil on that first call avoids boxing it at all.
		var next []byte
		var nextErr error
		if key == nil {
			next, nextErr = mapInstance.NextKeyBytes(nil)
		} else {
			next, nextErr = mapInstance.NextKeyBytes(key)
		}
		if errors.Is(nextErr, unix.ENOENT) {
			return count, nil
		}
		if nextErr != nil {
			return 0, nextErr
		}
		// Map.NextKeyBytes (this pinned cilium/ebpf version's map.go) does
		// not surface end-of-iteration as an error at this level at all: it
		// translates the lower-level ErrKeyNotExist into a plain (nil, nil)
		// return instead. The ENOENT check above is kept for defensiveness
		// (some other error path could still surface it that way), but a
		// nil key with no error is the return value end-of-iteration
		// actually produces here, and has to be checked for explicitly.
		if next == nil {
			return count, nil
		}
		if uintptr(len(next)) != keySize {
			return 0, fmt.Errorf("BPF map returned an unexpected key size: got %d bytes, want %d", len(next), keySize)
		}
		count++
		if count > maxEntries {
			return count, nil
		}
		key = next
	}
}
