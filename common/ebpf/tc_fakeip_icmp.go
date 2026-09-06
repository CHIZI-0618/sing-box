//go:build with_ebpf && (linux || android)

package ebpf

import (
	CiliumEBPF "github.com/cilium/ebpf"
)

// This file is TCBackend's thin delegation to FakeIPICMPBackend (see
// fakeip_icmp_backend.go for the object itself and why it is a standalone
// backend rather than fields inline on TCBackend). TCBackend's own public
// API here is unchanged from before that extraction, so protocol/ebpf's
// callers needed no changes: FakeIPICMPEnabled, the program accessors, and
// prepareTC's population of b.fakeIPICMP (in tc.go) are the only places
// that know FakeIPICMPBackend exists underneath.

// FakeIPICMPEnabled reports whether this backend loaded the fakeip_icmp
// object. protocol/ebpf's TC data plane uses this to decide whether to
// attach the extra local/shared reply filters at all.
func (b *TCBackend) FakeIPICMPEnabled() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fakeIPICMP != nil
}

func (b *TCBackend) FakeIPICMPLocalReplyProgramFD(framing TCLinkFraming) int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.LocalReplyProgramFD(framing)
}

func (b *TCBackend) FakeIPICMPLocalReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.LocalReplyProgram(framing)
}

func (b *TCBackend) FakeIPICMPSharedReplyProgramFD(framing TCLinkFraming) int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.SharedReplyProgramFD(framing)
}

func (b *TCBackend) FakeIPICMPSharedReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	backend := b.fakeIPICMP
	b.access.RUnlock()
	return backend.SharedReplyProgram(framing)
}

func (b *TCBackend) fakeIPICMPBackend() *FakeIPICMPBackend {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fakeIPICMP
}

// FakeIPICMPReplyCount, FakeIPICMPPassThroughCount, and
// FakeIPICMPRewriteFailureCount delegate to the underlying FakeIPICMPBackend's
// own counters (see that type's doc comments); each reports errBackendClosed
// if fakeip_icmp was never enabled on this backend.
func (b *TCBackend) FakeIPICMPReplyCount() (uint64, error) {
	return b.fakeIPICMPBackend().ReplyCount()
}

func (b *TCBackend) FakeIPICMPPassThroughCount() (uint64, error) {
	return b.fakeIPICMPBackend().PassThroughCount()
}

func (b *TCBackend) FakeIPICMPRewriteFailureCount() (uint64, error) {
	return b.fakeIPICMPBackend().RewriteFailureCount()
}
