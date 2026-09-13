//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
)

// newTestAssignmentBackend builds a backend whose only runtime is a real
// assignment map, which is what the lookup path reads and writes.
func newTestAssignmentBackend(t *testing.T) *TCBackend {
	t.Helper()
	assignmentMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(tcAssignKey{})),
		ValueSize:  uint32(unsafe.Sizeof(TCAssignment{})),
		MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("cannot create an assignment map: %v", err)
	}
	t.Cleanup(func() { _ = assignmentMap.Close() })
	backend := &TCBackend{}
	backend.runtime = &tcRuntime{maps: map[string]*CiliumEBPF.Map{"tc_assignment": assignmentMap}}
	backend.assignmentMapFD = assignmentMap.FD()
	return backend
}

// writeTestAssignment writes through the same raw map helper the programs and
// the lookup path use, so the value is laid out the way the map expects rather
// than the way a marshaller would pack it.
func writeTestAssignment(
	t *testing.T,
	backend *TCBackend,
	protocol uint8,
	source, destination netip.AddrPort,
	interfaceIndex uint32,
	value TCAssignment,
) {
	t.Helper()
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		t.Fatalf("build the assignment key: %v", err)
	}
	if err = updateMap(backend.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatalf("write the assignment: %v", err)
	}
}

// TestLookupAssignmentKeyIncludesInterfaceIndex covers what the interface index
// does in the lookup key: an entry is found under the index it was written for,
// and not under a different one.
//
// It says nothing about how long an entry lives or about what happens to entries
// when an interface goes away.
func TestLookupAssignmentKeyIncludesInterfaceIndex(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41000")
	destination := netip.MustParseAddrPort("10.0.0.1:53")
	const reusedIndex = 5

	// An entry written for one interface index.
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, reusedIndex, TCAssignment{
		SocketCookie:   0x1111,
		InterfaceIndex: reusedIndex,
		SourceMAC:      MACAddress{0xaa, 0, 0, 0, 0, 1},
		Path:           TCPathShared,
		SourceMACValid: 1,
	})

	// The same flow and the same index read the same key.
	assignment, err := backend.LookupAssignment(ProtocolUDP, source, destination, reusedIndex, false)
	if err != nil {
		t.Fatalf("lookup the assignment: %v", err)
	}
	if assignment.SocketCookie != 0x1111 {
		t.Fatalf("assignment = %+v, want the entry that was written", assignment)
	}

	// A different index is a different key.
	if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, reusedIndex+1, false); err == nil {
		t.Fatal("an assignment was found under an index it was not written for")
	}
}

// TestLookupAssignmentRemovesEntryOnRequest covers the removing form of the
// lookup, which is the one the TCP path uses: a successful read with remove set
// takes the entry with it, and a second read of the same key finds nothing.
//
// It covers that one call. It does not say what else may write the same key
// before or after.
func TestLookupAssignmentRemovesEntryOnRequest(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41001")
	destination := netip.MustParseAddrPort("10.0.0.1:443")

	writeTestAssignment(t, backend, ProtocolTCP, source, destination, 0, TCAssignment{
		SocketCookie: 0x2222,
		Path:         TCPathDelivery,
	})

	assignment, err := backend.LookupAssignment(ProtocolTCP, source, destination, 0, true)
	if err != nil {
		t.Fatalf("lookup the assignment: %v", err)
	}
	if assignment.SocketCookie != 0x2222 {
		t.Fatalf("assignment = %+v, want the entry that was written", assignment)
	}
	if _, err = backend.LookupAssignment(ProtocolTCP, source, destination, 0, false); err == nil {
		t.Fatal("the entry survived a lookup that was asked to remove it")
	}
}

// TestLookupAssignmentKeepsEntryWhenNotAsked covers the other form, which is the
// one the UDP path uses: reading without remove leaves the entry in place, so
// the same key can be read again.
//
// It covers the lookup only. Nothing here is a statement about when entries are
// otherwise removed.
func TestLookupAssignmentKeepsEntryWhenNotAsked(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41002")
	destination := netip.MustParseAddrPort("10.0.0.1:53")

	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 7, TCAssignment{
		SocketCookie: 0x3333,
		Path:         TCPathShared,
	})

	for range 3 {
		assignment, err := backend.LookupAssignment(ProtocolUDP, source, destination, 7, false)
		if err != nil {
			t.Fatalf("lookup the assignment: %v", err)
		}
		if assignment.SocketCookie != 0x3333 {
			t.Fatalf("assignment = %+v, want the entry that was written", assignment)
		}
	}
}
