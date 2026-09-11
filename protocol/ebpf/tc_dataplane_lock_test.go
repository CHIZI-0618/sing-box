//go:build with_ebpf && (linux || android)

package ebpf

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// testTCInterfaceLockIndex keeps the abstract socket names this file uses out of
// the range a running inbound would pick.
const testTCInterfaceLockIndex = 0x7f00

// tcLockHeld reports whether the lock for an interface index is currently taken.
func tcLockHeld(t *testing.T, index int) bool {
	t.Helper()
	lock, err := acquireTCInterfaceLock("probe", index)
	if err != nil {
		return true
	}
	if err = lock.Close(); err != nil {
		t.Fatalf("release the probe lock: %v", err)
	}
	return false
}

// TestTCInterfaceLockIsPerIndex states the property the reconcile ordering has
// to respect: the lock is named after the interface index alone, so two
// attachments that happen to share an index cannot hold it at the same time,
// whatever their names are.
func TestTCInterfaceLockIsPerIndex(t *testing.T) {
	held, err := acquireTCInterfaceLock("old", testTCInterfaceLockIndex)
	if err != nil {
		t.Fatalf("acquire the first lock: %v", err)
	}
	if _, err = acquireTCInterfaceLock("new", testTCInterfaceLockIndex); err == nil {
		t.Fatal("a second interface took the lock for an index that was already held")
	}
	if err = held.Close(); err != nil {
		t.Fatalf("release the first lock: %v", err)
	}
	second, err := acquireTCInterfaceLock("new", testTCInterfaceLockIndex)
	if err != nil {
		t.Fatalf("the lock was not released with the attachment that held it: %v", err)
	}
	if err = second.Close(); err != nil {
		t.Fatalf("release the second lock: %v", err)
	}
}

// newTestTCAttachment builds an attachment that owns a real interface lock and
// nothing else, so closing it exercises the lock release without needing
// netlink.
func newTestTCAttachment(t *testing.T, name string, index int) *tcInterfaceAttachment {
	t.Helper()
	lock, err := acquireTCInterfaceLock(name, index)
	if err != nil {
		t.Fatalf("acquire the lock for %s: %v", name, err)
	}
	return &tcInterfaceAttachment{
		interfaceName:  name,
		interfaceIndex: index,
		lock:           lock,
		lockOwned:      true,
		attachmentType: "clsact",
	}
}

// TestCloseStaleTCAttachmentsFreesReusedIndex covers an interface that was
// removed while another was given the index it had.
//
// The attachment that is no longer wanted has to be released before the one that
// replaced it is attached. Both want the same lock, so releasing afterwards
// makes the new attachment fail to take it and the whole reconciliation roll
// back, leaving the interface uncovered with nothing that would recover it: the
// next round sees the same two and fails the same way.
func TestCloseStaleTCAttachmentsFreesReusedIndex(t *testing.T) {
	removed := newTestTCAttachment(t, "removed0", testTCInterfaceLockIndex+1)
	current := map[string]*tcInterfaceAttachment{"removed0": removed}
	dataPlane := &tcDataPlane{attachments: []*tcInterfaceAttachment{removed}}
	// The replacement carries the index the removed interface used to have.
	desired := map[string]tcAttachmentState{
		"created0": {index: testTCInterfaceLockIndex + 1, framing: commonEBPF.TCLinkFramingEthernet},
	}

	if !tcLockHeld(t, testTCInterfaceLockIndex+1) {
		t.Fatal("the removed interface does not hold its lock")
	}
	if err := dataPlane.closeStaleTCAttachmentsLocked(current, desired); err != nil {
		t.Fatalf("close unwanted attachments: %v", err)
	}
	if tcLockHeld(t, testTCInterfaceLockIndex+1) {
		t.Fatal("the lock is still held, so the interface that reused the index cannot attach")
	}
	if _, present := current["removed0"]; present {
		t.Fatal("the released attachment is still tracked")
	}
}

// TestCloseUnwantedTCAttachmentsKeepsWantedOnes covers the other half: an
// attachment that is still wanted must survive this pass, whether or not its
// index changed, because the attach loop decides what to do with it.
func TestCloseStaleTCAttachmentsKeepsAttachmentsAtTheirOwnIndex(t *testing.T) {
	kept := newTestTCAttachment(t, "kept0", testTCInterfaceLockIndex+2)
	t.Cleanup(func() { _ = kept.Close() })
	current := map[string]*tcInterfaceAttachment{"kept0": kept}
	desired := map[string]tcAttachmentState{"kept0": {index: testTCInterfaceLockIndex + 2}}
	dataPlane := &tcDataPlane{attachments: []*tcInterfaceAttachment{kept}}

	if err := dataPlane.closeStaleTCAttachmentsLocked(current, desired); err != nil {
		t.Fatalf("close stale attachments: %v", err)
	}
	if len(current) != 1 {
		t.Fatalf("current = %v, want the attachment kept", current)
	}
	if len(dataPlane.attachments) != 1 {
		t.Fatalf("attachments = %v, want the attachment kept", dataPlane.attachments)
	}
	if !tcLockHeld(t, testTCInterfaceLockIndex+2) {
		t.Fatal("an attachment still sitting at its own index lost its lock")
	}
}

// TestCloseStaleTCAttachmentsReleasesRenumberedInterface covers the case a name
// check alone gets wrong: the interface is still wanted, but at a different
// index. The attachment holds the lock for the index it was created at, which
// the kernel is now free to give to something else, so it has to go before the
// attach pass rather than being kept because its name is still listed.
func TestCloseStaleTCAttachmentsReleasesRenumberedInterface(t *testing.T) {
	const oldIndex = testTCInterfaceLockIndex + 3
	renumbered := newTestTCAttachment(t, "renumbered0", oldIndex)
	current := map[string]*tcInterfaceAttachment{"renumbered0": renumbered}
	desired := map[string]tcAttachmentState{"renumbered0": {index: oldIndex + 1}}
	dataPlane := &tcDataPlane{attachments: []*tcInterfaceAttachment{renumbered}}

	if err := dataPlane.closeStaleTCAttachmentsLocked(current, desired); err != nil {
		t.Fatalf("close stale attachments: %v", err)
	}
	if tcLockHeld(t, oldIndex) {
		t.Fatal("the renumbered interface still holds the lock for the index it left")
	}
	if len(current) != 0 || len(dataPlane.attachments) != 0 {
		t.Fatalf("current = %v, attachments = %v, want the stale attachment released",
			current, dataPlane.attachments)
	}
}

// testTCLink is the little netlink.Link reconcile actually reads: a name, an
// index, and enough of an encapsulation to be classified as Ethernet.
func testTCLink(name string, index int) netlink.Link {
	attributes := netlink.NewLinkAttrs()
	attributes.Name = name
	attributes.Index = index
	attributes.EncapType = "ether"
	attributes.HardwareAddr = net.HardwareAddr{0, 1, 2, 3, 4, 5}
	return &netlink.Device{LinkAttrs: attributes}
}

func TestReconcileStagesLocalReplacementBeforeClosingPrevious(t *testing.T) {
	const oldIndex = testTCInterfaceLockIndex + 20
	const newIndex = testTCInterfaceLockIndex + 21
	previous := newTestTCAttachment(t, "wlan0", oldIndex)
	previous.role = tcInterfaceRole{local: true}
	var previousWasLiveDuringAttach bool
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{previous},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(name string) (netlink.Link, error) {
				if name == "rmnet_data0" {
					return testTCLink(name, newIndex), nil
				}
				return nil, netlink.LinkNotFoundError{}
			},
			attach: func(
				interfaceName string,
				state tcAttachmentState,
				lock io.Closer,
				lockOwned bool,
			) (*tcInterfaceAttachment, error) {
				previousWasLiveDuringAttach = tcLockHeld(t, oldIndex)
				return &tcInterfaceAttachment{
					interfaceName:  interfaceName,
					interfaceIndex: state.index,
					framing:        state.framing,
					role:           state.role,
					lock:           lock,
					lockOwned:      lockOwned,
					attachmentType: "clsact",
				}, nil
			},
		},
	}
	t.Cleanup(func() { _ = dataPlane.Close() })

	if err := dataPlane.reconcile("rmnet_data0", nil, nil); err != nil {
		t.Fatalf("reconcile local handover: %v", err)
	}
	if !previousWasLiveDuringAttach {
		t.Fatal("the previous local attachment was closed before its replacement was live")
	}
	if !previous.IsClosed() || tcLockHeld(t, oldIndex) {
		t.Fatal("the previous local attachment was not closed after the replacement became live")
	}
	if len(dataPlane.attachments) != 1 || dataPlane.attachments[0].interfaceName != "rmnet_data0" {
		t.Fatalf("attachments = %+v, want only the staged replacement", dataPlane.attachments)
	}
}

func TestReconcileKeepsLocalAttachmentWhenReplacementFails(t *testing.T) {
	const oldIndex = testTCInterfaceLockIndex + 22
	const newIndex = testTCInterfaceLockIndex + 23
	previous := newTestTCAttachment(t, "wlan0", oldIndex)
	previous.role = tcInterfaceRole{local: true}
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{previous},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(name string) (netlink.Link, error) {
				if name == "rmnet_data1" {
					return testTCLink(name, newIndex), nil
				}
				return nil, netlink.LinkNotFoundError{}
			},
			attach: func(
				_ string,
				_ tcAttachmentState,
				lock io.Closer,
				lockOwned bool,
			) (*tcInterfaceAttachment, error) {
				if !tcLockHeld(t, oldIndex) {
					t.Fatal("the previous local attachment was closed before the candidate attach")
				}
				if lockOwned && lock != nil {
					_ = lock.Close()
				}
				return nil, E.New("synthetic replacement failure")
			},
		},
	}
	t.Cleanup(func() { _ = dataPlane.Close() })

	err := dataPlane.reconcile("rmnet_data1", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "synthetic replacement failure") {
		t.Fatalf("reconcile error = %v, want the injected failure", err)
	}
	if previous.IsClosed() || !tcLockHeld(t, oldIndex) {
		t.Fatal("the working local attachment was not retained after the candidate failed")
	}
	if len(dataPlane.attachments) != 1 || dataPlane.attachments[0] != previous {
		t.Fatalf("attachments = %+v, want the previous attachment retained", dataPlane.attachments)
	}
}

// TestReconcileOrderReleasesBeforeLockingAReusedIndex drives the real
// reconciliation order and the real interface locks. The netlink lookup and the
// final attach are substituted, so this is not a test of attaching to a kernel
// interface: what it covers is that the reconciliation releases a stale
// attachment before it takes the lock that attachment was holding.
//
// The situation is one interface disappearing and another being created with the
// index the kernel had just freed. Both want the same lock, so releasing
// afterwards makes the reconciliation fail at the lock and roll back, leaving
// the new interface with no attachment and nothing that would recover it.
func TestReconcileOrderReleasesBeforeLockingAReusedIndex(t *testing.T) {
	const index = testTCInterfaceLockIndex + 4
	removed := newTestTCAttachment(t, "removed1", index)
	attached := make([]string, 0, 1)
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{removed},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(name string) (netlink.Link, error) {
				if name == "created1" {
					return testTCLink("created1", index), nil
				}
				return nil, netlink.LinkNotFoundError{}
			},
			attach: func(
				interfaceName string,
				state tcAttachmentState,
				lock io.Closer,
				lockOwned bool,
			) (*tcInterfaceAttachment, error) {
				attached = append(attached, interfaceName)
				return &tcInterfaceAttachment{
					interfaceName:  interfaceName,
					interfaceIndex: state.index,
					framing:        state.framing,
					role:           state.role,
					lock:           lock,
					lockOwned:      lockOwned,
					attachmentType: "clsact",
				}, nil
			},
		},
	}

	if err := dataPlane.reconcile("created1", nil, nil); err != nil {
		t.Fatalf("reconcile after an index was reused: %v", err)
	}
	if len(attached) != 1 || attached[0] != "created1" {
		t.Fatalf("attached = %v, want the interface that reused the index", attached)
	}
	if len(dataPlane.attachments) != 1 || dataPlane.attachments[0].interfaceName != "created1" {
		t.Fatalf("attachments = %+v, want only the new interface", dataPlane.attachments)
	}
	if dataPlane.attachments[0].interfaceIndex != index {
		t.Fatalf("attached index = %d, want %d", dataPlane.attachments[0].interfaceIndex, index)
	}
	t.Cleanup(func() {
		for _, attachment := range dataPlane.attachments {
			_ = attachment.Close()
		}
	})
}

// TestReconcileOrderReleasesInterfaceThatIsNoLongerWanted covers the plain
// removal through the same substituted lookup: nothing replaces the interface,
// and its attachment and lock still have to go.
func TestReconcileOrderReleasesInterfaceThatIsNoLongerWanted(t *testing.T) {
	const index = testTCInterfaceLockIndex + 5
	removed := newTestTCAttachment(t, "removed2", index)
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{removed},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(string) (netlink.Link, error) {
				return nil, netlink.LinkNotFoundError{}
			},
			attach: func(
				string, tcAttachmentState, io.Closer, bool,
			) (*tcInterfaceAttachment, error) {
				t.Fatal("nothing should be attached when no interface is wanted")
				return nil, nil
			},
		},
	}

	if err := dataPlane.reconcile("", nil, nil); err != nil {
		t.Fatalf("reconcile with nothing wanted: %v", err)
	}
	if len(dataPlane.attachments) != 0 {
		t.Fatalf("attachments = %+v, want none", dataPlane.attachments)
	}
	if tcLockHeld(t, index) {
		t.Fatal("the removed interface still holds its lock")
	}
}

// failingLockCloser stands in for an interface lock whose release reports an
// error.
type failingLockCloser struct{ err error }

func (c failingLockCloser) Close() error { return c.err }

// TestReconcileOrderRenumberedInterfaceFreesItsOldIndex is the case a name check
// alone gets wrong, driven through the reconciliation: wlan0 moves from one
// index to another and a second interface takes the index it left. wlan0 is
// still wanted, so its name is still listed, but the attachment holding the old
// index is stale and has to go before either interface is attached, whichever
// order the two are processed in.
func TestReconcileOrderRenumberedInterfaceFreesItsOldIndex(t *testing.T) {
	const freedIndex = testTCInterfaceLockIndex + 6
	const movedIndex = testTCInterfaceLockIndex + 7
	renumbered := newTestTCAttachment(t, "wlan0", freedIndex)
	attached := make(map[string]int)
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{renumbered},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(name string) (netlink.Link, error) {
				switch name {
				case "wlan0":
					return testTCLink("wlan0", movedIndex), nil
				case "newif":
					return testTCLink("newif", freedIndex), nil
				}
				return nil, netlink.LinkNotFoundError{}
			},
			attach: func(
				interfaceName string,
				state tcAttachmentState,
				lock io.Closer,
				lockOwned bool,
			) (*tcInterfaceAttachment, error) {
				attached[interfaceName] = state.index
				return &tcInterfaceAttachment{
					interfaceName:  interfaceName,
					interfaceIndex: state.index,
					role:           state.role,
					lock:           lock,
					lockOwned:      lockOwned,
					attachmentType: "clsact",
				}, nil
			},
		},
	}
	t.Cleanup(func() {
		for _, attachment := range dataPlane.attachments {
			_ = attachment.Close()
		}
	})

	if err := dataPlane.reconcile("wlan0", []string{"newif"}, nil); err != nil {
		t.Fatalf("reconcile after wlan0 was renumbered: %v", err)
	}
	if attached["wlan0"] != movedIndex {
		t.Fatalf("wlan0 attached at index %d, want %d", attached["wlan0"], movedIndex)
	}
	if attached["newif"] != freedIndex {
		t.Fatalf("newif attached at index %d, want the index wlan0 left (%d)", attached["newif"], freedIndex)
	}
	if len(dataPlane.attachments) != 2 {
		t.Fatalf("attachments = %+v, want both interfaces", dataPlane.attachments)
	}
}

// TestReconcileOrderRecoversAndClosesAfterAttachFailure follows one interface
// through the whole arc: a round whose attach fails after the release
// succeeded, the round after it that succeeds, and the final close.
//
// The released attachment is closed, so the data plane must stop reporting it
// straight away. The round that follows has to start from that state and attach
// the interface that took the index, and the close after that has to leave the
// index free.
func TestReconcileOrderRecoversAndClosesAfterAttachFailure(t *testing.T) {
	const index = testTCInterfaceLockIndex + 8
	removed := newTestTCAttachment(t, "removed3", index)
	attachErr := E.New("synthetic attach failure")
	failAttach := true
	attachCalls := 0
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{removed},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(name string) (netlink.Link, error) {
				if name == "created3" {
					return testTCLink("created3", index), nil
				}
				return nil, netlink.LinkNotFoundError{}
			},
			// attachTCInterfaceWithLock releases a lock it was given ownership of
			// when it fails, so the substitute has to as well or the index would
			// look held for the wrong reason.
			attach: func(
				interfaceName string,
				state tcAttachmentState,
				lock io.Closer,
				lockOwned bool,
			) (*tcInterfaceAttachment, error) {
				attachCalls++
				if failAttach {
					if lockOwned && lock != nil {
						_ = lock.Close()
					}
					return nil, attachErr
				}
				return &tcInterfaceAttachment{
					interfaceName:  interfaceName,
					interfaceIndex: state.index,
					role:           state.role,
					lock:           lock,
					lockOwned:      lockOwned,
					attachmentType: "clsact",
				}, nil
			},
		},
	}

	// First round: the release succeeds and the attach that follows does not.
	err := dataPlane.reconcile("created3", nil, nil)
	if err == nil {
		t.Fatal("a failed attach was reported as success")
	}
	if !strings.Contains(err.Error(), "synthetic attach failure") {
		t.Fatalf("error = %v, want the attach failure", err)
	}
	for _, attachment := range dataPlane.attachments {
		if attachment == removed {
			t.Fatal("a released attachment is still reported as live")
		}
	}
	if tcLockHeld(t, index) {
		t.Fatal("the released attachment still holds its lock after the failure")
	}
	for _, description := range dataPlane.attachmentDescriptions() {
		if strings.Contains(description, "removed3") {
			t.Fatalf("descriptions still mention the released attachment: %v", description)
		}
	}

	// Second round: the same reconciliation now succeeds from that state.
	failAttach = false
	if err = dataPlane.reconcile("created3", nil, nil); err != nil {
		t.Fatalf("the round after the failure did not recover: %v", err)
	}
	if attachCalls != 2 {
		t.Fatalf("attach ran %d times, want one failure and one recovery", attachCalls)
	}
	if len(dataPlane.attachments) != 1 {
		t.Fatalf("attachments = %+v, want only the recovered interface", dataPlane.attachments)
	}
	recovered := dataPlane.attachments[0]
	if recovered.interfaceName != "created3" || recovered.interfaceIndex != index {
		t.Fatalf("recovered attachment = %+v, want created3 at index %d", recovered, index)
	}
	if !tcLockHeld(t, index) {
		t.Fatal("the recovered attachment does not hold the interface lock")
	}

	// Closing the data plane releases what the recovery took.
	if err = dataPlane.Close(); err != nil {
		t.Fatalf("close the data plane: %v", err)
	}
	if len(dataPlane.attachments) != 0 {
		t.Fatalf("attachments = %+v after close, want none", dataPlane.attachments)
	}
	if tcLockHeld(t, index) {
		t.Fatal("the interface lock survived the close")
	}
}

// TestReconcileOrderReportsReleaseFailure covers the exit taken when the early
// release itself fails: the reconciliation stops there and says so, rather than
// going on to take locks while an attachment it could not release may still hold
// one.
func TestReconcileOrderReportsReleaseFailure(t *testing.T) {
	const index = testTCInterfaceLockIndex + 10
	releaseErr := E.New("synthetic lock release failure")
	stuck := &tcInterfaceAttachment{
		interfaceName:  "stuck0",
		interfaceIndex: index,
		lock:           failingLockCloser{err: releaseErr},
		lockOwned:      true,
		attachmentType: "clsact",
	}
	attachCalls := 0
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{stuck},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(name string) (netlink.Link, error) {
				if name == "created4" {
					return testTCLink("created4", index), nil
				}
				return nil, netlink.LinkNotFoundError{}
			},
			attach: func(
				string, tcAttachmentState, io.Closer, bool,
			) (*tcInterfaceAttachment, error) {
				attachCalls++
				return nil, nil
			},
		},
	}

	err := dataPlane.reconcile("created4", nil, nil)
	if err == nil {
		t.Fatal("a release that failed was reported as success")
	}
	if !strings.Contains(err.Error(), "synthetic lock release failure") {
		t.Fatalf("error = %v, want the release failure", err)
	}
	if attachCalls != 0 {
		t.Fatalf("attach ran %d times after the release failed, want 0", attachCalls)
	}
}

// TestReconcileOrderRetainedLocalDoesNotBlockAReusedIndex covers the handoff
// retention meeting a reused index.
//
// While the default interface monitor has no answer, the previous local
// attachment is kept in the desired set at the index it was created with, so a
// brief gap does not tear down interception that still works. If another
// interface has since been given that index, the retained entry is describing an
// interface that is gone, and holding its lock stops the interface that took the
// index from attaching.
func TestReconcileOrderRetainedLocalDoesNotBlockAReusedIndex(t *testing.T) {
	const index = testTCInterfaceLockIndex + 11
	retained := newTestTCAttachment(t, "wlan0", index)
	retained.role = tcInterfaceRole{local: true}
	attached := make(map[string]int)
	dataPlane := &tcDataPlane{
		backend:     &commonEBPF.TCBackend{},
		attachments: []*tcInterfaceAttachment{retained},
		priority:    defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			linkByName: func(name string) (netlink.Link, error) {
				// wlan0 is gone; a shared interface now carries the index it had.
				if name == "shared0" {
					return testTCLink("shared0", index), nil
				}
				return nil, netlink.LinkNotFoundError{}
			},
			attach: func(
				interfaceName string,
				state tcAttachmentState,
				lock io.Closer,
				lockOwned bool,
			) (*tcInterfaceAttachment, error) {
				attached[interfaceName] = state.index
				return &tcInterfaceAttachment{
					interfaceName:  interfaceName,
					interfaceIndex: state.index,
					role:           state.role,
					lock:           lock,
					lockOwned:      lockOwned,
					attachmentType: "clsact",
				}, nil
			},
		},
	}
	t.Cleanup(func() { _ = dataPlane.Close() })

	// An empty local interface is what makes the retention apply.
	if err := dataPlane.reconcile("", []string{"shared0"}, nil); err != nil {
		t.Fatalf("reconcile while the default interface is unavailable: %v", err)
	}
	if attached["shared0"] != index {
		t.Fatalf("shared0 attached at index %d, want the index wlan0 left (%d)", attached["shared0"], index)
	}
	for _, attachment := range dataPlane.attachments {
		if attachment == retained {
			t.Fatal("the retained local attachment outlived the interface that took its index")
		}
	}
}

// TestRetainLocalAttachmentStatesKeepsAnIndexNobodyElseClaims is the case the
// retention exists for: the default interface monitor has no answer, nothing
// else has taken the index, and the attachment is kept so a brief gap does not
// tear down interception that still works.
func TestRetainLocalAttachmentStatesKeepsAnIndexNobodyElseClaims(t *testing.T) {
	attachment := &tcInterfaceAttachment{
		interfaceName:  "wlan0",
		interfaceIndex: 5,
		role:           tcInterfaceRole{local: true},
	}
	desired := map[string]tcAttachmentState{
		"shared0": {index: 6},
	}
	retainLocalAttachmentStates("", desired, []*tcInterfaceAttachment{attachment})

	state, retained := desired["wlan0"]
	if !retained {
		t.Fatalf("desired = %v, want the local attachment retained", desired)
	}
	if state.index != 5 || !state.role.local {
		t.Fatalf("retained state = %+v, want index 5 with the local role", state)
	}
}

// TestRetainLocalAttachmentStatesDropsAnIndexAnotherInterfaceHolds covers the
// same retention when the index is no longer the attachment's to claim: another
// interface reports it, so the attachment describes an interface that is gone
// and keeping it would only hold a lock the other one needs.
func TestRetainLocalAttachmentStatesDropsAnIndexAnotherInterfaceHolds(t *testing.T) {
	attachment := &tcInterfaceAttachment{
		interfaceName:  "wlan0",
		interfaceIndex: 5,
		role:           tcInterfaceRole{local: true},
	}
	desired := map[string]tcAttachmentState{
		"shared0": {index: 5},
	}
	retainLocalAttachmentStates("", desired, []*tcInterfaceAttachment{attachment})

	if _, retained := desired["wlan0"]; retained {
		t.Fatalf("desired = %v, want wlan0 dropped because another interface holds its index", desired)
	}
	if desired["shared0"].index != 5 {
		t.Fatalf("desired = %v, want the interface that reported the index untouched", desired)
	}
}

// TestRetainLocalAttachmentStatesKeepsAResolvedInterface covers an attachment
// whose interface is still resolvable: the retention only adds the local role
// and leaves the index the lookup reported.
func TestRetainLocalAttachmentStatesKeepsAResolvedInterface(t *testing.T) {
	attachment := &tcInterfaceAttachment{
		interfaceName:  "wlan0",
		interfaceIndex: 5,
		role:           tcInterfaceRole{local: true},
	}
	desired := map[string]tcAttachmentState{
		"wlan0": {index: 7, role: tcInterfaceRole{shared: true}},
	}
	retainLocalAttachmentStates("", desired, []*tcInterfaceAttachment{attachment})

	state := desired["wlan0"]
	if state.index != 7 {
		t.Fatalf("retained state = %+v, want the index the lookup reported", state)
	}
	if !state.role.local || !state.role.shared {
		t.Fatalf("retained state = %+v, want both roles", state)
	}
}
