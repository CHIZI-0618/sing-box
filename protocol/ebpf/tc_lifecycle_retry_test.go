//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	udpnat "github.com/sagernet/sing/common/udpnat2"
)

type tcRetryResource struct {
	fail   bool
	calls  int
	closer io.Closer
}

func (r *tcRetryResource) Close() error {
	r.calls++
	if r.fail {
		return errors.New("injected cleanup failure")
	}
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// Info satisfies tcxAttachedLink; none of the tests using tcRetryResource as
// an ICMP link call filtersAttached, so its content does not matter.
func (r *tcRetryResource) Info() (*link.Info, error) {
	return nil, errors.New("tcRetryResource has no real TCX link info")
}

func TestTCAttachmentCloseRetainsLockUntilDetachSucceeds(t *testing.T) {
	for n, kind := range []string{"filter", "link"} {
		t.Run(kind, func(t *testing.T) {
			index := testStartupLockIndex + 0x100 + n
			a := newTestTCAttachment(t, "retry", index)
			t.Cleanup(func() { _ = a.Close() })
			failed := &tcRetryResource{fail: true}
			released := &tcRetryResource{}
			a.sharedICMPLink = released
			if kind == "filter" {
				a.localICMPFilter = &netlink.BpfFilter{}
				a.detachFilter = func(*netlink.BpfFilter) error { return failed.Close() }
			} else {
				a.localICMPLink = failed
			}
			if err := a.Close(); err == nil {
				t.Fatal("expected detach failure")
			}
			if a.IsClosed() || !a.HasOwnedResources() || !a.lockOwned || a.lock == nil || !tcLockHeld(t, index) {
				t.Fatal("detach failure lost owner or released interface lock")
			}
			failed.fail = false
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if !a.IsClosed() || tcLockHeld(t, index) {
				t.Fatal("retry did not release attachment and lock")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if released.calls != 1 || failed.calls != 2 {
				t.Fatalf("repeated successful release: %d/%d", released.calls, failed.calls)
			}
		})
	}
}

func TestTCAttachmentRetriesLockClose(t *testing.T) {
	a := newTestTCAttachment(t, "retry-lock", testStartupLockIndex+0x102)
	lock := &tcRetryResource{fail: true, closer: a.lock}
	a.lock = lock
	released := &tcRetryResource{}
	a.localICMPLink = released
	if err := a.Close(); err == nil {
		t.Fatal("expected lock failure")
	}
	if a.lock != lock || !a.lockOwned || a.IsClosed() || !tcLockHeld(t, a.interfaceIndex) {
		t.Fatal("failed lock owner was lost")
	}
	lock.fail = false
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if !a.IsClosed() || released.calls != 1 || lock.calls != 2 {
		t.Fatal("lock retry repeated released link or retained owner")
	}
}

func TestTCStaleReconciliationRetainsFailedOwner(t *testing.T) {
	a := newTestTCAttachment(t, "stale", testStartupLockIndex+0x103)
	failed := &tcRetryResource{fail: true}
	a.localICMPLink = failed
	d := &tcDataPlane{attachments: []*tcInterfaceAttachment{a}}
	current := map[string]*tcInterfaceAttachment{"stale": a}
	if err := d.closeStaleTCAttachmentsLocked(current, nil); err == nil {
		t.Fatal("expected stale close failure")
	}
	if len(d.attachments) != 1 || d.attachments[0] != a || current["stale"] != a || !tcLockHeld(t, a.interfaceIndex) {
		t.Fatal("stale owner lost")
	}
	failed.fail = false
	if err := d.closeStaleTCAttachmentsLocked(current, nil); err != nil {
		t.Fatal(err)
	}
	if len(d.attachments) != 0 || len(current) != 0 || !a.IsClosed() {
		t.Fatal("stale retry did not complete")
	}
}

func TestInboundTCCloseRetriesOwnedResources(t *testing.T) {
	for n, startup := range []bool{false, true} {
		name := "shutdown"
		if startup {
			name = "startup-cleanup"
		}
		t.Run(name, func(t *testing.T) {
			failed := &tcRetryResource{fail: true}
			a := newTestTCAttachment(t, "inbound", testStartupLockIndex+0x104+n)
			a.localICMPLink = failed
			released := &tcRetryResource{}
			routingLock := &tcRetryResource{}
			d := &tcDataPlane{
				backend:     &commonEBPF.TCBackend{},
				attachments: []*tcInterfaceAttachment{a, {localICMPLink: released}},
				routing:     &tcPolicyRouting{lock: routingLock}, delivery: &tcDeliveryLink{},
			}
			i := &Inbound{}
			i.udpNat = udpnat.New(i, i.preparePacketConnection, time.Minute, false)
			i.setTCDataPlane(d)
			closeFirst := i.Close
			if startup {
				closeFirst = i.cleanupStartFailure
			}
			if err := closeFirst(); err == nil {
				t.Fatal("expected attachment failure")
			}
			if i.tcDataPlane != d || d.IsClosed() || d.backend == nil || d.routing == nil || d.delivery == nil || len(d.attachments) != 1 || d.attachments[0] != a || routingLock.calls != 0 {
				t.Fatal("inbound lost failed owner or its dependencies")
			}
			failed.fail = false
			if err := i.Close(); err != nil {
				t.Fatal(err)
			}
			if i.tcDataPlane != nil || !d.IsClosed() || tcLockHeld(t, a.interfaceIndex) {
				t.Fatal("second inbound Close did not finish")
			}
			if err := i.Close(); err != nil {
				t.Fatal(err)
			}
			if released.calls != 1 || failed.calls != 2 || routingLock.calls != 1 {
				t.Fatal("successful resources closed again")
			}
		})
	}
}

func TestTCStartupAttachFailureReturnsRetryOwner(t *testing.T) {
	failed := &tcRetryResource{fail: true}
	var retained *tcInterfaceAttachment
	d := newStartupTestDataPlane(t, func(name string) (netlink.Link, error) {
		return testTCLink(name, testStartupLockIndex+0x106), nil
	}, func(name string, state tcAttachmentState, lock io.Closer, owned bool) (*tcInterfaceAttachment, error) {
		retained = &tcInterfaceAttachment{interfaceName: name, interfaceIndex: state.index, lock: lock, lockOwned: owned, localICMPLink: failed}
		return retained, errors.New("injected attach failure")
	})
	owners, err := d.attachTCInterfaces("startup", nil)
	if err == nil || len(owners) != 1 || owners[0] != retained || !tcLockHeld(t, retained.interfaceIndex) {
		t.Fatal("startup dropped unfinished attachment")
	}
	d.attachments = owners
	i := &Inbound{}
	i.setTCDataPlane(d)
	if err := i.closeTCDataPlane(); err == nil || i.tcDataPlane != d {
		t.Fatal("startup cleanup dropped dataplane")
	}
	failed.fail = false
	if err := i.closeTCDataPlane(); err != nil {
		t.Fatal(err)
	}
	if i.tcDataPlane != nil || !d.IsClosed() {
		t.Fatal("startup owner could not be reclaimed")
	}
}

func TestTCStartupLookupFailureReturnsFailedLock(t *testing.T) {
	lock := &tcRetryResource{fail: true}
	a, err := attachTCInterfaceWithLock(func(string) (netlink.Link, error) { return nil, errors.New("lookup failed") }, nil, "missing", tcAttachmentState{}, false, 1, lock, true)
	if err == nil || a == nil || a.lock != lock || !a.lockOwned {
		t.Fatal("early startup failure dropped lock")
	}
	lock.fail = false
	if err := a.Close(); err != nil || !a.IsClosed() {
		t.Fatalf("retry lock: %v", err)
	}
}

func TestTCDataPlaneRetainsFailedInfrastructure(t *testing.T) {
	routingLock := &tcRetryResource{fail: true}
	dir := t.TempDir()
	path := filepath.Join(dir, "rp_filter")
	// Reading a directory fails regardless of whether tests run as root.
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	d := &tcDataPlane{backend: &commonEBPF.TCBackend{}, routing: &tcPolicyRouting{lock: routingLock}, delivery: &tcDeliveryLink{globalSysctls: []tcSysctlState{{path: path, original: "1", applied: "0"}}}}
	if err := d.Close(); err == nil {
		t.Fatal("expected infrastructure failure")
	}
	if d.IsClosed() || d.backend == nil || d.routing == nil || d.delivery == nil {
		t.Fatal("lost infrastructure owner/backend")
	}
	routingLock.fail = false
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "1" || !d.IsClosed() {
		t.Fatal("infrastructure retry did not restore state")
	}
}

func TestTCReconcileRollbackRetainsCreatedOwner(t *testing.T) {
	failed := &tcRetryResource{fail: true}
	var created *tcInterfaceAttachment
	const index = testStartupLockIndex + 0x107
	d := newStartupTestDataPlane(t, func(name string) (netlink.Link, error) {
		offset := 0
		if name == "zzz" {
			offset = 1
		}
		return testTCLink(name, index+offset), nil
	}, func(name string, state tcAttachmentState, lock io.Closer, owned bool) (*tcInterfaceAttachment, error) {
		a := &tcInterfaceAttachment{interfaceName: name, interfaceIndex: state.index, framing: state.framing, role: state.role, lock: lock, lockOwned: owned}
		if name == "zzz" {
			return nil, errors.Join(errors.New("injected attach failure"), a.Close())
		}
		a.localICMPLink = failed
		created = a
		return a, nil
	})
	if err := d.reconcile("aaa", []string{"zzz"}, nil); err == nil {
		t.Fatal("expected attach and rollback failure")
	}
	if len(d.retiredAttachments) != 1 || d.retiredAttachments[0] != created || !tcLockHeld(t, index) {
		t.Fatal("rollback dropped new owner")
	}
	if err := d.reconcile("aaa", nil, nil); err == nil || failed.calls != 2 {
		t.Fatal("next reconcile did not retry pending cleanup first")
	}
	failed.fail = false
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if !d.IsClosed() || tcLockHeld(t, index) {
		t.Fatal("retired owner survived shutdown")
	}
}

func TestTCStaleRetryFinishesBeforeReusingAttachment(t *testing.T) {
	a := newTestTCAttachment(t, "returning", testStartupLockIndex+0x109)
	failed := &tcRetryResource{fail: true}
	a.localICMPLink = failed
	d := &tcDataPlane{attachments: []*tcInterfaceAttachment{a}}
	current := map[string]*tcInterfaceAttachment{a.interfaceName: a}
	if err := d.closeStaleTCAttachmentsLocked(current, nil); err == nil {
		t.Fatal("expected close failure")
	}
	// The interface reappeared, but its partially closed owner cannot be reused.
	desired := map[string]tcAttachmentState{a.interfaceName: {index: a.interfaceIndex, framing: a.framing, role: a.role}}
	failed.fail = false
	if err := d.closeStaleTCAttachmentsLocked(current, desired); err != nil {
		t.Fatal(err)
	}
	if len(d.attachments) != 0 || len(current) != 0 || !a.IsClosed() {
		t.Fatal("partially closed owner was reused")
	}
}
