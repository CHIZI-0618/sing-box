//go:build with_ebpf && (linux || android)

package ebpf

import (
	"io"
	"strings"
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// testStartupLockIndex keeps the abstract socket names this file uses clear of
// the ones tc_dataplane_lock_test.go takes.
const testStartupLockIndex = testTCInterfaceLockIndex + 0x40

// newStartupTestDataPlane builds a data plane whose lookup and attach are
// substituted, so the startup pass can be driven without a kernel interface.
//
// The default attach substitute keeps the lock it is given, exactly as
// attachTCInterfaceWithLock does on success, so the attachment it returns is the
// only thing that can release it.
func newStartupTestDataPlane(
	t *testing.T,
	linkByName func(string) (netlink.Link, error),
	attach func(string, tcAttachmentState, io.Closer, bool) (*tcInterfaceAttachment, error),
) *tcDataPlane {
	t.Helper()
	if attach == nil {
		attach = func(
			interfaceName string,
			state tcAttachmentState,
			lock io.Closer,
			lockOwned bool,
		) (*tcInterfaceAttachment, error) {
			return &tcInterfaceAttachment{
				interfaceName:  interfaceName,
				interfaceIndex: state.index,
				framing:        state.framing,
				role:           state.role,
				lock:           lock,
				lockOwned:      lockOwned,
				attachmentType: "clsact",
			}, nil
		}
	}
	return &tcDataPlane{
		backend:  &commonEBPF.TCBackend{},
		priority: defaultTCPriority,
		hooks:    &tcDataPlaneHooks{linkByName: linkByName, attach: attach},
	}
}

// TestAttachTCInterfacesReleasesEarlierInterfacesWhenALookupFails covers the
// startup pass giving up because an interface it still has to attach cannot be
// looked up, after an earlier one was already attached.
//
// The list is never returned in that case, so nothing else learns about the
// attachments that were made: startTCDataPlane closes a data plane whose
// attachments field was never set. What was attached has to be released here, or
// its filters stay on the interface with no listener behind them and the
// interface lock it holds makes the next attempt report the interface as managed
// by another inbound.
func TestAttachTCInterfacesReleasesEarlierInterfacesWhenALookupFails(t *testing.T) {
	const attachedIndex = testStartupLockIndex
	attached := make([]string, 0, 1)
	dataPlane := newStartupTestDataPlane(t, func(name string) (netlink.Link, error) {
		if name == "sbaaa0" {
			return testTCLink("sbaaa0", attachedIndex), nil
		}
		// Not a "not found" error, so it is not the case the startup pass skips.
		return nil, unix.ENOBUFS
	}, nil)
	dataPlane.hooks.attach = func(
		interfaceName string,
		state tcAttachmentState,
		lock io.Closer,
		lockOwned bool,
	) (*tcInterfaceAttachment, error) {
		attached = append(attached, interfaceName)
		return &tcInterfaceAttachment{
			interfaceName:  interfaceName,
			interfaceIndex: state.index,
			role:           state.role,
			lock:           lock,
			lockOwned:      lockOwned,
			attachmentType: "clsact",
		}, nil
	}

	// Sorted order puts the interface that resolves first, so the failure lands
	// after something has been attached.
	attachments, err := dataPlane.attachTCInterfaces("sbzzz0", []string{"sbaaa0"})
	if err == nil {
		t.Fatal("a failed interface lookup was reported as success")
	}
	if attachments != nil {
		t.Fatalf("attachments = %+v, want none handed back", attachments)
	}
	if len(attached) != 1 || attached[0] != "sbaaa0" {
		t.Fatalf("attached = %v, want the interface that resolved", attached)
	}
	if tcLockHeld(t, attachedIndex) {
		t.Fatal("the interface attached before the lookup failed still holds its lock")
	}
}

// TestAttachTCInterfacesReleasesEarlierInterfacesWhenAnAttachFails is the same
// arc with the failure one step later: the second interface resolves and its
// attach is what fails.
func TestAttachTCInterfacesReleasesEarlierInterfacesWhenAnAttachFails(t *testing.T) {
	const firstIndex = testStartupLockIndex + 1
	const secondIndex = testStartupLockIndex + 2
	attachErr := E.New("synthetic attach failure")
	dataPlane := newStartupTestDataPlane(t, func(name string) (netlink.Link, error) {
		switch name {
		case "sbaaa1":
			return testTCLink("sbaaa1", firstIndex), nil
		case "sbzzz1":
			return testTCLink("sbzzz1", secondIndex), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}, nil)
	dataPlane.hooks.attach = func(
		interfaceName string,
		state tcAttachmentState,
		lock io.Closer,
		lockOwned bool,
	) (*tcInterfaceAttachment, error) {
		if interfaceName == "sbzzz1" {
			// attachTCInterfaceWithLock releases a lock it was given ownership of
			// when it fails, so the substitute has to as well.
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
	}

	attachments, err := dataPlane.attachTCInterfaces("sbzzz1", []string{"sbaaa1"})
	if err == nil {
		t.Fatal("a failed attach was reported as success")
	}
	if !strings.Contains(err.Error(), "synthetic attach failure") {
		t.Fatalf("error = %v, want the attach failure", err)
	}
	if attachments != nil {
		t.Fatalf("attachments = %+v, want none handed back", attachments)
	}
	if tcLockHeld(t, firstIndex) {
		t.Fatal("the interface attached before the failure still holds its lock")
	}
	if tcLockHeld(t, secondIndex) {
		t.Fatal("the lock taken for the interface whose attach failed is still held")
	}
}

// TestAttachTCInterfacesReportsCleanupFailures covers the other half of owning
// these attachments: a release that fails has to reach the caller alongside the
// failure that triggered it, rather than being dropped.
func TestAttachTCInterfacesReportsCleanupFailures(t *testing.T) {
	const attachedIndex = testStartupLockIndex + 3
	closeErr := E.New("synthetic release failure")
	dataPlane := newStartupTestDataPlane(t, func(name string) (netlink.Link, error) {
		if name == "sbaaa2" {
			return testTCLink("sbaaa2", attachedIndex), nil
		}
		return nil, unix.ENOBUFS
	}, nil)
	dataPlane.hooks.attach = func(
		interfaceName string,
		state tcAttachmentState,
		lock io.Closer,
		lockOwned bool,
	) (*tcInterfaceAttachment, error) {
		// The real lock is released here so the test leaves nothing behind. What
		// the attachment carries instead is a release that reports an error.
		if lockOwned && lock != nil {
			_ = lock.Close()
		}
		return &tcInterfaceAttachment{
			interfaceName:  interfaceName,
			interfaceIndex: state.index,
			role:           state.role,
			lock:           failingLockCloser{err: closeErr},
			lockOwned:      true,
			attachmentType: "clsact",
		}, nil
	}

	_, err := dataPlane.attachTCInterfaces("sbzzz2", []string{"sbaaa2"})
	if err == nil {
		t.Fatal("a failed interface lookup was reported as success")
	}
	if !strings.Contains(err.Error(), "synthetic release failure") {
		t.Fatalf("error = %v, want it to carry the failed release", err)
	}
	if !strings.Contains(err.Error(), "sbzzz2") {
		t.Fatalf("error = %v, want it to carry the lookup that failed", err)
	}
}

// TestAttachTCInterfacesSkipsMissingSharedInterfaces states the behaviour the
// cleanup must not change: a shared-only interface that is simply not present is
// skipped, and the interfaces around it are still attached.
func TestAttachTCInterfacesSkipsMissingSharedInterfaces(t *testing.T) {
	const attachedIndex = testStartupLockIndex + 4
	dataPlane := newStartupTestDataPlane(t, func(name string) (netlink.Link, error) {
		if name == "sbaaa3" {
			return testTCLink("sbaaa3", attachedIndex), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}, nil)

	attachments, err := dataPlane.attachTCInterfaces("", []string{"sbaaa3", "sbzzz3"})
	if err != nil {
		t.Fatalf("attach with one shared interface missing: %v", err)
	}
	t.Cleanup(func() { _ = closeTCInterfaceAttachments(attachments) })
	if len(attachments) != 1 || attachments[0].interfaceName != "sbaaa3" {
		t.Fatalf("attachments = %+v, want only the interface that exists", attachments)
	}
}
