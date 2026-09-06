//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

// TestFakeIPICMPHealthCheckDetectsAndRepairsAMissingClsactFilter drives the
// real detection-and-repair path filtersAttached feeds: attach normally
// (both the ordinary local filter and the fakeip_icmp filter land, and a
// real ping is answered), detach only the fakeip_icmp filter behind the
// attachment's back (as if the kernel or an external actor had removed it),
// confirm filtersAttached now reports the drift and a ping genuinely stops
// being answered, then run the real reconcile() an operator would trigger
// and confirm it repairs the attachment and answers a real ping again.
func TestFakeIPICMPHealthCheckDetectsAndRepairsAMissingClsactFilter(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	const fakeIPTarget = "198.18.0.1"
	self := setupFakeIPICMPPingVeth(t, "sbicmph0", "sbicmph1", fakeIPTarget)

	const priority = 2 // force clsact; see TestAttachTCInterfaceAddsTheFakeIPICMPFilterWhenEnabled.
	lock, err := acquireTCInterfaceLock("sbicmph0", self.Attrs().Index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		"sbicmph0",
		tcAttachmentState{
			index:   self.Attrs().Index,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{local: true},
		},
		false,
		priority,
		lock,
		true,
	)
	if err != nil {
		t.Fatalf("attach the interface: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.localICMPFilter == nil {
		t.Fatal("the fakeip_icmp filter was not attached alongside the ordinary one")
	}

	if err = pingFakeIPICMPTarget(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("ping before breaking anything: %v", err)
	}

	// Simulate the fakeip_icmp filter vanishing on its own — an external
	// actor deleting it, or a kernel event this package never observed —
	// while the ordinary local filter is left completely untouched. The
	// Go-side attachment.localICMPFilter pointer is deliberately left as it
	// is: a real external deletion has no way to reach into this process
	// and clear it, and reconcile()'s own clearStaleAttachments step is
	// exactly what must discover and clear it instead.
	if err = detachTCFilter(attachment.localICMPFilter); err != nil {
		t.Fatalf("detach the fakeip_icmp filter to simulate drift: %v", err)
	}

	attached, err := attachment.filtersAttached(priority, backend)
	if err != nil {
		t.Fatalf("filtersAttached: %v", err)
	}
	if attached {
		t.Fatal("filtersAttached reported this attachment healthy with the fakeip_icmp filter missing")
	}

	if err = pingFakeIPICMPTarget(t, fakeIPTarget, 2*time.Second); err == nil {
		t.Fatal("ping still answered after the fakeip_icmp filter was detached — the drift is not real")
	}

	healthyMainFilter := attachment.localFilter
	dataPlane := &tcDataPlane{backend: backend, attachments: []*tcInterfaceAttachment{attachment}, priority: priority}
	if err = dataPlane.reconcile("sbicmph0", nil, nil); err != nil {
		t.Fatalf("reconcile did not repair the missing fakeip_icmp filter: %v", err)
	}
	if len(dataPlane.attachments) != 1 {
		t.Fatalf("attachments after repair = %d, want 1", len(dataPlane.attachments))
	}
	repaired := dataPlane.attachments[0]
	if repaired.localFilter == nil {
		t.Fatal("repair lost the ordinary local filter")
	}
	if repaired.localFilter != healthyMainFilter {
		t.Fatal("repair replaced the ordinary local filter instead of leaving the still-healthy one alone")
	}
	if repaired.localICMPFilter == nil {
		t.Fatal("repair did not restore the fakeip_icmp filter")
	}
	attached, err = repaired.filtersAttached(priority, backend)
	if err != nil {
		t.Fatalf("filtersAttached after repair: %v", err)
	}
	if !attached {
		t.Fatal("filtersAttached still reports unhealthy immediately after repair")
	}

	if err = pingFakeIPICMPTarget(t, fakeIPTarget, 5*time.Second); err != nil {
		t.Fatalf("ping after repair: %v (the health check repaired the struct but not the real kernel state)", err)
	}

	// Closing must stop reconcile from doing anything further, including a
	// repair that would otherwise still look due.
	if err = dataPlane.Close(); err != nil {
		t.Fatalf("close the data plane: %v", err)
	}
	if err = dataPlane.reconcile("sbicmph0", nil, nil); err == nil {
		t.Fatal("reconcile ran again after Close instead of reporting the data plane closed")
	}
}
