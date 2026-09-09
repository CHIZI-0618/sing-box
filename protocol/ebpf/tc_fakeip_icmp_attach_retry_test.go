//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	"github.com/sagernet/netlink"
)

// TestUpdateTCInterfaceAttachmentRepairRetainsAHealthyFilterOnICMPFailure
// covers the exact shape reconcile's health-check repair produces: the
// ordinary local filter is already attached and healthy (as
// filtersAttached — see TestFakeIPICMPHealthCheckDetectsAndRepairsAMissingClsactFilter
// — already confirmed before deciding a repair is even needed), and only
// the fakeip_icmp filter is missing. A transient failure repairing just the
// missing piece must not take down the filter that was never actually
// broken, and a later retry must reach a fully attached, healthy state
// without a duplicate mount of the filter that was never touched.
func TestUpdateTCInterfaceAttachmentRepairRetainsAHealthyFilterOnICMPFailure(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealFakeIPICMPBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	attributes := netlink.NewLinkAttrs()
	attributes.Name = "test0"
	attributes.Index = 42
	device := &netlink.Dummy{LinkAttrs: attributes}
	preExisting := &netlink.BpfFilter{}
	attachment := &tcInterfaceAttachment{
		interfaceName:  attributes.Name,
		interfaceIndex: attributes.Index,
		attachmentType: "clsact",
		localFilter:    preExisting,
	}

	normalAttachAttempts := 0
	icmpAttachAttempts := 0
	ops := tcInterfaceAttachmentOps{
		ensureClsact: func(netlink.Link) error { return nil },
		attachFilter: func(_ netlink.Link, _ uint32, _ int, name string, _ uint16, _ uint16) (*netlink.BpfFilter, error) {
			if name == "sb_tc_local" {
				normalAttachAttempts++
				return &netlink.BpfFilter{}, nil
			}
			icmpAttachAttempts++
			if icmpAttachAttempts == 1 {
				return nil, errors.New("injected fakeip_icmp attach failure")
			}
			return &netlink.BpfFilter{}, nil
		},
		detachFilter: func(*netlink.BpfFilter) error { return nil },
	}
	update := func() error {
		return updateTCInterfaceAttachmentWithOps(
			func(string) (netlink.Link, error) { return device, nil },
			backend,
			attachment,
			tcInterfaceRole{local: true},
			false,
			1,
			ops,
		)
	}

	if err := update(); err == nil {
		t.Fatal("expected the injected fakeip_icmp attach failure")
	}
	if attachment.localFilter != preExisting {
		t.Fatal("the failed repair took down the ordinary local filter, which was never broken")
	}
	if attachment.localICMPFilter != nil {
		t.Fatal("the failed repair reports an ICMP filter that was never actually attached")
	}
	if normalAttachAttempts != 0 {
		t.Fatalf("ordinary local filter attach attempts = %d, want 0 — it was already attached and healthy", normalAttachAttempts)
	}

	if err := update(); err != nil {
		t.Fatalf("retry after the injected failure: %v", err)
	}
	if attachment.localFilter != preExisting {
		t.Fatal("the recovered repair replaced the ordinary local filter instead of leaving it alone")
	}
	if attachment.localICMPFilter == nil {
		t.Fatal("the recovered repair did not attach the fakeip_icmp filter")
	}
	if normalAttachAttempts != 0 {
		t.Fatalf(
			"ordinary local filter attach attempts after retry = %d, want still 0 — "+
				"a repair must never re-mount a filter that was already healthy", normalAttachAttempts,
		)
	}
	if icmpAttachAttempts != 2 {
		t.Fatalf("fakeip_icmp attach attempts = %d, want exactly 2 (one failure, one success)", icmpAttachAttempts)
	}
}
