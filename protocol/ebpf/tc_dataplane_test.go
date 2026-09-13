//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"golang.org/x/sys/unix"
)

func TestTCXUnsupportedError(t *testing.T) {
	if !tcxUnsupportedError(CiliumEBPF.ErrNotSupported) ||
		!tcxUnsupportedError(errors.Join(errors.New("attach"), unix.EOPNOTSUPP)) ||
		!tcxUnsupportedError(unix.ENOSYS) {
		t.Fatal("expected unsupported TCX errors to be classified")
	}
	if tcxUnsupportedError(unix.EPERM) || tcxUnsupportedError(unix.EINVAL) {
		t.Fatal("permission and interface-specific errors must not disable TCX globally")
	}
}

func TestTCVethNamesFitLinuxLimit(t *testing.T) {
	redirectName, deliveryName, err := nextTCVethNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(redirectName) > 15 || len(deliveryName) > 15 {
		t.Fatalf("delivery link names exceed Linux limit: %q %q", redirectName, deliveryName)
	}
	if redirectName == deliveryName {
		t.Fatal("delivery link names are identical")
	}
}

func TestRetainLocalAttachmentStatesDuringHandoff(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"wlan2": {
			index:   2,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{shared: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("", desired, attachments)

	state, loaded := desired["rmnet_data1"]
	if !loaded {
		t.Fatal("local attachment was not retained while default interface was unavailable")
	}
	if state.index != 19 || state.framing != commonEBPF.TCLinkFramingRawIP || !state.role.local {
		t.Fatalf("unexpected retained local state: %+v", state)
	}
	if _, loaded = desired["wlan2"]; !loaded {
		t.Fatal("shared attachment was dropped while retaining local attachment")
	}
}

func TestRetainLocalAttachmentStatesDoesNotOverrideNewDefault(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"rmnet_data2": {
			index:   20,
			framing: commonEBPF.TCLinkFramingRawIP,
			role:    tcInterfaceRole{local: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("rmnet_data2", desired, attachments)

	if _, loaded := desired["rmnet_data1"]; loaded {
		t.Fatal("stale local attachment was retained after a new default interface appeared")
	}
}

func TestHandoffTCGlobalSysctls(t *testing.T) {
	previous := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "1"}},
	}
	next := &tcDeliveryLink{}
	handoffTCGlobalSysctls(previous, next)
	if len(previous.globalSysctls) != 0 {
		t.Fatal("previous delivery retained global sysctl ownership")
	}
	if len(next.globalSysctls) != 1 || next.globalSysctls[0].path != "all/rp_filter" {
		t.Fatalf("new delivery did not receive global sysctl ownership: %+v", next.globalSysctls)
	}
}

func TestHandoffTCGlobalSysctlsKeepsFreshState(t *testing.T) {
	previous := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "1"}},
	}
	next := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "2"}},
	}
	handoffTCGlobalSysctls(previous, next)
	if len(previous.globalSysctls) != 0 {
		t.Fatal("previous delivery retained global sysctl ownership")
	}
	if len(next.globalSysctls) != 1 || next.globalSysctls[0].original != "2" {
		t.Fatalf("new delivery state was unexpectedly replaced: %+v", next.globalSysctls)
	}
}

func TestRestoreTCSysctlStatesPreservesExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rp_filter")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, changed, err := setTCSysctl(path, "0")
	if err != nil || !changed {
		t.Fatalf("set sysctl: changed=%v err=%v", changed, err)
	}
	if err = restoreTCSysctlStates([]tcSysctlState{state}); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "1" {
		t.Fatalf("sysctl was not restored: value=%q err=%v", value, err)
	}

	state, changed, err = setTCSysctl(path, "0")
	if err != nil || !changed {
		t.Fatalf("set sysctl for external change: changed=%v err=%v", changed, err)
	}
	if err = os.WriteFile(path, []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = restoreTCSysctlStates([]tcSysctlState{state}); err != nil {
		t.Fatal(err)
	}
	value, err = os.ReadFile(path)
	if err != nil || string(value) != "2\n" {
		t.Fatalf("external sysctl change was overwritten: value=%q err=%v", value, err)
	}
}

func TestTransitionTCXInterfaceRoleAttachesBeforeDetach(t *testing.T) {
	var events []string
	err := transitionTCXInterfaceRole(
		tcInterfaceRole{local: true},
		tcInterfaceRole{shared: true},
		true,
		false,
		func(local bool) error {
			if local {
				events = append(events, "attach-local")
			} else {
				events = append(events, "attach-shared")
			}
			return nil
		},
		func(local bool) error {
			if local {
				events = append(events, "detach-local")
			} else {
				events = append(events, "detach-shared")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"attach-shared", "detach-local"}
	if !slices.Equal(events, want) {
		t.Fatalf("unexpected TCX transition order: got %v, want %v", events, want)
	}
}

func TestTransitionTCXInterfaceRoleRollsBackNewLinks(t *testing.T) {
	var events []string
	err := transitionTCXInterfaceRole(
		tcInterfaceRole{},
		tcInterfaceRole{local: true, shared: true},
		false,
		false,
		func(local bool) error {
			if local {
				events = append(events, "attach-local")
				return nil
			}
			events = append(events, "attach-shared")
			return errors.New("shared attach failed")
		},
		func(local bool) error {
			if local {
				events = append(events, "detach-local")
			} else {
				events = append(events, "detach-shared")
			}
			return nil
		},
	)
	if err == nil {
		t.Fatal("expected TCX transition failure")
	}
	want := []string{"attach-local", "attach-shared", "detach-local"}
	if !slices.Equal(events, want) {
		t.Fatalf("unexpected TCX rollback order: got %v, want %v", events, want)
	}
}

func TestDetachFakeIPICMPFilterFailureRetainsOwnership(t *testing.T) {
	filter := &netlink.BpfFilter{}
	attempts := 0
	detach := func(*netlink.BpfFilter) error {
		attempts++
		if attempts == 1 {
			return errors.New("injected ICMP filter detach failure")
		}
		return nil
	}
	if err := detachTCFilterOwnedWith(&filter, detach); err == nil {
		t.Fatal("expected injected ICMP filter detach failure")
	}
	if filter == nil {
		t.Fatal("failed ICMP filter detach lost the retry handle")
	}
	if err := detachTCFilterOwnedWith(&filter, detach); err != nil {
		t.Fatalf("retry ICMP filter detach: %v", err)
	}
	if filter != nil {
		t.Fatal("successful ICMP filter detach retained a stale handle")
	}
}

func TestUpdateTCInterfaceAttachmentRetriesFakeIPICMPDetach(t *testing.T) {
	attributes := netlink.NewLinkAttrs()
	attributes.Name = "test0"
	attributes.Index = 42
	device := &netlink.Dummy{LinkAttrs: attributes}
	normalFilter := &netlink.BpfFilter{}
	icmpFilter := &netlink.BpfFilter{}
	attachment := &tcInterfaceAttachment{
		interfaceName:    attributes.Name,
		interfaceIndex:   attributes.Index,
		role:             tcInterfaceRole{shared: true},
		attachmentType:   "clsact",
		sharedFilter:     normalFilter,
		sharedICMPFilter: icmpFilter,
	}
	icmpAttempts := 0
	ops := tcInterfaceAttachmentOps{
		ensureClsact: func(netlink.Link) error { return nil },
		attachFilter: func(netlink.Link, uint32, int, string, uint16, uint16) (*netlink.BpfFilter, error) {
			t.Fatal("unexpected attach during detach-only update")
			return nil, nil
		},
		detachFilter: func(filter *netlink.BpfFilter) error {
			if filter == icmpFilter {
				icmpAttempts++
				if icmpAttempts == 1 {
					return errors.New("injected update ICMP detach failure")
				}
			}
			return nil
		},
	}
	update := func() error {
		return updateTCInterfaceAttachmentWithOps(
			func(string) (netlink.Link, error) { return device, nil },
			&commonEBPF.TCBackend{},
			attachment,
			tcInterfaceRole{},
			false,
			1,
			ops,
		)
	}
	if err := update(); err == nil {
		t.Fatal("expected injected update ICMP detach failure")
	}
	if attachment.sharedICMPFilter != icmpFilter || attachment.sharedFilter != normalFilter {
		t.Fatal("failed update lost an ICMP or primary filter needed for retry")
	}
	if attachment.role != (tcInterfaceRole{shared: true}) {
		t.Fatalf("failed update changed role to %+v", attachment.role)
	}
	if err := update(); err != nil {
		t.Fatalf("retry update: %v", err)
	}
	if attachment.sharedICMPFilter != nil || attachment.sharedFilter != nil {
		t.Fatal("successful retry retained detached filters")
	}
	if attachment.role != (tcInterfaceRole{}) {
		t.Fatalf("successful retry retained role %+v", attachment.role)
	}
}

type retryCloser struct {
	attempts int
}

func (c *retryCloser) Close() error {
	c.attempts++
	if c.attempts == 1 {
		return errors.New("injected ICMP link close failure")
	}
	return nil
}

// Info satisfies tcxAttachedLink; the close-retention tests using
// retryCloser never call filtersAttached, so its content does not matter.
func (c *retryCloser) Info() (*link.Info, error) {
	return nil, errors.New("retryCloser has no real TCX link info")
}

func TestCloseFakeIPICMPTCXLinkFailureRetainsOwnership(t *testing.T) {
	closer := &retryCloser{}
	attachment := &tcInterfaceAttachment{localICMPLink: closer}
	if err := attachment.closeLinks(); err == nil {
		t.Fatal("expected injected ICMP TCX link close failure")
	}
	if attachment.localICMPLink == nil {
		t.Fatal("failed ICMP TCX close lost the retry link")
	}
	if err := attachment.closeLinks(); err != nil {
		t.Fatalf("retry ICMP TCX close: %v", err)
	}
	if attachment.localICMPLink != nil {
		t.Fatal("successful ICMP TCX close retained a stale link")
	}
}

func TestTransitionTCXInterfaceRoleReportsRollbackDetachFailure(t *testing.T) {
	attachErr := errors.New("injected shared attach failure")
	rollbackErr := errors.New("injected ICMP rollback detach failure")
	err := transitionTCXInterfaceRole(
		tcInterfaceRole{},
		tcInterfaceRole{local: true, shared: true},
		false,
		false,
		func(local bool) error {
			if local {
				return nil
			}
			return attachErr
		},
		func(bool) error { return rollbackErr },
	)
	if !errors.Is(err, attachErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("transition error %v does not preserve attach and rollback failures", err)
	}
}
