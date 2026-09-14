//go:build with_ebpf && (linux || android)

package runtime

import (
	"errors"
	"testing"

	"github.com/sagernet/netlink"
)

type sharedCountingCloser struct{ attempts int }

func (c *sharedCountingCloser) Close() error {
	c.attempts++
	return nil
}

func TestSharedRewriteAttachmentCloseRetainsFailedResources(t *testing.T) {
	filter := &netlink.BpfFilter{}
	interfaceLock := &sharedCountingCloser{}
	detachAttempts := 0
	attachment := &sharedRewriteAttachment{
		ingressFilter: filter,
		lock:          interfaceLock,
		detachFilter: func(*netlink.BpfFilter) error {
			detachAttempts++
			if detachAttempts == 1 {
				return errors.New("injected shared filter detach failure")
			}
			return nil
		},
	}

	if err := attachment.Close(); err == nil {
		t.Fatal("expected injected shared filter detach failure")
	}
	if attachment.ingressFilter != filter {
		t.Fatal("failed detach lost the filter needed for retry")
	}
	if attachment.lock == nil || interfaceLock.attempts != 0 {
		t.Fatal("interface lock was released while a filter was still owned")
	}
	if attachment.IsClosed() {
		t.Fatal("attachment reports closed while it still owns resources")
	}

	if err := attachment.Close(); err != nil {
		t.Fatalf("retry shared attachment close: %v", err)
	}
	if !attachment.IsClosed() {
		t.Fatal("attachment retained resources after successful retry")
	}
	if interfaceLock.attempts != 1 {
		t.Fatalf("interface lock close attempts = %d, want 1", interfaceLock.attempts)
	}
}

func TestSharedRewriteRuntimeCloseRetainsFailedAttachment(t *testing.T) {
	filter := &netlink.BpfFilter{}
	detachAttempts := 0
	attachment := &sharedRewriteAttachment{
		ingressFilter: filter,
		detachFilter: func(*netlink.BpfFilter) error {
			detachAttempts++
			if detachAttempts == 1 {
				return errors.New("injected runtime detach failure")
			}
			return nil
		},
	}
	runtime := &sharedRewriteDataPlane{
		attachments: map[string]*sharedRewriteAttachment{"wlan0": attachment},
	}

	if err := runtime.Close(); err == nil {
		t.Fatal("expected injected runtime detach failure")
	}
	if runtime.IsClosed() {
		t.Fatal("runtime reports closed after losing an attachment cleanup")
	}
	if runtime.attachments["wlan0"] != attachment {
		t.Fatal("runtime lost the attachment needed for cleanup retry")
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("retry shared runtime close: %v", err)
	}
	if !runtime.IsClosed() {
		t.Fatal("runtime remained open after successful cleanup retry")
	}
}
