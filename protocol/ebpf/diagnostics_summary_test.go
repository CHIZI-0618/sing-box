//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/netlink"
)

// captureLogger is a minimal log.ContextLogger double that records every
// Info call's rendered message and discards everything else; logStartupSummary
// only ever calls Info.
type captureLogger struct {
	infoMessages []string
}

func (l *captureLogger) Trace(args ...any) {}
func (l *captureLogger) Debug(args ...any) {}
func (l *captureLogger) Info(args ...any) {
	var builder strings.Builder
	for _, arg := range args {
		if text, ok := arg.(string); ok {
			builder.WriteString(text)
		}
	}
	l.infoMessages = append(l.infoMessages, builder.String())
}
func (l *captureLogger) Warn(args ...any)  {}
func (l *captureLogger) Error(args ...any) {}
func (l *captureLogger) Fatal(args ...any) {}
func (l *captureLogger) Panic(args ...any) {}

func (l *captureLogger) TraceContext(context.Context, ...any) {}
func (l *captureLogger) DebugContext(context.Context, ...any) {}
func (l *captureLogger) InfoContext(ctx context.Context, args ...any) {
	l.Info(args...)
}
func (l *captureLogger) WarnContext(context.Context, ...any)  {}
func (l *captureLogger) ErrorContext(context.Context, ...any) {}
func (l *captureLogger) FatalContext(context.Context, ...any) {}
func (l *captureLogger) PanicContext(context.Context, ...any) {}

// TestLogStartupSummaryNamesEachRequiredFact proves item 9's four required
// facts (enabled paths, actual mount, waiting interfaces, fakeip_icmp
// coverage) each appear in the one Info line, for a local TC path that has
// no interface yet and fakeip_icmp enabled but consequently not covering
// anything.
func TestLogStartupSummaryNamesEachRequiredFact(t *testing.T) {
	logger := &captureLogger{}
	inbound := &Inbound{
		localEnabled:    true,
		localDataPlane:  localDataPlaneTC,
		fakeIPICMPReply: true,
		logger:          logger,
	}
	inbound.logStartupSummary()

	if len(logger.infoMessages) != 1 {
		t.Fatalf("Info was called %d times, want exactly 1", len(logger.infoMessages))
	}
	message := logger.infoMessages[0]
	for _, want := range []string{"local=tc", "waiting_for_interface=[local]", "fakeip_icmp=[enabled, not yet covering any attachment]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("summary %q missing %q", message, want)
		}
	}
}

// TestLogStartupSummaryReportsAnActualAttachmentAndItsFakeIPICMPCoverage
// covers the other half: a real attachment gets named by interface and
// mechanism, and when fakeip_icmp actually covers it, that attachment name
// appears rather than the "not yet covering" fallback.
func TestLogStartupSummaryReportsAnActualAttachmentAndItsFakeIPICMPCoverage(t *testing.T) {
	logger := &captureLogger{}
	inbound := &Inbound{
		localEnabled:    true,
		localDataPlane:  localDataPlaneTC,
		fakeIPICMPReply: true,
		logger:          logger,
	}
	inbound.tcDataPlane = &tcDataPlane{
		attachments: []*tcInterfaceAttachment{
			{
				interfaceName:  "eth0",
				role:           tcInterfaceRole{local: true},
				attachmentType: "tcx",
				// A real fakeip_icmp-covered attachment has a non-nil
				// localICMPFilter or localICMPLink; attachmentDiagnostics
				// reads exactly that to decide FakeIPICMP, so a bare
				// non-nil filter here is enough without a real netlink call.
				localICMPFilter: &netlink.BpfFilter{},
			},
		},
	}
	inbound.logStartupSummary()

	if len(logger.infoMessages) != 1 {
		t.Fatalf("Info was called %d times, want exactly 1", len(logger.infoMessages))
	}
	message := logger.infoMessages[0]
	for _, want := range []string{"mounts=[eth0(local,tcx)]", "waiting_for_interface=[none]", "fakeip_icmp=[eth0(local)]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("summary %q missing %q", message, want)
		}
	}
}
