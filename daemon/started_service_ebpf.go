package daemon

import (
	"context"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *StartedService) GetEBPFDiagnostics(_ context.Context, _ *emptypb.Empty) (*EBPFDiagnosticsResponse, error) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return nil, os.ErrInvalid
	}
	response := &EBPFDiagnosticsResponse{}
	if s.instance.inboundManager == nil {
		return response, nil
	}
	for _, inbound := range s.instance.inboundManager.Inbounds() {
		provider, loaded := inbound.(adapter.EBPFDiagnosticsProvider)
		if !loaded {
			continue
		}
		response.Inbounds = append(response.Inbounds, marshalEBPFDiagnostics(provider.EBPFDiagnostics()))
		if response.KernelRuntime == nil {
			response.KernelRuntime = marshalEBPFKernelRuntime(provider.EBPFKernelRuntime())
		}
	}
	return response, nil
}

func marshalEBPFKernelRuntime(source adapter.EBPFKernelRuntimeDiagnostics) *EBPFKernelRuntimeDiagnostics {
	destination := &EBPFKernelRuntimeDiagnostics{
		ObservedAt:    source.ObservedAt.UnixMilli(),
		ProgramsError: source.ProgramsError,
		MapOccupancy: &EBPFMapOccupancyDiagnostics{
			Status: source.MapOccupancy.Status,
			Error:  source.MapOccupancy.Error,
		},
	}
	for _, program := range source.Programs {
		destination.Programs = append(destination.Programs, &EBPFProgramDiagnostics{
			Id:       program.ID,
			Name:     program.Name,
			Type:     program.Type,
			MapCount: int32(program.MapCount),
			MapIDs:   program.MapIDs,
		})
	}
	for _, item := range source.MapOccupancy.Maps {
		destination.MapOccupancy.Maps = append(destination.MapOccupancy.Maps, &EBPFMapDiagnostics{
			Id:         item.ID,
			Name:       item.Name,
			Type:       item.Type,
			MaxEntries: item.MaxEntries,
			KeySize:    item.KeySize,
			ValueSize:  item.ValueSize,
			Flags:      item.Flags,
			Entries:    item.Entries,
			Supported:  item.Supported,
			Error:      item.Error,
		})
	}
	return destination
}

func marshalEBPFDiagnostics(source adapter.EBPFRuntimeDiagnostics) *EBPFInboundDiagnostics {
	destination := &EBPFInboundDiagnostics{
		SchemaVersion:                      int32(source.SchemaVersion),
		ObservedAt:                         source.ObservedAt.UnixMilli(),
		Tag:                                source.Tag,
		State:                              source.State,
		LocalEnabled:                       source.LocalEnabled,
		LocalDataPlane:                     source.LocalDataPlane,
		SharedEnabled:                      source.SharedEnabled,
		SharedDataPlane:                    source.SharedDataPlane,
		FakeIPICMPReply:                    source.FakeIPICMPReply,
		LastError:                          source.LastError,
		LastErrorAt:                        optionalUnixMillis(source.LastErrorAt),
		LastRecoveryAt:                     optionalUnixMillis(source.LastRecoveryAt),
		RecoveryPending:                    source.RecoveryPending,
		RecoveryUnrecoverable:              source.RecoveryUnrecoverable,
		NextRetryAt:                        optionalUnixMillis(source.NextRetryAt),
		BypassRuleSetConsistent:            source.BypassRuleSetConsistent,
		BypassRuleSetPending:               source.BypassRuleSetPending,
		BypassRuleSetPolicyVersion:         source.BypassRuleSetPolicyVersion,
		BypassRuleSetExpectedPolicyVersion: source.BypassRuleSetExpectedPolicyVersion,
		BypassRuleSetRetryCount:            source.BypassRuleSetRetryCount,
		BypassRuleSetBackendState:          make(map[string]*EBPFBypassRuleSetBackendState, len(source.BypassRuleSetBackendState)),
		UdpSessionCount:                    int64(source.UDPSessionCount),
		UdpNAT: &EBPFUDPNATDiagnostics{
			ActiveSessions:                 int64(source.UDPNAT.ActiveSessions),
			CreatedSessions:                source.UDPNAT.CreatedSessions,
			CapacityEvictions:              source.UDPNAT.CapacityEvictions,
			QueueDrops:                     source.UDPNAT.QueueDrops,
			SocketReleaseEvents:            source.UDPNAT.SocketReleaseEvents,
			SocketReleaseMatched:           source.UDPNAT.SocketReleaseMatched,
			PendingReleaseCapacityRejected: source.UDPNAT.PendingReleaseCapacityRejected,
			ReleaseNotificationDrops:       source.UDPNAT.ReleaseNotificationDrops,
		},
		UdpReplySockets: &EBPFUDPReplySocketDiagnostics{
			Count:            source.UDPReplySockets.Count,
			Peak:             source.UDPReplySockets.Peak,
			Evicted:          source.UDPReplySockets.Evicted,
			CapacityRejected: source.UDPReplySockets.CapacityRejected,
		},
		Counters: &EBPFCounters{
			AssignmentLookupFailures:      source.Counters.AssignmentLookupFailures,
			TcSocketLookupFailures:        source.Counters.TCSocketLookupFailures,
			TcSKAssignFailures:            source.Counters.TCSKAssignFailures,
			TcAssignmentUpdateFailures:    source.Counters.TCAssignmentUpdateFailures,
			TcLocalFragmentPasses:         source.Counters.TCLocalFragmentPasses,
			TcSharedFragmentPasses:        source.Counters.TCSharedFragmentPasses,
			TokenReservationFailures:      source.Counters.TokenReservationFailures,
			RewriteFailures:               source.Counters.RewriteFailures,
			SharedIngressPasses:           source.Counters.SharedIngressPasses,
			SharedEgressPasses:            source.Counters.SharedEgressPasses,
			SharedIngressFragmentPasses:   source.Counters.SharedIngressFragmentPasses,
			SharedEgressFragmentPasses:    source.Counters.SharedEgressFragmentPasses,
			SharedReconcileFailures:       source.Counters.SharedReconcileFailures,
			RecoveryAttempts:              source.Counters.RecoveryAttempts,
			RecoverySuccesses:             source.Counters.RecoverySuccesses,
			RecoveryFailures:              source.Counters.RecoveryFailures,
			FakeIPICMPReplies:             source.Counters.FakeIPICMPReplies,
			FakeIPICMPPassThrough:         source.Counters.FakeIPICMPPassThrough,
			FakeIPICMPRewriteFailureDrops: source.Counters.FakeIPICMPRewriteFailureDrops,
		},
	}
	for _, attachment := range source.Attachments {
		destination.Attachments = append(destination.Attachments, &EBPFAttachmentDiagnostics{
			InterfaceName:  attachment.InterfaceName,
			InterfaceIndex: int32(attachment.InterfaceIndex),
			Role:           attachment.Role,
			Framing:        attachment.Framing,
			Mechanism:      attachment.Mechanism,
			IcmpEchoReply:  attachment.ICMPEchoReply,
		})
	}
	for name, state := range source.BypassRuleSetBackendState {
		destination.BypassRuleSetBackendState[name] = &EBPFBypassRuleSetBackendState{
			Version: state.Version,
			Known:   state.Known,
		}
	}
	return destination
}

func optionalUnixMillis(value *time.Time) *int64 {
	if value == nil {
		return nil
	}
	milliseconds := value.UnixMilli()
	return &milliseconds
}
