package session

import (
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

// ComputeServerFeatures builds the bitmask the controller injects into
// REGISTER_VIEWER_ACK, based on controller configuration.
func ComputeServerFeatures(multiSite, singleTenantBackend bool) uint32 {
	var overlay uint32
	if multiSite {
		overlay |= uint32(cartaDefinitions.ServerFeatureFlags_MULTI_SITE)
	}
	if singleTenantBackend {
		overlay |= uint32(cartaDefinitions.ServerFeatureFlags_SINGLE_TENANT_BACKEND)
	}
	return overlay
}

// forwardRegisterViewerAck OR-s the controller's feature overlay into a
// REGISTER_VIEWER_ACK and forwards it to the client. On unmarshal failure it
// forwards the original payload unmodified.
func (s *Session) forwardRegisterViewerAck(requestId uint32, payload []byte) {
	var ack cartaDefinitions.RegisterViewerAck
	if err := proto.Unmarshal(payload, &ack); err != nil {
		slog.Error("Failed to unmarshal register viewer ack; forwarding unmodified", "error", err)
		s.sendToClient(cartaHelpers.PrepareBinaryMessage(payload, cartaDefinitions.EventType_REGISTER_VIEWER_ACK, requestId))
		return
	}
	ack.ServerFeatureFlags |= s.serverFeatures
	out, err := cartaHelpers.PrepareMessagePayload(&ack, cartaDefinitions.EventType_REGISTER_VIEWER_ACK, requestId)
	if err != nil {
		slog.Error("Failed to marshal modified register viewer ack", "error", err)
		return
	}
	s.sendToClient(out)
}
