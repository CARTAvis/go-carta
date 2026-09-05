package session

import (
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

// serverFeatureOverlay returns the feature flags the controller adds to those
// reported by the backend.
func (s *Session) serverFeatureOverlay() uint32 {
	var overlay uint32
	if s.multiBackend {
		overlay |= uint32(cartaDefinitions.ServerFeatureFlags_SINGLE_TENANT_BACKEND)
	}
	return overlay
}

// forwardRegisterViewerAck adds the controller's feature flags to a
// REGISTER_VIEWER_ACK before forwarding it to the client.
func (s *Session) forwardRegisterViewerAck(requestId uint32, payload []byte) {
	var ack cartaDefinitions.RegisterViewerAck
	if err := proto.Unmarshal(payload, &ack); err != nil {
		slog.Error("Failed to unmarshal register viewer ack; forwarding unmodified", "error", err)
		s.sendToClient(cartaHelpers.PrepareBinaryMessage(payload, cartaDefinitions.EventType_REGISTER_VIEWER_ACK, requestId))
		return
	}
	ack.ServerFeatureFlags |= s.serverFeatureOverlay()
	out, err := cartaHelpers.PrepareMessagePayload(&ack, cartaDefinitions.EventType_REGISTER_VIEWER_ACK, requestId)
	if err != nil {
		slog.Error("Failed to marshal modified register viewer ack", "error", err)
		return
	}
	s.sendToClient(out)
}
