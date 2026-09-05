package session

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

func forwardedAck(t *testing.T, s *Session, requestId uint32, in *cartaDefinitions.RegisterViewerAck) (cartaHelpers.MessagePrefix, *cartaDefinitions.RegisterViewerAck) {
	t.Helper()
	s.forwardRegisterViewerAck(requestId, marshal(t, in))
	raw := (<-s.clientSendChan).data
	prefix, err := cartaHelpers.DecodeMessagePrefix(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var ack cartaDefinitions.RegisterViewerAck
	if err := proto.Unmarshal(raw[8:], &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return prefix, &ack
}

func TestForwardRegisterViewerAck_AddsSingleTenantFlagInMultiBackendMode(t *testing.T) {
	s := newTestSession()
	prefix, ack := forwardedAck(t, s, 11, &cartaDefinitions.RegisterViewerAck{
		Success:            true,
		ServerFeatureFlags: uint32(cartaDefinitions.ServerFeatureFlags_USER_PREFERENCES),
	})

	if prefix.EventType != cartaDefinitions.EventType_REGISTER_VIEWER_ACK || prefix.RequestId != 11 {
		t.Fatalf("unexpected frame %v request %d", prefix.EventType, prefix.RequestId)
	}
	if ack.ServerFeatureFlags&uint32(cartaDefinitions.ServerFeatureFlags_USER_PREFERENCES) == 0 {
		t.Fatal("dropped pre-existing USER_PREFERENCES flag")
	}
	if ack.ServerFeatureFlags&uint32(cartaDefinitions.ServerFeatureFlags_SINGLE_TENANT_BACKEND) == 0 {
		t.Fatal("missing SINGLE_TENANT_BACKEND")
	}
}

func TestForwardRegisterViewerAck_SingleBackendLeavesFlagsAlone(t *testing.T) {
	s := newTestSession()
	s.multiBackend = false
	_, ack := forwardedAck(t, s, 3, &cartaDefinitions.RegisterViewerAck{
		Success:            true,
		ServerFeatureFlags: uint32(cartaDefinitions.ServerFeatureFlags_USER_PREFERENCES),
	})

	if ack.ServerFeatureFlags != uint32(cartaDefinitions.ServerFeatureFlags_USER_PREFERENCES) {
		t.Fatalf("flags changed in single-backend mode: %d", ack.ServerFeatureFlags)
	}
}
