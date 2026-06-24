package session

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

func TestComputeServerFeatureOverlay(t *testing.T) {
	if got := ComputeServerFeatures(false, false); got != 0 {
		t.Fatalf("want 0, got %d", got)
	}
	if got := ComputeServerFeatures(false, true); got != uint32(cartaDefinitions.ServerFeatureFlags_SINGLE_TENANT_BACKEND) {
		t.Fatalf("want SINGLE_TENANT_BACKEND, got %d", got)
	}
	both := ComputeServerFeatures(true, true)
	if both&uint32(cartaDefinitions.ServerFeatureFlags_MULTI_SITE) == 0 {
		t.Fatalf("missing MULTI_SITE in %d", both)
	}
	if both&uint32(cartaDefinitions.ServerFeatureFlags_SINGLE_TENANT_BACKEND) == 0 {
		t.Fatalf("missing SINGLE_TENANT_BACKEND in %d", both)
	}
}

func TestForwardRegisterViewerAck_InjectsFlagsPreservingExisting(t *testing.T) {
	s := &Session{
		clientSendChan: make(chan []byte, 4),
		serverFeatures: ComputeServerFeatures(true, true),
	}
	in, _ := proto.Marshal(&cartaDefinitions.RegisterViewerAck{
		Success:            true,
		ServerFeatureFlags: uint32(cartaDefinitions.ServerFeatureFlags_USER_PREFERENCES),
	})

	s.forwardRegisterViewerAck(11, in)

	raw := <-s.clientSendChan
	prefix, err := cartaHelpers.DecodeMessagePrefix(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if prefix.EventType != cartaDefinitions.EventType_REGISTER_VIEWER_ACK {
		t.Fatalf("unexpected event type %v", prefix.EventType)
	}
	if prefix.RequestId != 11 {
		t.Fatalf("expected requestId 11, got %d", prefix.RequestId)
	}
	var ack cartaDefinitions.RegisterViewerAck
	if err := proto.Unmarshal(raw[8:], &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.ServerFeatureFlags&uint32(cartaDefinitions.ServerFeatureFlags_USER_PREFERENCES) == 0 {
		t.Fatalf("dropped pre-existing USER_PREFERENCES flag")
	}
	if ack.ServerFeatureFlags&uint32(cartaDefinitions.ServerFeatureFlags_MULTI_SITE) == 0 {
		t.Fatalf("missing MULTI_SITE")
	}
	if ack.ServerFeatureFlags&uint32(cartaDefinitions.ServerFeatureFlags_SINGLE_TENANT_BACKEND) == 0 {
		t.Fatalf("missing SINGLE_TENANT_BACKEND")
	}
}
