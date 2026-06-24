package session

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

func TestHandleBulkSetRegion_FansOutAndGathers(t *testing.T) {
	s := &Session{
		Context:        context.Background(),
		clientSendChan: make(chan []byte, 4),
		sharedWorker:   &SessionWorker{}, // non-nil so checkAndParse passes
		fileMap:        map[int32]*SessionWorker{},
	}
	w0 := &SessionWorker{sendChan: make(chan []byte, 4)}
	w1 := &SessionWorker{sendChan: make(chan []byte, 4)}
	s.fileMap[0] = w0
	s.fileMap[1] = w1

	bulk := &cartaDefinitions.BulkSetRegion{SetRegions: []*cartaDefinitions.SetRegion{
		{FileId: 0, RegionId: 5},
		{FileId: 1, RegionId: 5},
	}}
	payload, _ := proto.Marshal(bulk)

	done := make(chan error, 1)
	go func() {
		done <- s.handleBulkSetRegion(cartaDefinitions.EventType_BULK_SET_REGION, 42, payload)
	}()

	// Each worker receives a SET_REGION; reply with an ack on that controller id.
	for _, w := range []*SessionWorker{w0, w1} {
		raw := <-w.sendChan
		prefix, _ := cartaHelpers.DecodeMessagePrefix(raw)
		if prefix.EventType != cartaDefinitions.EventType_SET_REGION {
			t.Fatalf("expected SET_REGION, got %v", prefix.EventType)
		}
		ackBytes, _ := proto.Marshal(&cartaDefinitions.SetRegionAck{Success: true, RegionId: 5})
		if !w.deliverToPending(prefix.RequestId, cartaDefinitions.EventType_SET_REGION_ACK, ackBytes) {
			t.Fatalf("deliverToPending failed for requestId %d", prefix.RequestId)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("handler error: %v", err)
	}

	raw := <-s.clientSendChan
	prefix, _ := cartaHelpers.DecodeMessagePrefix(raw)
	if prefix.EventType != cartaDefinitions.EventType_BULK_SET_REGION_ACK {
		t.Fatalf("expected BULK_SET_REGION_ACK, got %v", prefix.EventType)
	}
	if prefix.RequestId != 42 {
		t.Fatalf("expected requestId 42, got %d", prefix.RequestId)
	}
	var ack cartaDefinitions.BulkSetRegionAck
	if err := proto.Unmarshal(raw[8:], &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ack.GetAcks()) != 2 {
		t.Fatalf("expected 2 acks, got %d", len(ack.GetAcks()))
	}
	for _, a := range ack.GetAcks() {
		if !a.GetSuccess() {
			t.Fatalf("ack not success: %+v", a)
		}
	}
}

func TestHandleBulkSetRegion_NoWorkerFailsImmediately(t *testing.T) {
	s := &Session{
		Context:        context.Background(),
		clientSendChan: make(chan []byte, 4),
		sharedWorker:   &SessionWorker{},
		fileMap:        map[int32]*SessionWorker{},
	}
	bulk := &cartaDefinitions.BulkSetRegion{SetRegions: []*cartaDefinitions.SetRegion{{FileId: 3, RegionId: 1}}}
	payload, _ := proto.Marshal(bulk)

	if err := s.handleBulkSetRegion(cartaDefinitions.EventType_BULK_SET_REGION, 7, payload); err != nil {
		t.Fatalf("handler: %v", err)
	}
	raw := <-s.clientSendChan
	var ack cartaDefinitions.BulkSetRegionAck
	if err := proto.Unmarshal(raw[8:], &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ack.GetAcks()) != 1 || ack.GetAcks()[0].GetSuccess() {
		t.Fatalf("expected 1 failure ack, got %+v", ack.GetAcks())
	}
}

func TestHandleBulkRemoveRegion_FansOutToWorkers(t *testing.T) {
	s := &Session{
		Context:        context.Background(),
		clientSendChan: make(chan []byte, 4),
		sharedWorker:   &SessionWorker{},
		fileMap:        map[int32]*SessionWorker{},
	}
	w0 := &SessionWorker{sendChan: make(chan []byte, 4)}
	w1 := &SessionWorker{sendChan: make(chan []byte, 4)}
	s.fileMap[0] = w0
	s.fileMap[1] = w1

	bulk := &cartaDefinitions.BulkRemoveRegion{RemoveRegions: []*cartaDefinitions.RemoveRegion{
		{FileId: 0, RegionId: 5},
		{FileId: 1, RegionId: 5},
	}}
	payload, _ := proto.Marshal(bulk)

	if err := s.handleBulkRemoveRegion(cartaDefinitions.EventType_BULK_REMOVE_REGION, 99, payload); err != nil {
		t.Fatalf("handler: %v", err)
	}

	for _, w := range []*SessionWorker{w0, w1} {
		raw := <-w.sendChan
		prefix, _ := cartaHelpers.DecodeMessagePrefix(raw)
		if prefix.EventType != cartaDefinitions.EventType_REMOVE_REGION {
			t.Fatalf("expected REMOVE_REGION, got %v", prefix.EventType)
		}
		var rr cartaDefinitions.RemoveRegion
		if err := proto.Unmarshal(raw[8:], &rr); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if rr.GetRegionId() != 5 {
			t.Fatalf("expected region 5, got %d", rr.GetRegionId())
		}
	}

	// Fire-and-forget: nothing goes to the client.
	select {
	case <-s.clientSendChan:
		t.Fatalf("bulk remove must not send a client message")
	default:
	}
}
