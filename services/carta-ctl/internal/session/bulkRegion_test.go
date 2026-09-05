package session

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

const bulkTestRequestId = 7

// ackFromWorker pops the SET_REGION the worker received and answers it.
func ackFromWorker(t *testing.T, w *SessionWorker, ack *cartaDefinitions.SetRegionAck) {
	t.Helper()
	prefix := expectWorkerEvent(t, w, cartaDefinitions.EventType_SET_REGION)
	if !w.deliverToPending(prefix.RequestId, cartaDefinitions.EventType_SET_REGION_ACK, marshal(t, ack)) {
		t.Fatalf("worker %s had no pending request %d", w.name, prefix.RequestId)
	}
}

func bulkSetRegion(t *testing.T, s *Session, bulk *cartaDefinitions.BulkSetRegion) <-chan error {
	t.Helper()
	raw := marshal(t, bulk)
	done := make(chan error, 1)
	go func() {
		done <- s.handleBulkSetRegion(cartaDefinitions.EventType_BULK_SET_REGION, bulkTestRequestId, raw)
	}()
	return done
}

func readBulkAck(t *testing.T, s *Session, done <-chan error) *cartaDefinitions.BulkSetRegionAck {
	t.Helper()
	if err := <-done; err != nil {
		t.Fatalf("handleBulkSetRegion: %v", err)
	}
	raw := (<-s.clientSendChan).data
	prefix, err := cartaHelpers.DecodeMessagePrefix(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if prefix.EventType != cartaDefinitions.EventType_BULK_SET_REGION_ACK || prefix.RequestId != bulkTestRequestId {
		t.Fatalf("unexpected frame %v request %d", prefix.EventType, prefix.RequestId)
	}
	var ack cartaDefinitions.BulkSetRegionAck
	if err := proto.Unmarshal(raw[8:], &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &ack
}

func TestHandleBulkSetRegion_FansOutAndGathersInOrder(t *testing.T) {
	s := newSessionWithFiles(0, 1)
	w0, _ := s.getFileWorker(0)
	w1, _ := s.getFileWorker(1)

	done := bulkSetRegion(t, s, &cartaDefinitions.BulkSetRegion{SetRegions: []*cartaDefinitions.SetRegion{
		{FileId: 1, RegionId: 5},
		{FileId: 0, RegionId: 5},
	}})
	ackFromWorker(t, w0, &cartaDefinitions.SetRegionAck{Success: true, RegionId: 5})
	ackFromWorker(t, w1, &cartaDefinitions.SetRegionAck{Success: false, RegionId: 5, Message: "nope"})

	ack := readBulkAck(t, s, done)
	if len(ack.Acks) != 2 {
		t.Fatalf("expected 2 acks, got %d", len(ack.Acks))
	}
	if ack.Acks[0].FileId != 1 || ack.Acks[0].Success || ack.Acks[0].Message != "nope" {
		t.Fatalf("ack 0 should be file 1's failure, got %+v", ack.Acks[0])
	}
	if ack.Acks[1].FileId != 0 || !ack.Acks[1].Success {
		t.Fatalf("ack 1 should be file 0's success, got %+v", ack.Acks[1])
	}
}

func TestHandleBulkSetRegion_UnknownFileGoesToSharedBackend(t *testing.T) {
	s := newSessionWithFiles(0)

	done := bulkSetRegion(t, s, &cartaDefinitions.BulkSetRegion{SetRegions: []*cartaDefinitions.SetRegion{
		{FileId: 9, RegionId: 2},
	}})
	ackFromWorker(t, s.sharedWorker, &cartaDefinitions.SetRegionAck{Success: true, RegionId: 2})

	ack := readBulkAck(t, s, done)
	if len(ack.Acks) != 1 || !ack.Acks[0].Success || ack.Acks[0].FileId != 9 {
		t.Fatalf("unexpected acks %+v", ack.Acks)
	}
}

func TestHandleBulkSetRegion_PreviewRegionIsNotAwaited(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	done := bulkSetRegion(t, s, &cartaDefinitions.BulkSetRegion{SetRegions: []*cartaDefinitions.SetRegion{
		{FileId: 0, RegionId: 3, PreviewRegion: true},
	}})

	ack := readBulkAck(t, s, done)
	prefix := expectWorkerEvent(t, w0, cartaDefinitions.EventType_SET_REGION)
	if prefix.RequestId&controllerRequestIDBit == 0 {
		t.Fatal("a preview region must be forwarded under a controller request id")
	}
	if len(ack.Acks) != 1 || !ack.Acks[0].Success || ack.Acks[0].RegionId != 3 {
		t.Fatalf("unexpected acks %+v", ack.Acks)
	}
}

func TestHandleBulkSetRegion_LostBackendFailsEntry(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	done := bulkSetRegion(t, s, &cartaDefinitions.BulkSetRegion{SetRegions: []*cartaDefinitions.SetRegion{
		{FileId: 0, RegionId: 4},
	}})
	expectWorkerEvent(t, w0, cartaDefinitions.EventType_SET_REGION)
	w0.failAllPending()

	ack := readBulkAck(t, s, done)
	if len(ack.Acks) != 1 || ack.Acks[0].Success {
		t.Fatalf("expected a failure ack, got %+v", ack.Acks)
	}
}

func TestHandleBulkSetRegion_EmptyRequestStillAcks(t *testing.T) {
	s := newSessionWithFiles()

	ack := readBulkAck(t, s, bulkSetRegion(t, s, &cartaDefinitions.BulkSetRegion{}))
	if len(ack.Acks) != 0 {
		t.Fatalf("expected no acks, got %d", len(ack.Acks))
	}
}

func TestHandleBulkRemoveRegion_FansOutToWorkers(t *testing.T) {
	s := newSessionWithFiles(0, 1)
	w0, _ := s.getFileWorker(0)
	w1, _ := s.getFileWorker(1)

	bulk := &cartaDefinitions.BulkRemoveRegion{RemoveRegions: []*cartaDefinitions.RemoveRegion{
		{FileId: 0, RegionId: 5},
		{FileId: 1, RegionId: 5},
	}}
	if err := s.handleBulkRemoveRegion(cartaDefinitions.EventType_BULK_REMOVE_REGION, 8, marshal(t, bulk)); err != nil {
		t.Fatalf("handleBulkRemoveRegion: %v", err)
	}
	expectWorkerEvent(t, w0, cartaDefinitions.EventType_REMOVE_REGION)
	expectWorkerEvent(t, w1, cartaDefinitions.EventType_REMOVE_REGION)
	expectNoWorkerEvent(t, s.sharedWorker)
}

func TestHandleMessage_RejectsControllerRequestIds(t *testing.T) {
	s := newSessionWithFiles()
	frame := cartaHelpers.PrepareBinaryMessage(marshal(t, &cartaDefinitions.SetCursor{FileId: 0}), cartaDefinitions.EventType_SET_CURSOR, controllerRequestIDBit|5)

	if err := s.HandleMessage(frame); err == nil {
		t.Fatal("a client request id with the controller bit set must be rejected")
	}
	expectNoWorkerEvent(t, s.sharedWorker)
}
