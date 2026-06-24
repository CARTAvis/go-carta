package session

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

func TestRequest_DeliversResponseThenCloses(t *testing.T) {
	sw := &SessionWorker{sendChan: make(chan []byte, 4)}
	ch, cancel, err := sw.Request(context.Background(), cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{FileId: 0, RegionId: 5})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	defer cancel()

	raw := <-sw.sendChan
	prefix, err := cartaHelpers.DecodeMessagePrefix(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if prefix.RequestId&(1<<31) == 0 {
		t.Fatalf("controller requestId should have high bit set, got %d", prefix.RequestId)
	}

	ackBytes, _ := proto.Marshal(&cartaDefinitions.SetRegionAck{Success: true, RegionId: 5})
	if !sw.deliverToPending(prefix.RequestId, cartaDefinitions.EventType_SET_REGION_ACK, ackBytes) {
		t.Fatalf("deliverToPending returned false for a pending request")
	}

	wm, ok := <-ch
	if !ok {
		t.Fatalf("channel closed without a value")
	}
	if wm.EventType != cartaDefinitions.EventType_SET_REGION_ACK {
		t.Fatalf("unexpected event type %v", wm.EventType)
	}
	if _, ok := <-ch; ok {
		t.Fatalf("channel should be closed after one-shot delivery")
	}
}

func TestRequest_TimeoutClosesChannel(t *testing.T) {
	sw := &SessionWorker{sendChan: make(chan []byte, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	ch, _, err := sw.Request(ctx, cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	<-sw.sendChan
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected closed channel after ctx cancel")
		}
	case <-time.After(time.Second):
		t.Fatalf("channel not closed after ctx cancel")
	}
}

func TestDeliverToPending_UnknownReturnsFalse(t *testing.T) {
	sw := &SessionWorker{}
	if sw.deliverToPending(12345, cartaDefinitions.EventType_SET_REGION_ACK, nil) {
		t.Fatalf("expected false for unknown requestId")
	}
}

func TestRequestStream_DeliversUntilTerminal(t *testing.T) {
	sw := &SessionWorker{sendChan: make(chan []byte, 4)}
	isTerminal := func(et cartaDefinitions.EventType, _ []byte) bool {
		return et == cartaDefinitions.EventType_FILE_LIST_RESPONSE
	}
	ch, _, err := sw.RequestStream(context.Background(), cartaDefinitions.EventType_FILE_LIST_REQUEST, &cartaDefinitions.FileListRequest{}, isTerminal, 8)
	if err != nil {
		t.Fatalf("RequestStream: %v", err)
	}
	raw := <-sw.sendChan
	prefix, _ := cartaHelpers.DecodeMessagePrefix(raw)
	rid := prefix.RequestId

	sw.deliverToPending(rid, cartaDefinitions.EventType_FILE_LIST_PROGRESS, nil)
	sw.deliverToPending(rid, cartaDefinitions.EventType_FILE_LIST_PROGRESS, nil)
	sw.deliverToPending(rid, cartaDefinitions.EventType_FILE_LIST_RESPONSE, nil)

	count := 0
	for range ch {
		count++
	}
	if count != 3 {
		t.Fatalf("expected 3 stream items, got %d", count)
	}
}

func TestRequest_ReturnedCancelClosesChannel(t *testing.T) {
	sw := &SessionWorker{sendChan: make(chan []byte, 4)}
	ch, cancel, err := sw.Request(context.Background(), cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	<-sw.sendChan
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected closed channel after cancel()")
		}
	case <-time.After(time.Second):
		t.Fatalf("channel not closed after cancel()")
	}
}

func TestRequestStream_ReturnedCancelClosesChannel(t *testing.T) {
	sw := &SessionWorker{sendChan: make(chan []byte, 4)}
	ch, cancel, err := sw.RequestStream(context.Background(), cartaDefinitions.EventType_FILE_LIST_REQUEST, &cartaDefinitions.FileListRequest{}, nil, 8)
	if err != nil {
		t.Fatalf("RequestStream: %v", err)
	}
	<-sw.sendChan
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected closed channel after cancel()")
		}
	case <-time.After(time.Second):
		t.Fatalf("channel not closed after cancel()")
	}
}

func TestFailAllPending_ClosesInflightChannels(t *testing.T) {
	sw := &SessionWorker{sendChan: make(chan []byte, 4)}
	ch, cancel, err := sw.Request(context.Background(), cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	defer cancel()
	<-sw.sendChan

	// Simulates the worker read loop exiting after the backend connection drops.
	sw.failAllPending()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected closed channel after failAllPending")
		}
	case <-time.After(time.Second):
		t.Fatalf("channel not closed after failAllPending (would block forever on a real crash)")
	}
}

func TestRequest_TimeoutLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	sw := &SessionWorker{sendChan: make(chan []byte, 4), fileRequest: &cartaDefinitions.OpenFile{FileId: 7}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	ch, _, err := sw.Request(ctx, cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	<-sw.sendChan
	<-ch // blocks until the timeout watcher closes the channel

	if !strings.Contains(buf.String(), "timed out") {
		t.Fatalf("expected a timeout warning, got: %q", buf.String())
	}
}
