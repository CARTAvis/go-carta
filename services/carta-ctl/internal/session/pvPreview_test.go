package session

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

func newPvSession(fileId int32, worker *SessionWorker) *Session {
	return &Session{
		sharedWorker: &SessionWorker{}, // non-nil so checkAndParse passes
		fileMap:      map[int32]*SessionWorker{fileId: worker},
	}
}

// expectWorkerEvent reads one frame off the worker and asserts its EventType.
func expectWorkerEvent(t *testing.T, w *SessionWorker, want cartaDefinitions.EventType) {
	t.Helper()
	select {
	case raw := <-w.sendChan:
		prefix, err := cartaHelpers.DecodeMessagePrefix(raw)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if prefix.EventType != want {
			t.Fatalf("worker got %v, want %v", prefix.EventType, want)
		}
	default:
		t.Fatalf("expected %v to be routed to the worker, got nothing", want)
	}
}

func TestHandlePvRequest_RecordsPreviewMappingAndRoutes(t *testing.T) {
	w := &SessionWorker{sendChan: make(chan []byte, 4)}
	s := newPvSession(5, w)

	req := &cartaDefinitions.PvRequest{
		FileId:          5,
		PreviewSettings: &cartaDefinitions.PvPreviewSettings{PreviewId: 42},
	}
	payload, _ := proto.Marshal(req)
	if err := s.handlePvRequest(cartaDefinitions.EventType_PV_REQUEST, 7, payload); err != nil {
		t.Fatalf("handlePvRequest: %v", err)
	}

	expectWorkerEvent(t, w, cartaDefinitions.EventType_PV_REQUEST)
	if fileId, ok := s.pvPreviewFile(42); !ok || fileId != 5 {
		t.Fatalf("preview 42 should map to file 5, got (%d, %v)", fileId, ok)
	}
}

func TestHandlePvRequest_NonPreviewDoesNotRecord(t *testing.T) {
	w := &SessionWorker{sendChan: make(chan []byte, 4)}
	s := newPvSession(5, w)

	payload, _ := proto.Marshal(&cartaDefinitions.PvRequest{FileId: 5}) // no PreviewSettings
	if err := s.handlePvRequest(cartaDefinitions.EventType_PV_REQUEST, 7, payload); err != nil {
		t.Fatalf("handlePvRequest: %v", err)
	}

	expectWorkerEvent(t, w, cartaDefinitions.EventType_PV_REQUEST)
	if _, ok := s.pvPreviewFile(0); ok {
		t.Fatal("a non-preview PV request must not record a preview mapping")
	}
}

func TestHandleStopPvPreview_RoutesToMappedWorkerAndKeepsMapping(t *testing.T) {
	w := &SessionWorker{sendChan: make(chan []byte, 4)}
	s := newPvSession(5, w)
	s.setPvPreviewFile(42, 5)

	payload, _ := proto.Marshal(&cartaDefinitions.StopPvPreview{PreviewId: 42})
	// requestId 0 is valid for this fire-and-forget control message.
	if err := s.handleStopPvPreview(cartaDefinitions.EventType_STOP_PV_PREVIEW, 0, payload); err != nil {
		t.Fatalf("handleStopPvPreview: %v", err)
	}

	expectWorkerEvent(t, w, cartaDefinitions.EventType_STOP_PV_PREVIEW)
	if _, ok := s.pvPreviewFile(42); !ok {
		t.Fatal("STOP must keep the preview mapping (it may resume)")
	}
}

func TestHandleClosePvPreview_RoutesAndForgets(t *testing.T) {
	w := &SessionWorker{sendChan: make(chan []byte, 4)}
	s := newPvSession(5, w)
	s.setPvPreviewFile(42, 5)

	payload, _ := proto.Marshal(&cartaDefinitions.ClosePvPreview{PreviewId: 42})
	if err := s.handleClosePvPreview(cartaDefinitions.EventType_CLOSE_PV_PREVIEW, 0, payload); err != nil {
		t.Fatalf("handleClosePvPreview: %v", err)
	}

	expectWorkerEvent(t, w, cartaDefinitions.EventType_CLOSE_PV_PREVIEW)
	if _, ok := s.pvPreviewFile(42); ok {
		t.Fatal("CLOSE must forget the preview mapping")
	}
}

func TestHandleStopPvPreview_UnknownPreviewErrors(t *testing.T) {
	w := &SessionWorker{sendChan: make(chan []byte, 4)}
	s := newPvSession(5, w)

	payload, _ := proto.Marshal(&cartaDefinitions.StopPvPreview{PreviewId: 99})
	if err := s.handleStopPvPreview(cartaDefinitions.EventType_STOP_PV_PREVIEW, 0, payload); err == nil {
		t.Fatal("expected an error for an unmapped preview id")
	}
}

func TestShutdownFileWorker_DropsPvPreviews(t *testing.T) {
	s := &Session{fileMap: map[int32]*SessionWorker{5: newTestFileWorker()}}
	s.setPvPreviewFile(42, 5)
	s.setPvPreviewFile(7, 5)

	s.shutdownFileWorker(5)

	if _, ok := s.pvPreviewFile(42); ok {
		t.Fatal("closing file 5 should drop its preview mappings")
	}
	if _, ok := s.pvPreviewFile(7); ok {
		t.Fatal("closing file 5 should drop all its preview mappings")
	}
}
