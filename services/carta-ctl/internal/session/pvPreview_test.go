package session

import (
	"testing"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

func pvRequest(fileId, previewId int32) *cartaDefinitions.PvRequest {
	req := &cartaDefinitions.PvRequest{FileId: fileId, RegionId: 1}
	if previewId != 0 {
		req.PreviewSettings = &cartaDefinitions.PvPreviewSettings{PreviewId: previewId}
	}
	return req
}

func TestHandlePvRequest_RecordsPreviewMappingAndRoutes(t *testing.T) {
	s := newSessionWithFiles(5)
	w, _ := s.getFileWorker(5)

	if err := s.handlePvRequest(cartaDefinitions.EventType_PV_REQUEST, 1, marshal(t, pvRequest(5, 42))); err != nil {
		t.Fatalf("handlePvRequest: %v", err)
	}
	expectWorkerEvent(t, w, cartaDefinitions.EventType_PV_REQUEST)
	if fileId, ok := s.pvPreviewFile(42); !ok || fileId != 5 {
		t.Fatalf("expected preview 42 -> file 5, got %d ok=%v", fileId, ok)
	}
}

func TestHandlePvRequest_NonPreviewDoesNotRecord(t *testing.T) {
	s := newSessionWithFiles(5)
	w, _ := s.getFileWorker(5)

	if err := s.handlePvRequest(cartaDefinitions.EventType_PV_REQUEST, 1, marshal(t, pvRequest(5, 0))); err != nil {
		t.Fatalf("handlePvRequest: %v", err)
	}
	expectWorkerEvent(t, w, cartaDefinitions.EventType_PV_REQUEST)
	if len(s.pvPreviewToFile) != 0 {
		t.Fatal("a non-preview PV request must not record a mapping")
	}
}

func TestHandlePvRequest_MovedPreviewClosesOnOldBackend(t *testing.T) {
	s := newSessionWithFiles(5, 6)
	w5, _ := s.getFileWorker(5)
	w6, _ := s.getFileWorker(6)
	s.setPvPreviewFile(42, 5)

	if err := s.handlePvRequest(cartaDefinitions.EventType_PV_REQUEST, 1, marshal(t, pvRequest(6, 42))); err != nil {
		t.Fatalf("handlePvRequest: %v", err)
	}
	expectWorkerEvent(t, w6, cartaDefinitions.EventType_PV_REQUEST)
	expectWorkerEvent(t, w5, cartaDefinitions.EventType_CLOSE_PV_PREVIEW)
	if fileId, _ := s.pvPreviewFile(42); fileId != 6 {
		t.Fatalf("expected preview 42 -> file 6, got %d", fileId)
	}
}

func TestHandleStopPvPreview_RoutesToMappedWorkerAndKeepsMapping(t *testing.T) {
	s := newSessionWithFiles(5)
	w, _ := s.getFileWorker(5)
	s.setPvPreviewFile(42, 5)

	raw := marshal(t, &cartaDefinitions.StopPvPreview{PreviewId: 42})
	if err := s.handleStopPvPreview(cartaDefinitions.EventType_STOP_PV_PREVIEW, 2, raw); err != nil {
		t.Fatalf("handleStopPvPreview: %v", err)
	}
	prefix := expectWorkerEvent(t, w, cartaDefinitions.EventType_STOP_PV_PREVIEW)
	if prefix.RequestId != 2 {
		t.Fatalf("request id not preserved: %d", prefix.RequestId)
	}
	if _, ok := s.pvPreviewFile(42); !ok {
		t.Fatal("stopping a preview must keep its mapping so it can resume")
	}
}

func TestHandleClosePvPreview_RoutesAndForgets(t *testing.T) {
	s := newSessionWithFiles(5)
	w, _ := s.getFileWorker(5)
	s.setPvPreviewFile(42, 5)

	raw := marshal(t, &cartaDefinitions.ClosePvPreview{PreviewId: 42})
	if err := s.handleClosePvPreview(cartaDefinitions.EventType_CLOSE_PV_PREVIEW, 3, raw); err != nil {
		t.Fatalf("handleClosePvPreview: %v", err)
	}
	expectWorkerEvent(t, w, cartaDefinitions.EventType_CLOSE_PV_PREVIEW)
	if _, ok := s.pvPreviewFile(42); ok {
		t.Fatal("closing a preview must forget its mapping")
	}
}

func TestHandleStopPvPreview_UnknownPreviewIsIgnored(t *testing.T) {
	s := newSessionWithFiles(5)
	w, _ := s.getFileWorker(5)

	raw := marshal(t, &cartaDefinitions.StopPvPreview{PreviewId: 99})
	if err := s.handleStopPvPreview(cartaDefinitions.EventType_STOP_PV_PREVIEW, 2, raw); err != nil {
		t.Fatalf("an unknown preview should be ignored, got %v", err)
	}
	expectNoWorkerEvent(t, w)
	expectNoWorkerEvent(t, s.sharedWorker)
}

func TestHandleCloseFile_DropsPvPreviews(t *testing.T) {
	s := newSessionWithFiles(5)
	s.setPvPreviewFile(42, 5)
	s.setPvPreviewFile(43, 5)

	closeFile(t, s, 5)

	if len(s.pvPreviewToFile) != 0 {
		t.Fatalf("expected preview mappings dropped with the file, %d remain", len(s.pvPreviewToFile))
	}
}
