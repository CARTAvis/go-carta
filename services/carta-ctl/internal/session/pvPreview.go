package session

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

// handlePvRequest routes a PV_REQUEST to the source file's backend (by file_id,
// like any other proxied message) and, for preview-mode requests, records the
// preview_id -> file_id mapping so the later STOP_PV_PREVIEW / CLOSE_PV_PREVIEW
// (which carry only the preview_id) can reach the same backend.
func (s *Session) handlePvRequest(eventType cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.PvRequest
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing pv request: %v", err)
	}
	if ps := payload.GetPreviewSettings(); ps != nil {
		s.setPvPreviewFile(ps.GetPreviewId(), payload.GetFileId())
	}
	return s.handleProxiedMessage(eventType, requestId, msg)
}

// handleStopPvPreview routes a STOP_PV_PREVIEW to the backend running the
// preview. The mapping is retained so the preview can be resumed.
func (s *Session) handleStopPvPreview(eventType cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.StopPvPreview
	if err := proto.Unmarshal(msg, &payload); err != nil {
		return fmt.Errorf("error parsing stop pv preview: %v", err)
	}
	return s.routePvPreview(payload.GetPreviewId(), eventType, requestId, msg, false)
}

// handleClosePvPreview routes a CLOSE_PV_PREVIEW to the backend running the
// preview and forgets the mapping.
func (s *Session) handleClosePvPreview(eventType cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.ClosePvPreview
	if err := proto.Unmarshal(msg, &payload); err != nil {
		return fmt.Errorf("error parsing close pv preview: %v", err)
	}
	return s.routePvPreview(payload.GetPreviewId(), eventType, requestId, msg, true)
}

// routePvPreview forwards a preview control message to the worker that owns
// previewId. When forget is true the mapping is removed (the preview is closing).
func (s *Session) routePvPreview(previewId int32, eventType cartaDefinitions.EventType, requestId uint32, msg []byte, forget bool) error {
	fileId, ok := s.pvPreviewFile(previewId)
	if !ok {
		return fmt.Errorf("no backend mapped for pv preview_id=%d", previewId)
	}
	if forget {
		s.deletePvPreview(previewId)
	}
	worker, ok := s.getFileWorker(fileId)
	if !ok || worker == nil {
		return fmt.Errorf("no backend for file_id=%d (pv preview_id=%d)", fileId, previewId)
	}
	if !worker.enqueue(cartaHelpers.PrepareBinaryMessage(msg, eventType, requestId)) {
		return fmt.Errorf("worker for file_id=%d is shutting down", fileId)
	}
	return nil
}

func (s *Session) setPvPreviewFile(previewId, fileId int32) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	if s.pvPreviewToFile == nil {
		s.pvPreviewToFile = make(map[int32]int32)
	}
	s.pvPreviewToFile[previewId] = fileId
}

func (s *Session) pvPreviewFile(previewId int32) (int32, bool) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	fileId, ok := s.pvPreviewToFile[previewId]
	return fileId, ok
}

func (s *Session) deletePvPreview(previewId int32) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	delete(s.pvPreviewToFile, previewId)
}

// deletePvPreviewsForFile drops every preview mapping owned by fileId, called
// when that file's backend is reaped so stale previews don't linger in the map.
func (s *Session) deletePvPreviewsForFile(fileId int32) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	for previewId, fid := range s.pvPreviewToFile {
		if fid == fileId {
			delete(s.pvPreviewToFile, previewId)
		}
	}
}
