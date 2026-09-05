package session

import (
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// handlePvRequest routes a PV_REQUEST by file id and, for previews, records
// which file's backend owns the preview id so that STOP_PV_PREVIEW and
// CLOSE_PV_PREVIEW, which carry only that id, can follow it.
func (s *Session) handlePvRequest(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.PvRequest
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing pv request: %v", err)
	}
	fileId := payload.GetFileId()
	if err := s.sendToWorker(s.workerForFile(fileId), cartaDefinitions.EventType_PV_REQUEST, requestId, msg); err != nil {
		return err
	}
	if ps := payload.GetPreviewSettings(); ps != nil {
		if old, moved := s.setPvPreviewFile(ps.GetPreviewId(), fileId); moved {
			s.closeStalePvPreview(ps.GetPreviewId(), old, requestId)
		}
	}
	return nil
}

func (s *Session) handleStopPvPreview(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.StopPvPreview
	if err := proto.Unmarshal(msg, &payload); err != nil {
		return fmt.Errorf("error parsing stop pv preview: %v", err)
	}
	fileId, ok := s.pvPreviewFile(payload.GetPreviewId())
	if !ok {
		slog.Debug("Ignoring STOP_PV_PREVIEW for an unknown preview", "previewId", payload.GetPreviewId())
		return nil
	}
	return s.sendToWorker(s.workerForFile(fileId), cartaDefinitions.EventType_STOP_PV_PREVIEW, requestId, msg)
}

func (s *Session) handleClosePvPreview(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.ClosePvPreview
	if err := proto.Unmarshal(msg, &payload); err != nil {
		return fmt.Errorf("error parsing close pv preview: %v", err)
	}
	fileId, ok := s.takePvPreview(payload.GetPreviewId())
	if !ok {
		slog.Debug("Ignoring CLOSE_PV_PREVIEW for an unknown preview", "previewId", payload.GetPreviewId())
		return nil
	}
	return s.sendToWorker(s.workerForFile(fileId), cartaDefinitions.EventType_CLOSE_PV_PREVIEW, requestId, msg)
}

// closeStalePvPreview tells the backend that previously served previewId to
// drop it, after the preview has moved to another file.
func (s *Session) closeStalePvPreview(previewId, oldFileId int32, requestId uint32) {
	worker := s.workerForFile(oldFileId)
	if worker == nil {
		return
	}
	msg := &cartaDefinitions.ClosePvPreview{PreviewId: previewId}
	if err := worker.proxyMessageToWorker(msg, cartaDefinitions.EventType_CLOSE_PV_PREVIEW, requestId); err != nil {
		slog.Warn("Failed to close stale pv preview", "previewId", previewId, "fileId", oldFileId, "error", err)
	}
}

// setPvPreviewFile records fileId as the owner of previewId. It reports the
// previous owner when the preview has moved from a different file.
func (s *Session) setPvPreviewFile(previewId, fileId int32) (old int32, moved bool) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	if s.pvPreviewToFile == nil {
		s.pvPreviewToFile = make(map[int32]int32)
	}
	old, existed := s.pvPreviewToFile[previewId]
	s.pvPreviewToFile[previewId] = fileId
	return old, existed && old != fileId
}

func (s *Session) pvPreviewFile(previewId int32) (int32, bool) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	fileId, ok := s.pvPreviewToFile[previewId]
	return fileId, ok
}

func (s *Session) takePvPreview(previewId int32) (int32, bool) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	fileId, ok := s.pvPreviewToFile[previewId]
	delete(s.pvPreviewToFile, previewId)
	return fileId, ok
}

func (s *Session) deletePvPreviewsForFile(fileId int32) {
	s.pvPreviewMu.Lock()
	defer s.pvPreviewMu.Unlock()
	for previewId, fid := range s.pvPreviewToFile {
		if fid == fileId {
			delete(s.pvPreviewToFile, previewId)
		}
	}
}
