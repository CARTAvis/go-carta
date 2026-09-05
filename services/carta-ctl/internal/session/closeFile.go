package session

import (
	"fmt"
	"log/slog"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// handleCloseFile shuts down the backend serving the file, or every file
// backend when file_id is -1. An image a backend derived from its own file is
// closed on that backend, which keeps running. Files held by the shared
// backend are closed by forwarding the message to it.
func (s *Session) handleCloseFile(eventType cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.CloseFile
	if err := s.parse(&payload, msg); err != nil {
		return fmt.Errorf("error parsing close file: %v", err)
	}
	if payload.FileId == -1 {
		err := s.proxyToShared(eventType, requestId, msg)
		fileIds, workers := s.takeFileWorkers()
		for _, fileId := range fileIds {
			s.deletePvPreviewsForFile(fileId)
		}
		for _, w := range workers {
			w.shutdown()
		}
		return err
	}

	w := s.takeFileWorker(payload.FileId)
	if w == nil {
		return s.proxyToShared(eventType, requestId, msg)
	}
	s.deletePvPreviewsForFile(payload.FileId)
	if w.fileRequest.FileId != payload.FileId {
		err := s.sendToWorker(w, eventType, requestId, msg)
		w.forgetDerivedFile(payload.FileId)
		return err
	}
	fileIds, _ := s.removeWorker(w)
	for _, fileId := range fileIds {
		s.deletePvPreviewsForFile(fileId)
	}
	w.shutdown()
	return nil
}

// dropWorker unregisters a worker and shuts it down, without reporting it as
// a loss. Used when the client is told what happened by other means.
func (s *Session) dropWorker(sw *SessionWorker) {
	s.removeWorker(sw)
	sw.shutdown()
}

// workerLost unregisters a worker whose backend connection has dropped, along
// with any derived images it served, and shuts it down. Losing the shared
// backend ends the session, so the client reconnects rather than talking to a
// backend that is gone.
func (s *Session) workerLost(sw *SessionWorker) {
	fileIds, wasShared := s.removeWorker(sw)
	for _, fileId := range fileIds {
		s.deletePvPreviewsForFile(fileId)
	}
	sw.shutdown()
	if wasShared {
		slog.Warn("Shared backend connection lost, ending session", "user", s.User)
		s.endSession()
		return
	}
	for _, fileId := range fileIds {
		slog.Warn("Backend connection lost", "fileId", fileId, "workerName", sw.name)
		s.sendErrorToClient(fmt.Sprintf("The backend serving file %d is no longer available. Close and reopen the image to continue.", fileId))
	}
}
