package session

import (
	"fmt"
	"log/slog"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// handleCloseFile shuts down the backend serving the file, or every file
// backend when file_id is -1. Files held by the shared backend are closed by
// forwarding the message to it.
func (s *Session) handleCloseFile(eventType cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.CloseFile
	if err := s.parse(&payload, msg); err != nil {
		return fmt.Errorf("error parsing close file: %v", err)
	}
	if payload.FileId == -1 {
		err := s.proxyToShared(eventType, requestId, msg)
		for _, w := range s.takeFileWorkers() {
			w.shutdown()
		}
		return err
	}
	w := s.takeFileWorker(payload.FileId)
	if w == nil {
		return s.proxyToShared(eventType, requestId, msg)
	}
	w.shutdown()
	return nil
}

// workerLost unregisters a worker whose backend connection has dropped and
// shuts it down. Losing the shared backend ends the session, so the client
// reconnects rather than talking to a backend that is gone.
// dropWorker unregisters a worker and shuts it down, without reporting it as
// a loss. Used when the client is told what happened by other means.
func (s *Session) dropWorker(sw *SessionWorker) {
	s.removeWorker(sw)
	sw.shutdown()
}

func (s *Session) workerLost(sw *SessionWorker) {
	fileIds, wasShared := s.removeWorker(sw)
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
