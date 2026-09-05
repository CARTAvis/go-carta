package session

import (
	"fmt"
	"log/slog"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// handleOpenFile starts a dedicated backend for the file. The worker is
// registered and its registration queued before the backend is started, so
// nothing overtakes the registration and a close arriving meanwhile is
// honoured. The worker forwards the open request once the backend
// acknowledges it.
func (s *Session) handleOpenFile(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.OpenFile
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing message: %v", err)
	}

	w := newSessionWorker(s, &payload, requestId)
	displaced, ok := s.setFileWorker(payload.FileId, w)
	if !ok {
		return fmt.Errorf("session ended while opening file %d", payload.FileId)
	}
	if displaced != nil {
		slog.Warn("Replacing backend for a file that is already open", "fileId", payload.FileId)
		displaced.shutdown()
	}
	if err := w.proxyMessageToWorker(s.clientRegistration(), cartaDefinitions.EventType_REGISTER_VIEWER, requestId); err != nil {
		return err
	}
	w.startAsync(func(err error) {
		s.sendAckToClient(&cartaDefinitions.OpenFileAck{Success: false, FileId: payload.FileId, Message: err.Error()},
			cartaDefinitions.EventType_OPEN_FILE_ACK, requestId)
	})
	return nil
}
