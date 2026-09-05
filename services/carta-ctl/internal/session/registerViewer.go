package session

import (
	"fmt"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// handleRegisterViewerMessage starts the session's shared backend and forwards
// the registration to it.
func (s *Session) handleRegisterViewerMessage(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.RegisterViewer
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing message: %v", err)
	}

	s.setRegisterViewer(&payload)
	w := newSessionWorker(s, nil, requestId)
	displaced, ok := s.setSharedWorker(w)
	if !ok {
		return fmt.Errorf("session ended during registration")
	}
	if displaced != nil {
		displaced.shutdown()
	}
	if err := w.proxyMessageToWorker(&payload, cartaDefinitions.EventType_REGISTER_VIEWER, requestId); err != nil {
		return err
	}
	w.startAsync(func(err error) {
		s.sendAckToClient(&cartaDefinitions.RegisterViewerAck{Success: false, Message: err.Error()},
			cartaDefinitions.EventType_REGISTER_VIEWER_ACK, requestId)
	})
	return nil
}
