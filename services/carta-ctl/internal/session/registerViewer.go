package session

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gorilla/websocket"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

// RegisterViewer is a special case as it is the first message we receive and is used to spin up the worker connection and set up the proxy handler
func (s *Session) handleRegisterViewerMessage(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.RegisterViewer
	err := s.checkAndParse(&payload, requestId, msg)
	if err != nil {
		return fmt.Errorf("error parsing message: %v", err)
	}

	info, err := spawnerHelpers.RequestWorkerStartup(s.SpawnerAddress, s.User.Username)
	if err != nil {
		return fmt.Errorf("error starting worker: %v", err)
	}
	s.Info = info

	slog.Info("Worker started for session", "workerId", info.WorkerId, "sessionId", payload.SessionId, "address", info.Address, "port", info.Port)
	addr := fmt.Sprintf("ws://%s:%d", info.Address, info.Port)
	wctx := s.Context
	if wctx == nil {
		wctx = context.Background()
	}
	workerConn, _, err := websocket.DefaultDialer.DialContext(wctx, addr, nil)

	if err != nil {
		return fmt.Errorf("could not connect to worker at %s: %w", addr, err)
	}

	s.sharedWorker = &SessionWorker{
		conn:           workerConn,
		clientSendChan: s.clientSendChan,
		fileRequest:    nil,
	}
	s.sharedWorker.handleInit()
	return s.sharedWorker.proxyMessageToWorker(&payload, cartaDefinitions.EventType_REGISTER_VIEWER, requestId)
}
