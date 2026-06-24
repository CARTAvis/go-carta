package session

import (
	"fmt"
	"log/slog"

	"github.com/gorilla/websocket"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

// OpenFile needs to spin up a new worker and proxy the message to it
func (s *Session) handleOpenFile(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.OpenFile
	err := s.checkAndParse(&payload, requestId, msg)
	if err != nil {
		return fmt.Errorf("error parsing message: %v", err)
	}

	info, err := spawnerHelpers.RequestWorkerStartup(s.SpawnerAddress, s.User.Username)
	if err != nil {
		return fmt.Errorf("error starting worker: %v", err)
	}

	slog.Info("Worker started", "workerId", info.WorkerId, "fileId", payload.FileId, "address", info.Address, "port", info.Port)
	addr := fmt.Sprintf("ws://%s:%d", info.Address, info.Port)
	workerConn, _, err := websocket.DefaultDialer.DialContext(s.Context, addr, nil)
	if err != nil {
		return fmt.Errorf("could not connect to worker at %s: %w", addr, err)
	}

	fileWorker := &SessionWorker{
		requestId:   requestId,
		fileRequest: &payload,
		conn:        workerConn,
		workerId:    info.WorkerId,
		owner:       s,
	}
	fileWorker.handleInit()

	s.setFileWorker(payload.FileId, fileWorker)

	// We  need to first pass through a register viewer message, and then wait for the ack before sending through the open file message
	// File opening is handled by workerMessageHandler
	return fileWorker.proxyMessageToWorker(&payload, cartaDefinitions.EventType_REGISTER_VIEWER, requestId)
}
