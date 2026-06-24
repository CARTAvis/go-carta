package session

import (
	"fmt"
	"log/slog"

	"github.com/gorilla/websocket"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

func sendHandler(channel <-chan []byte, done <-chan struct{}, conn *websocket.Conn, name string) {
	slog.Debug("Starting send handler", "name", name, "channel", fmt.Sprintf("%p", channel))
	for {
		select {
		case byteData := <-channel:
			if err := conn.WriteMessage(websocket.BinaryMessage, byteData); err != nil {
				slog.Error("Error sending message", "name", name, "channel", fmt.Sprintf("%p", channel), "error", err)
				// Continue processing other messages even if one fails
			}
		case <-done:
			slog.Debug("Send handler exiting", "name", name)
			return
		}
	}
}

// handleProxiedMessage proxies unhandled messages to the appropriate worker.
// It extracts the fileId from the message (if present) and routes to the corresponding worker.
func (s *Session) handleProxiedMessage(eventType cartaDefinitions.EventType, requestId uint32, bytes []byte) error {
	messageBytes := cartaHelpers.PrepareBinaryMessage(bytes, eventType, requestId)

	// Try to extract fileId from the message
	fileId, hasFileId := cartaHelpers.ExtractFileIdFromBytes(eventType, bytes)

	// Determine which worker to send the message to
	var targetWorker *SessionWorker
	var workerName string

	if hasFileId {
		// Check if we have a worker for this fileId
		if worker, exists := s.getFileWorker(fileId); exists {
			targetWorker = worker
			workerName = fmt.Sprintf("worker:%d", fileId)
		} else {
			// FileId found but no worker mapped, use shared worker
			targetWorker = s.sharedWorker
			workerName = fmt.Sprintf("shared-worker (fileId:%d not mapped)", fileId)
		}
	} else {
		// No fileId in message or fileMap not initialized, use shared worker
		targetWorker = s.sharedWorker
		workerName = "shared-worker"
	}

	slog.Debug("Proxying message from client to worker", "eventType", eventType, "workerName", workerName)

	if targetWorker == nil {
		return fmt.Errorf("no worker available to handle message")
	}

	if !targetWorker.enqueue(messageBytes) {
		return fmt.Errorf("worker %s is shutting down", workerName)
	}
	return nil
}

func (s *Session) handleStatusMessage(_ cartaDefinitions.EventType, _ uint32, _ []byte) error {
	if s.Info.WorkerId == "" {
		return fmt.Errorf("status request received before worker registration")
	}
	status, err := spawnerHelpers.GetWorkerStatus(s.Info.WorkerId, s.SpawnerAddress)
	if err != nil {
		return fmt.Errorf("error getting worker status: %v", err)
	} else {
		slog.Info("Worker status", "alive", status.Alive, "reachable", status.IsReachable)
	}
	return nil
}
