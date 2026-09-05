package session

import (
	"fmt"
	"log/slog"

	"github.com/gorilla/websocket"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

func sendHandler(channel <-chan []byte, conn *websocket.Conn, name string) {
	slog.Debug("Starting send handler", "name", name, "channel", fmt.Sprintf("%p", channel))
	for byteData := range channel {
		err := conn.WriteMessage(websocket.BinaryMessage, byteData)
		if err != nil {
			slog.Error("Error sending message", "name", name, "channel", fmt.Sprintf("%p", channel), "error", err)
			// Continue processing other messages even if one fails
		}
	}
	slog.Debug("Send handler exiting", "name", name)
}

// handleProxiedMessage forwards a message with no dedicated handler to the
// worker serving its file, or to the shared worker.
func (s *Session) handleProxiedMessage(eventType cartaDefinitions.EventType, requestId uint32, bytes []byte) error {
	messageBytes := cartaHelpers.PrepareBinaryMessage(bytes, eventType, requestId)

	targetWorker := s.sharedWorker
	workerName := "shared-worker"
	if s.multiBackend {
		if fileId, ok := cartaHelpers.ExtractFileIdFromBytes(eventType, bytes); ok {
			if worker, exists := s.fileMap[fileId]; exists {
				targetWorker = worker
				workerName = fmt.Sprintf("worker:%d", fileId)
			} else {
				workerName = fmt.Sprintf("shared-worker (fileId:%d not mapped)", fileId)
			}
		}
	}

	slog.Debug("Proxying message from client to worker", "eventType", eventType, "workerName", workerName)

	if targetWorker == nil {
		return fmt.Errorf("no worker available to handle message")
	}

	targetWorker.sendChan <- messageBytes
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
