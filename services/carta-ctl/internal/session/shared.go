package session

import (
	"fmt"
	"log/slog"

	"github.com/gorilla/websocket"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

// outbound is one frame queued for a connection's send handler.
type outbound struct {
	messageType int
	data        []byte
}

// sendHandler is a connection's only writer. It stops at the first write
// error, since the connection is unusable from then on.
func sendHandler(channel <-chan outbound, done <-chan struct{}, conn *websocket.Conn, name string) {
	slog.Debug("Starting send handler", "name", name)
	defer slog.Debug("Send handler exiting", "name", name)
	for {
		select {
		case out := <-channel:
			if err := conn.WriteMessage(out.messageType, out.data); err != nil {
				slog.Error("Error sending message", "name", name, "error", err)
				return
			}
		case <-done:
			return
		}
	}
}

// handleProxiedMessage forwards a message with no dedicated handler to the
// worker serving its file, or to the shared worker.
func (s *Session) handleProxiedMessage(eventType cartaDefinitions.EventType, requestId uint32, bytes []byte) error {
	if s.multiBackend {
		if fileId, ok := cartaHelpers.ExtractFileIdFromBytes(eventType, bytes); ok {
			return s.sendToWorker(s.workerForFile(fileId), eventType, requestId, bytes)
		}
	}
	return s.proxyToShared(eventType, requestId, bytes)
}

func (s *Session) proxyToShared(eventType cartaDefinitions.EventType, requestId uint32, bytes []byte) error {
	return s.sendToWorker(s.getSharedWorker(), eventType, requestId, bytes)
}

func (s *Session) sendToWorker(worker *SessionWorker, eventType cartaDefinitions.EventType, requestId uint32, bytes []byte) error {
	if worker == nil {
		return fmt.Errorf("no worker available to handle %v", eventType)
	}
	bytes = relabelForBackend(worker, eventType, bytes)
	slog.Debug("Proxying message from client to worker", "eventType", eventType, "workerName", worker.name)
	return worker.enqueue(cartaHelpers.PrepareBinaryMessage(bytes, eventType, requestId))
}

// relabelForBackend rewrites a client message about an image the backend
// opened on its own so it names the id that backend knows.
func relabelForBackend(worker *SessionWorker, eventType cartaDefinitions.EventType, bytes []byte) []byte {
	fileId, ok := cartaHelpers.FileIdFromBytes(eventType, bytes)
	if !ok {
		return bytes
	}
	backendFileId, ok := worker.backendFileId(fileId)
	if !ok {
		return bytes
	}
	payload, err := cartaHelpers.RewriteFileId(eventType, bytes, backendFileId)
	if err != nil {
		slog.Error("Failed to relabel a client message", "eventType", eventType, "workerName", worker.name, "error", err)
		return bytes
	}
	return payload
}

func (s *Session) handleStatusMessage(_ cartaDefinitions.EventType, _ uint32, _ []byte) error {
	shared := s.getSharedWorker()
	if shared == nil {
		return fmt.Errorf("status request received before worker registration")
	}
	shared.mu.Lock()
	workerId := shared.workerId
	shared.mu.Unlock()
	if workerId == "" {
		return fmt.Errorf("status request received while the backend is still starting")
	}
	go func() {
		status, err := spawnerHelpers.GetWorkerStatus(workerId, s.SpawnerAddress)
		if err != nil {
			slog.Error("Error getting worker status", "error", err)
			return
		}
		slog.Info("Worker status", "alive", status.Alive, "reachable", status.IsReachable)
	}()
	return nil
}
