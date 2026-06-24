package session

import (
	"fmt"
	"log/slog"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

// handleCloseFile shuts down the backend serving a file. In single-tenant mode a
// CLOSE_FILE must reap that file's backend rather than be proxied to it. file_id
// == -1 closes every file worker (used when the frontend replaces all open
// files).
func (s *Session) handleCloseFile(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.CloseFile
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing close file: %v", err)
	}

	if payload.FileId == -1 {
		s.shutdownAllFileWorkers()
		return nil
	}
	s.shutdownFileWorker(payload.FileId)
	return nil
}

// shutdownAllFileWorkers reaps every open file worker. Used for CLOSE_FILE with
// file_id == -1 and on client disconnect.
func (s *Session) shutdownAllFileWorkers() {
	for _, fileId := range s.fileWorkerIds() {
		s.shutdownFileWorker(fileId)
	}
}

// shutdownFileWorker disconnects the worker for fileId and asks the spawner to
// stop the backend process. No-op if there is no worker for fileId. The worker
// is removed from fileMap under the lock; the disconnect + spawner shutdown I/O
// runs without holding fileMapMu.
func (s *Session) shutdownFileWorker(fileId int32) {
	s.fileMapMu.Lock()
	worker, ok := s.fileMap[fileId]
	if ok {
		delete(s.fileMap, fileId)
	}
	s.fileMapMu.Unlock()

	if !ok || worker == nil {
		return
	}

	s.deletePvPreviewsForFile(fileId)
	worker.disconnect() // closes done + the WS conn; read loop exits -> failAllPending
	if worker.workerId != "" {
		if err := spawnerHelpers.RequestWorkerShutdown(worker.workerId, s.SpawnerAddress); err != nil {
			slog.Error("Failed to shut down file backend", "fileId", fileId, "workerId", worker.workerId, "error", err)
		}
	}
	slog.Info("Closed file backend", "fileId", fileId, "workerId", worker.workerId)
}
