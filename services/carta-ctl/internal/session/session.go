package session

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

type contextKey string

const UserContextKey contextKey = "sessionUser"

type Session struct {
	Info           spawnerHelpers.WorkerInfo
	SpawnerAddress string
	WebSocket      *websocket.Conn
	User           *auth.User
	Context        context.Context
	Cancel         context.CancelFunc

	clientSendChan chan []byte
	// clientDone is closed once (via clientDoneOnce) on disconnect. Senders to
	// clientSendChan select on it so they never race the channel's teardown;
	// clientSendChan is never closed.
	clientDone     chan struct{}
	clientDoneOnce sync.Once
	// maps incoming file IDs to the internal IDs of the workers. Guarded by
	// fileMapMu: it is written by handleOpenFile and CLOSE_FILE/disconnect
	// teardown while being read concurrently by message routing, all from
	// separate per-message goroutines.
	fileMapMu    sync.Mutex
	fileMap      map[int32]*SessionWorker
	sharedWorker *SessionWorker

	// serverFeatures to add to an incoming REGISTER_VIEWER_ACK before it reaches the client.
	serverFeatures uint32
}

var handlerMap = map[cartaDefinitions.EventType]func(*Session, cartaDefinitions.EventType, uint32, []byte) error{
	cartaDefinitions.EventType_REGISTER_VIEWER:    (*Session).handleRegisterViewerMessage,
	cartaDefinitions.EventType_OPEN_FILE:          (*Session).handleOpenFile,
	cartaDefinitions.EventType_CLOSE_FILE:         (*Session).handleCloseFile,
	cartaDefinitions.EventType_EMPTY_EVENT:        (*Session).handleStatusMessage,
	cartaDefinitions.EventType_BULK_SET_REGION:    (*Session).handleBulkSetRegion,
	cartaDefinitions.EventType_BULK_REMOVE_REGION: (*Session).handleBulkRemoveRegion,
}

func NewSession(conn *websocket.Conn, workerAddr string, user *auth.User, serverFeatures uint32) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		WebSocket:      conn,
		SpawnerAddress: workerAddr,
		User:           user,
		Context:        ctx,
		Cancel:         cancel,
		serverFeatures: serverFeatures,
	}
}

// setFileWorker registers the worker serving fileId, lazily creating the map.
// All writes to fileMap go through here so they share fileMapMu.
func (s *Session) setFileWorker(fileId int32, w *SessionWorker) {
	s.fileMapMu.Lock()
	defer s.fileMapMu.Unlock()
	if s.fileMap == nil {
		s.fileMap = make(map[int32]*SessionWorker)
	}
	s.fileMap[fileId] = w
}

// getFileWorker returns the worker serving fileId, if any. All reads of fileMap
// go through here so they share fileMapMu.
func (s *Session) getFileWorker(fileId int32) (*SessionWorker, bool) {
	s.fileMapMu.Lock()
	defer s.fileMapMu.Unlock()
	w, ok := s.fileMap[fileId]
	return w, ok
}

// fileWorkerIds snapshots the currently open file ids under the lock so teardown
// can iterate without holding fileMapMu across per-worker shutdown I/O.
func (s *Session) fileWorkerIds() []int32 {
	s.fileMapMu.Lock()
	defer s.fileMapMu.Unlock()
	ids := make([]int32, 0, len(s.fileMap))
	for id := range s.fileMap {
		ids = append(ids, id)
	}
	return ids
}

func (s *Session) checkAndParse(msg proto.Message, requestId uint32, rawMsg []byte) error {
	// Register viewer messages are allowed without a worker connection
	if s.sharedWorker == nil {
		switch msg.(type) {
		case *cartaDefinitions.RegisterViewer:
			break
		default:
			return fmt.Errorf("missing worker connection")
		}
	}

	if requestId == 0 {
		return fmt.Errorf("invalid or missing request id")
	}

	err := proto.Unmarshal(rawMsg, msg)

	if err != nil {
		return err
	}

	return nil
}

func (s *Session) HandleConnection() {
	s.clientSendChan = make(chan []byte, 100)
	s.clientDone = make(chan struct{})
	go sendHandler(s.clientSendChan, s.clientDone, s.WebSocket, "client")
}

// sendToClient forwards a framed message to the client, dropping it if the
// session is being torn down. Selecting on clientDone means the send can never
// panic on a closed clientSendChan (it is never closed). A nil clientDone (in
// unit tests that set clientSendChan directly) is never ready, so the send
// proceeds as a plain buffered send.
func (s *Session) sendToClient(msg []byte) {
	select {
	case s.clientSendChan <- msg:
	case <-s.clientDone:
	}
}

func (s *Session) HandleMessage(msg []byte) error {
	// Message prefix is used for determining message type and matching requests to responses
	prefix, err := cartaHelpers.DecodeMessagePrefix(msg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal message: %v", err)
	}

	handler, ok := handlerMap[prefix.EventType]
	if !ok {
		// Any messages that don't have a specific handler are simply proxied to the worker
		err = s.handleProxiedMessage(prefix.EventType, prefix.RequestId, msg[8:])
	} else {
		err = handler(s, prefix.EventType, prefix.RequestId, msg[8:])
	}

	if err != nil {
		return fmt.Errorf("error handling message: %v", err)
	}
	return nil
}

func (s *Session) HandleDisconnect() {
	// Signal the client sender goroutine (and any in-flight senders) to stop.
	s.clientDoneOnce.Do(func() {
		if s.clientDone != nil {
			close(s.clientDone)
		}
	})

	// Reap every per-file backend so a client that disconnects without sending
	// CLOSE_FILE doesn't leak backend processes.
	s.shutdownAllFileWorkers()

	// Close the shared worker channel to signal its sender goroutine to stop.
	if s.sharedWorker != nil {
		s.sharedWorker.disconnect()
	}

	if s.Info.WorkerId != "" {
		if err := spawnerHelpers.RequestWorkerShutdown(s.Info.WorkerId, s.SpawnerAddress); err != nil {
			slog.Error("Error shutting down shared worker", "error", err)
		}
		slog.Info("Shut down shared worker", "workerId", s.Info.WorkerId)
	}
}
