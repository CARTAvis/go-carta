package session

import (
	"context"
	"fmt"
	"log/slog"

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
	// maps incoming file IDs to the internal IDs of the workers
	fileMap      map[int32]*SessionWorker
	sharedWorker *SessionWorker

	// multiBackend serves each open file from its own backend process.
	multiBackend bool
}

type messageHandler func(*Session, cartaDefinitions.EventType, uint32, []byte) error

var handlerMap = map[cartaDefinitions.EventType]messageHandler{
	cartaDefinitions.EventType_REGISTER_VIEWER: (*Session).handleRegisterViewerMessage,
	cartaDefinitions.EventType_EMPTY_EVENT:     (*Session).handleStatusMessage,
}

// multiBackendHandlerMap holds handlers that only apply when each file has its own backend.
var multiBackendHandlerMap = map[cartaDefinitions.EventType]messageHandler{
	cartaDefinitions.EventType_OPEN_FILE: (*Session).handleOpenFile,
	// TODO: We need to handle CLOSE_FILE separately as well, because it will require shutting down a worker
}

func NewSession(conn *websocket.Conn, workerAddr string, user *auth.User, multiBackend bool) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		WebSocket:      conn,
		SpawnerAddress: workerAddr,
		User:           user,
		Context:        ctx,
		Cancel:         cancel,
		multiBackend:   multiBackend,
	}
}

func (s *Session) lookupHandler(eventType cartaDefinitions.EventType) (messageHandler, bool) {
	if handler, ok := handlerMap[eventType]; ok {
		return handler, true
	}
	if s.multiBackend {
		handler, ok := multiBackendHandlerMap[eventType]
		return handler, ok
	}
	return nil, false
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
	go sendHandler(s.clientSendChan, s.WebSocket, "client")
}

func (s *Session) HandleMessage(msg []byte) error {
	// Message prefix is used for determining message type and matching requests to responses
	prefix, err := cartaHelpers.DecodeMessagePrefix(msg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal message: %v", err)
	}

	handler, ok := s.lookupHandler(prefix.EventType)
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
	// Close the client channel to signal the sender goroutine to stop
	if s.clientSendChan != nil {
		close(s.clientSendChan)
	}

	if s.Info.WorkerId == "" {
		return
	}

	// Close the worker channel to signal the sender goroutine to stop
	if s.sharedWorker != nil {
		s.sharedWorker.disconnect()
	}

	err := spawnerHelpers.RequestWorkerShutdown(s.Info.WorkerId, s.SpawnerAddress)
	if err != nil {
		slog.Error("Error shutting down worker", "error", err)
	}
	slog.Info("Shut down worker", "workerId", s.Info.WorkerId)

}
