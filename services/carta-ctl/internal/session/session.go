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
)

type contextKey string

const UserContextKey contextKey = "sessionUser"

type Session struct {
	SpawnerAddress string
	WebSocket      *websocket.Conn
	User           *auth.User
	// Context is cancelled when the session ends.
	Context context.Context
	Cancel  context.CancelFunc

	clientSendChan chan outbound

	// mu guards sharedWorker and fileMap, which are written by registration
	// and teardown while routing reads them from other goroutines. fileMap
	// also holds images a backend derived from its own file, pointing at that
	// backend's worker.
	mu           sync.Mutex
	sharedWorker *SessionWorker
	fileMap      map[int32]*SessionWorker
	// pvPreviewToFile maps a PV preview id to the file whose backend serves it.
	pvPreviewMu     sync.Mutex
	pvPreviewToFile map[int32]int32

	// registerViewer is the client's registration, replayed to each per-file
	// backend so they see the same session id and client feature flags.
	registerViewer *cartaDefinitions.RegisterViewer

	// multiBackend serves each open file from its own backend process.
	multiBackend bool
}

type messageHandler func(*Session, cartaDefinitions.EventType, uint32, []byte) error

var handlerMap = map[cartaDefinitions.EventType]messageHandler{
	cartaDefinitions.EventType_REGISTER_VIEWER:    (*Session).handleRegisterViewerMessage,
	cartaDefinitions.EventType_EMPTY_EVENT:        (*Session).handleStatusMessage,
	cartaDefinitions.EventType_BULK_SET_REGION:    (*Session).handleBulkSetRegion,
	cartaDefinitions.EventType_BULK_REMOVE_REGION: (*Session).handleBulkRemoveRegion,
}

// multiBackendHandlerMap holds handlers that only apply when each file has its own backend.
var multiBackendHandlerMap = map[cartaDefinitions.EventType]messageHandler{
	cartaDefinitions.EventType_OPEN_FILE:        (*Session).handleOpenFile,
	cartaDefinitions.EventType_CLOSE_FILE:       (*Session).handleCloseFile,
	cartaDefinitions.EventType_PV_REQUEST:       (*Session).handlePvRequest,
	cartaDefinitions.EventType_STOP_PV_PREVIEW:  (*Session).handleStopPvPreview,
	cartaDefinitions.EventType_CLOSE_PV_PREVIEW: (*Session).handleClosePvPreview,
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

// closed reports whether the session has ended.
func (s *Session) closed() bool {
	return s.Context.Err() != nil
}

// setSharedWorker publishes w as the shared worker and returns the worker it
// replaced. It returns ok=false if the session has ended, in which case the
// caller still owns w.
func (s *Session) setSharedWorker(w *SessionWorker) (displaced *SessionWorker, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed() {
		return nil, false
	}
	displaced, s.sharedWorker = s.sharedWorker, w
	return displaced, true
}

func (s *Session) setRegisterViewer(msg *cartaDefinitions.RegisterViewer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registerViewer = msg
}

// clientRegistration returns the registration to send a per-file backend.
func (s *Session) clientRegistration() *cartaDefinitions.RegisterViewer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registerViewer == nil {
		return &cartaDefinitions.RegisterViewer{}
	}
	return s.registerViewer
}

func (s *Session) getSharedWorker() *SessionWorker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sharedWorker
}

func (s *Session) takeSharedWorker() *SessionWorker {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.sharedWorker
	s.sharedWorker = nil
	return w
}

// setFileWorker registers w as the worker for fileId and returns the worker it
// replaced. It returns ok=false if the session has ended, in which case the
// caller still owns w.
func (s *Session) setFileWorker(fileId int32, w *SessionWorker) (displaced *SessionWorker, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed() {
		return nil, false
	}
	if s.fileMap == nil {
		s.fileMap = make(map[int32]*SessionWorker)
	}
	displaced = s.fileMap[fileId]
	s.fileMap[fileId] = w
	return displaced, true
}

func (s *Session) getFileWorker(fileId int32) (*SessionWorker, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.fileMap[fileId]
	return w, ok
}

// workerForFile returns the worker serving fileId, or the shared worker for
// files the session has no dedicated backend for.
func (s *Session) workerForFile(fileId int32) *SessionWorker {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.fileMap[fileId]; ok {
		return w
	}
	return s.sharedWorker
}

// takeFileWorker unregisters and returns the worker for fileId, if any.
func (s *Session) takeFileWorker(fileId int32) *SessionWorker {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.fileMap[fileId]
	delete(s.fileMap, fileId)
	return w
}

// removeWorker unregisters w wherever it is still registered. It returns the
// file ids that were routed to w and whether w was the shared worker.
func (s *Session) removeWorker(w *SessionWorker) (fileIds []int32, wasShared bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fileId, entry := range s.fileMap {
		if entry == w {
			delete(s.fileMap, fileId)
			fileIds = append(fileIds, fileId)
		}
	}
	if s.sharedWorker == w {
		s.sharedWorker = nil
		wasShared = true
	}
	return fileIds, wasShared
}

// addFileAlias routes fileId, an image w's backend opened on its own, to w. It
// returns false if the id could not be taken, either because another backend
// already serves it or because the session has ended.
func (s *Session) addFileAlias(fileId int32, w *SessionWorker) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed() {
		return false
	}
	if existing, ok := s.fileMap[fileId]; ok && existing != w {
		return false
	}
	if s.fileMap == nil {
		s.fileMap = make(map[int32]*SessionWorker)
	}
	s.fileMap[fileId] = w
	return true
}

// takeFileWorkers unregisters every file id and returns the ids and the
// distinct workers that served them.
func (s *Session) takeFileWorkers() ([]int32, []*SessionWorker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fileIds := make([]int32, 0, len(s.fileMap))
	workers := make([]*SessionWorker, 0, len(s.fileMap))
	seen := make(map[*SessionWorker]bool, len(s.fileMap))
	for fileId, w := range s.fileMap {
		fileIds = append(fileIds, fileId)
		if !seen[w] {
			seen[w] = true
			workers = append(workers, w)
		}
	}
	s.fileMap = nil
	return fileIds, workers
}

// parse decodes a client message. Only a register-viewer message is accepted
// before the session has a backend to talk to.
func (s *Session) parse(msg proto.Message, rawMsg []byte) error {
	if s.getSharedWorker() == nil {
		if _, ok := msg.(*cartaDefinitions.RegisterViewer); !ok {
			return fmt.Errorf("missing worker connection")
		}
	}
	return proto.Unmarshal(rawMsg, msg)
}

// checkAndParse decodes a client message that expects a response, so it must
// carry a request id to correlate that response with.
func (s *Session) checkAndParse(msg proto.Message, requestId uint32, rawMsg []byte) error {
	if requestId == 0 {
		return fmt.Errorf("invalid or missing request id")
	}
	return s.parse(msg, rawMsg)
}

func (s *Session) HandleConnection() {
	s.clientSendChan = make(chan outbound, 100)
	go func() {
		sendHandler(s.clientSendChan, s.Context.Done(), s.WebSocket, "client")
		s.Cancel()
	}()
}

// sendToClient queues a binary frame for the client, dropping it once the
// session has ended.
func (s *Session) sendToClient(msg []byte) {
	s.send(outbound{messageType: websocket.BinaryMessage, data: msg})
}

// SendText queues a text frame for the client. All writes to the client go
// through the send handler, which is the connection's only writer.
func (s *Session) SendText(text string) {
	s.send(outbound{messageType: websocket.TextMessage, data: []byte(text)})
}

func (s *Session) send(out outbound) {
	select {
	case s.clientSendChan <- out:
	case <-s.Context.Done():
	}
}

// sendAckToClient marshals a response for the client, for acks the controller
// produces itself when a backend could not.
func (s *Session) sendAckToClient(msg proto.Message, eventType cartaDefinitions.EventType, requestId uint32) {
	out, err := cartaHelpers.PrepareMessagePayload(msg, eventType, requestId)
	if err != nil {
		slog.Error("Failed to marshal ack", "eventType", eventType, "error", err)
		return
	}
	s.sendToClient(out)
}

// sendErrorToClient reports a controller-side failure to the client.
func (s *Session) sendErrorToClient(message string) {
	s.sendAckToClient(&cartaDefinitions.ErrorData{
		Severity: cartaDefinitions.ErrorSeverity_ERROR,
		Tags:     []string{"backend"},
		Message:  message,
	}, cartaDefinitions.EventType_ERROR_DATA, 0)
}

func (s *Session) HandleMessage(msg []byte) error {
	// Message prefix is used for determining message type and matching requests to responses
	prefix, err := cartaHelpers.DecodeMessagePrefix(msg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal message: %v", err)
	}
	if prefix.RequestId&controllerRequestIDBit != 0 {
		return fmt.Errorf("request id %d is reserved for the controller", prefix.RequestId)
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

// endSession stops the session from the controller's side, for instance when
// the shared backend is lost. Closing the client connection makes the
// connection handler run HandleDisconnect.
func (s *Session) endSession() {
	s.Cancel()
	if s.WebSocket != nil {
		_ = s.WebSocket.Close()
	}
}

// HandleDisconnect stops the client sender and shuts down every backend the
// session started. Workers still starting see the ended session when they
// try to register and shut themselves down.
func (s *Session) HandleDisconnect() {
	s.Cancel()
	_, workers := s.takeFileWorkers()
	for _, w := range workers {
		w.shutdown()
	}
	if w := s.takeSharedWorker(); w != nil {
		w.shutdown()
	}
}
