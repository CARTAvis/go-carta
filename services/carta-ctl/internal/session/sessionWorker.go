package session

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	helpers "github.com/CARTAvis/go-carta/pkg/shared"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/spawnerHelpers"
)

// sendTimeout bounds how long a message waits for a backend that is not
// reading its socket, so one backend cannot stall the whole session.
const sendTimeout = 5 * time.Second

// SessionWorker proxies one backend process. fileRequest is nil for the
// session's shared worker. A worker is registered with its session before the
// backend is started, so a close that arrives while it is starting is honoured.
type SessionWorker struct {
	owner       *Session
	fileRequest *cartaDefinitions.OpenFile
	requestId   uint32
	name        string
	sendChan    chan outbound

	// done is closed by shutdown. sendChan is never closed, so senders select
	// on done instead.
	done         chan struct{}
	shutdownOnce sync.Once

	// derivedMu guards the translation between the ids the client uses for
	// images this backend opened on its own and the ids the backend gave them.
	derivedMu       sync.Mutex
	derivedToBacked map[int32]int32
	derivedToClient map[int32]int32

	// pending maps controller-originated request ids to their waiting channel.
	reqMu      sync.Mutex
	pending    map[uint32]chan WorkerMessage
	reqCounter atomic.Uint32

	// mu guards workerId and conn, which start is still filling in when a
	// concurrent shutdown may read them.
	mu       sync.Mutex
	workerId string
	conn     *websocket.Conn
}

func newSessionWorker(owner *Session, fileRequest *cartaDefinitions.OpenFile, requestId uint32) *SessionWorker {
	sw := &SessionWorker{
		owner:       owner,
		fileRequest: fileRequest,
		requestId:   requestId,
		name:        "shared-worker",
		sendChan:    make(chan outbound, 100),
		done:        make(chan struct{}),
		pending:     make(map[uint32]chan WorkerMessage),
	}
	if fileRequest != nil {
		sw.name = fmt.Sprintf("worker:%d", fileRequest.FileId)
	}
	return sw
}

// start asks the spawner for a backend, connects to it and starts the proxy
// goroutines. A backend obtained after the worker was shut down is released
// again.
func (sw *SessionWorker) start() error {
	if sw.isDone() {
		return fmt.Errorf("worker %s was closed before starting", sw.name)
	}
	info, err := spawnerHelpers.RequestWorkerStartup(sw.owner.SpawnerAddress, sw.owner.User.Username)
	if err != nil {
		sw.shutdown()
		return fmt.Errorf("error starting worker: %w", err)
	}
	if !sw.claim(info.WorkerId) {
		releaseBackend(sw.name, info.WorkerId, sw.owner.SpawnerAddress)
		return fmt.Errorf("worker %s was closed while starting", sw.name)
	}
	slog.Info("Worker started", "workerName", sw.name, "workerId", info.WorkerId, "address", info.Address, "port", info.Port)

	addr := fmt.Sprintf("ws://%s:%d", info.Address, info.Port)
	conn, _, err := websocket.DefaultDialer.DialContext(sw.owner.Context, addr, nil)
	if err != nil {
		sw.shutdown()
		return fmt.Errorf("could not connect to worker at %s: %w", addr, err)
	}
	if !sw.attach(conn) {
		helpers.CloseOrLog(conn)
		return fmt.Errorf("worker %s was closed while starting", sw.name)
	}
	go func() {
		sendHandler(sw.sendChan, sw.done, conn, sw.name)
		sw.shutdown()
	}()
	go sw.readLoop(conn)
	return nil
}

func (sw *SessionWorker) claim(workerId string) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.isDone() {
		return false
	}
	sw.workerId = workerId
	return true
}

func (sw *SessionWorker) attach(conn *websocket.Conn) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.isDone() {
		return false
	}
	sw.conn = conn
	return true
}

// startAsync starts the backend in the background so the session keeps
// handling client messages while the spawner works. A failure is reported to
// the client through failure, unless the worker was closed meanwhile, in which
// case the client already knows the file is gone.
func (sw *SessionWorker) startAsync(failure func(error)) {
	go func() {
		if err := sw.start(); err != nil {
			if fileIds, wasShared := sw.owner.removeWorker(sw); len(fileIds) == 0 && !wasShared {
				return
			}
			slog.Error("Failed to start backend", "workerName", sw.name, "error", err)
			failure(err)
		}
	}()
}

// shutdown stops the proxy goroutines, closes the backend connection and asks
// the spawner to stop the backend process. Repeated calls are no-ops.
func (sw *SessionWorker) shutdown() {
	sw.shutdownOnce.Do(func() {
		close(sw.done)
		sw.mu.Lock()
		conn, workerId := sw.conn, sw.workerId
		sw.mu.Unlock()
		if conn != nil {
			helpers.CloseOrLog(conn)
		}
		if workerId != "" {
			go releaseBackend(sw.name, workerId, sw.owner.SpawnerAddress)
		}
	})
}

func releaseBackend(name, workerId, spawnerAddress string) {
	if err := spawnerHelpers.RequestWorkerShutdown(workerId, spawnerAddress); err != nil {
		slog.Error("Failed to shut down backend", "workerName", name, "workerId", workerId, "error", err)
		return
	}
	slog.Info("Shut down backend", "workerName", name, "workerId", workerId)
}

// mapDerivedFile records that fileId, as the client knows it, is backendFileId
// to this backend.
func (sw *SessionWorker) mapDerivedFile(fileId, backendFileId int32) {
	sw.derivedMu.Lock()
	defer sw.derivedMu.Unlock()
	if sw.derivedToBacked == nil {
		sw.derivedToBacked = make(map[int32]int32)
		sw.derivedToClient = make(map[int32]int32)
	}
	sw.derivedToBacked[fileId] = backendFileId
	sw.derivedToClient[backendFileId] = fileId
}

// backendFileId translates an id the client used into the id this backend
// knows the image by.
func (sw *SessionWorker) backendFileId(fileId int32) (int32, bool) {
	sw.derivedMu.Lock()
	defer sw.derivedMu.Unlock()
	backendFileId, ok := sw.derivedToBacked[fileId]
	return backendFileId, ok
}

// clientFileId translates an id this backend used into the id the client
// knows the image by.
func (sw *SessionWorker) clientFileId(backendFileId int32) (int32, bool) {
	sw.derivedMu.Lock()
	defer sw.derivedMu.Unlock()
	fileId, ok := sw.derivedToClient[backendFileId]
	return fileId, ok
}

// forgetDerivedFile drops the translation for an image the client has closed.
func (sw *SessionWorker) forgetDerivedFile(fileId int32) {
	sw.derivedMu.Lock()
	defer sw.derivedMu.Unlock()
	if backendFileId, ok := sw.derivedToBacked[fileId]; ok {
		delete(sw.derivedToBacked, fileId)
		delete(sw.derivedToClient, backendFileId)
	}
}

func (sw *SessionWorker) isDone() bool {
	select {
	case <-sw.done:
		return true
	default:
		return false
	}
}

func (sw *SessionWorker) proxyMessageToWorker(msg proto.Message, eventType cartaDefinitions.EventType, requestId uint32) error {
	byteData, err := cartaHelpers.PrepareMessagePayload(msg, eventType, requestId)
	if err != nil {
		return err
	}
	slog.Debug("Proxying message from session to worker", "eventType", eventType, "workerName", sw.name)
	return sw.enqueue(byteData)
}

// enqueue hands a framed binary message to the send handler. It fails once
// the worker is shutting down.
func (sw *SessionWorker) enqueue(byteData []byte) error {
	return sw.send(outbound{messageType: websocket.BinaryMessage, data: byteData})
}

func (sw *SessionWorker) send(out outbound) error {
	if sw.isDone() {
		return fmt.Errorf("worker %s is shutting down", sw.name)
	}
	select {
	case sw.sendChan <- out:
		return nil
	case <-sw.done:
		return fmt.Errorf("worker %s is shutting down", sw.name)
	case <-time.After(sendTimeout):
		return fmt.Errorf("worker %s is not reading its messages", sw.name)
	}
}

func (sw *SessionWorker) readLoop(conn *websocket.Conn) {
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if sw.isDone() {
				slog.Debug("Worker connection closed", "workerName", sw.name)
			} else {
				slog.Error("Error reading message from worker", "workerName", sw.name, "error", err)
			}
			break
		}

		// Ping/pong sequence
		if messageType == websocket.TextMessage && string(message) == "PING" {
			slog.Debug("Received PING from worker, sending PONG")
			if err := sw.send(outbound{messageType: websocket.TextMessage, data: []byte("PONG")}); err != nil {
				slog.Error("Failed to send pong message", "error", err)
			}
			continue
		}

		// Ignore all other non-binary messages
		if messageType != websocket.BinaryMessage {
			slog.Warn("Ignoring non-binary message", "messageType", messageType, "message", string(message))
			continue
		}

		// Handled inline so frames reach the client in the order the backend
		// sent them and a slow client applies back-pressure to the backend.
		sw.handleMessage(message)
	}
	sw.owner.workerLost(sw)
	sw.failAllPending()
}

func (sw *SessionWorker) handleMessage(message []byte) {
	prefix, err := cartaHelpers.DecodeMessagePrefix(message)
	if err != nil {
		slog.Error("failed to unmarshal message", "error", err)
		return
	}
	slog.Debug("Received message from worker", "eventType", prefix.EventType, "workerName", sw.name)

	if sw.deliverToPending(prefix.RequestId, prefix.EventType, message[8:]) {
		return
	}
	if prefix.RequestId&controllerRequestIDBit != 0 {
		slog.Warn("Dropping late response to a controller request", "eventType", prefix.EventType, "requestId", prefix.RequestId, "workerName", sw.name)
		return
	}

	if rewritten := sw.adoptDerivedFiles(prefix.EventType, message[8:], prefix.RequestId); rewritten != nil {
		sw.owner.sendToClient(rewritten)
		return
	}
	message = sw.relabelForClient(prefix, message)

	// Send the open file request once the backend has registered the viewer
	if sw.fileRequest != nil && prefix.EventType == cartaDefinitions.EventType_REGISTER_VIEWER_ACK {
		sw.openFileAfterRegistration(message[8:])
		return
	}

	if sw.fileRequest == nil && prefix.EventType == cartaDefinitions.EventType_REGISTER_VIEWER_ACK {
		sw.owner.forwardRegisterViewerAck(prefix.RequestId, message[8:])
		return
	}

	sw.owner.sendToClient(message)
}

// relabelForClient rewrites a backend message about an image the backend
// opened on its own so it names the id the client knows.
func (sw *SessionWorker) relabelForClient(prefix cartaHelpers.MessagePrefix, message []byte) []byte {
	backendFileId, ok := cartaHelpers.FileIdFromBytes(prefix.EventType, message[8:])
	if !ok {
		return message
	}
	fileId, ok := sw.clientFileId(backendFileId)
	if !ok {
		return message
	}
	payload, err := cartaHelpers.RewriteFileId(prefix.EventType, message[8:], fileId)
	if err != nil {
		slog.Error("Failed to relabel a backend message", "eventType", prefix.EventType, "workerName", sw.name, "error", err)
		return message
	}
	return cartaHelpers.PrepareBinaryMessage(payload, prefix.EventType, prefix.RequestId)
}

// openFileAfterRegistration forwards the open request once the backend has
// registered the viewer, or tells the client the file could not be opened if
// the backend refused to register.
func (sw *SessionWorker) openFileAfterRegistration(payload []byte) {
	var ack cartaDefinitions.RegisterViewerAck
	if err := proto.Unmarshal(payload, &ack); err != nil || !ack.GetSuccess() {
		message := ack.GetMessage()
		if err != nil {
			message = "backend sent a malformed registration response"
		}
		slog.Error("Backend refused to register", "workerName", sw.name, "message", message)
		sw.owner.dropWorker(sw)
		sw.owner.sendAckToClient(&cartaDefinitions.OpenFileAck{Success: false, FileId: sw.fileRequest.GetFileId(), Message: message},
			cartaDefinitions.EventType_OPEN_FILE_ACK, sw.requestId)
		return
	}
	if err := sw.proxyMessageToWorker(sw.fileRequest, cartaDefinitions.EventType_OPEN_FILE, sw.requestId); err != nil {
		slog.Error("Error proxying open file message to worker", "workerName", sw.name, "error", err)
	}
}
