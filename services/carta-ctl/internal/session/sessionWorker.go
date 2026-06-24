package session

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	helpers "github.com/CARTAvis/go-carta/pkg/shared"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

type SessionWorker struct {
	fileRequest *cartaDefinitions.OpenFile
	requestId   uint32
	conn        *websocket.Conn
	sendChan    chan []byte

	// done is closed once (via doneOnce) when the worker is torn down. Senders
	// and the sendHandler goroutine select on it instead of relying on sendChan
	// being closed, so a send can never race a close (send-on-closed panic).
	done     chan struct{}
	doneOnce sync.Once

	// workerId is the spawner's id for the backend process this worker proxies.
	// Retained so the backend can be reaped (RequestWorkerShutdown) on CLOSE_FILE
	// or client disconnect. Empty if unknown.
	workerId string

	// owner is the Session this worker belongs to (set at construction). Used to
	// reach session-level helpers such as server-feature-flag injection.
	owner *Session

	// Controller-originated request/stream correlation. pending maps a
	// controller-allocated requestId (high bit set) to its waiting consumer.
	reqMu      sync.Mutex
	pending    map[uint32]*pendingRequest
	reqCounter atomic.Uint32
}

func (sw *SessionWorker) proxyMessageToWorker(msg proto.Message, eventType cartaDefinitions.EventType, requestId uint32) error {
	byteData, err := cartaHelpers.PrepareMessagePayload(msg, eventType, requestId)
	if err != nil {
		return err
	}

	slog.Debug("Proxying message from session to worker", "eventType", eventType)
	if !sw.enqueue(byteData) {
		return fmt.Errorf("worker is shutting down")
	}
	return nil
}

// enqueue hands a framed message to the sendHandler, or returns false if the
// worker is being torn down. Selecting on done means the send can never panic
// on a closed sendChan (sendChan is never closed). A nil done (in unit tests
// that build a worker by hand) is never ready, so the send proceeds.
func (sw *SessionWorker) enqueue(byteData []byte) bool {
	select {
	case sw.sendChan <- byteData:
		return true
	case <-sw.done:
		return false
	}
}

func (sw *SessionWorker) workerMessageHandler() {
	for {
		messageType, message, err := sw.conn.ReadMessage()
		if err != nil {
			slog.Error("Error reading message from worker", "error", err)
			break
		}

		// Ping/pong sequence
		if messageType == websocket.TextMessage && string(message) == "PING" {
			slog.Debug("Received PING from worker, sending PONG")
			err := sw.conn.WriteMessage(websocket.TextMessage, []byte("PONG"))
			if err != nil {
				slog.Error("Failed to send pong message", "error", err)
			}
			continue
		}

		// Ignore all other non-binary messages
		if messageType != websocket.BinaryMessage {
			slog.Warn("Ignoring non-binary message", "messageType", messageType, "message", string(message))
			continue
		}

		go func() {
			prefix, err := cartaHelpers.DecodeMessagePrefix(message)
			if err != nil {
				slog.Error("failed to unmarshal message", "error", err)
				return
			}
			if prefix.IcdVersion != cartaHelpers.IcdVersion {
				slog.Error("invalid ICD version", "version", prefix.IcdVersion)
				return
			}
			slog.Debug("Received message from worker", "eventType", prefix.EventType)

			var workerName string
			if sw.fileRequest != nil {
				workerName = fmt.Sprintf("worker:%d", sw.fileRequest.FileId)
			} else {
				workerName = "shared-worker"
			}

			// Special case for register viewer: send the open file payload once the worker is ready

			slog.Debug("Received message from worker", "eventType", prefix.EventType, "workerName", workerName, "hasFileRequest", sw.fileRequest != nil)

			// Controller-originated request/stream responses go to their
			// waiting channel and are not forwarded to the client.
			if sw.deliverToPending(prefix.RequestId, prefix.EventType, message[8:]) {
				return
			}

			if sw.fileRequest != nil && prefix.EventType == cartaDefinitions.EventType_REGISTER_VIEWER_ACK {
				slog.Debug("Proxying OPEN_FILE message to worker after REGISTER_VIEWER_ACK", "workerName", workerName)
				if err := sw.proxyMessageToWorker(sw.fileRequest, cartaDefinitions.EventType_OPEN_FILE, sw.requestId); err != nil {
					slog.Error("Error proxying open file message to worker", "error", err)
				}
				return
			}

			if sw.fileRequest == nil && prefix.EventType == cartaDefinitions.EventType_REGISTER_VIEWER_ACK {
				sw.owner.forwardRegisterViewerAck(prefix.RequestId, message[8:])
				return
			}

			// Pass the incoming message along to the client
			sw.owner.sendToClient(message)
		}()
	}

	// The backend connection has dropped; release any in-flight controller
	// requests so their consumers don't block forever.
	sw.failAllPending()
}

func (sw *SessionWorker) handleInit() {
	sw.sendChan = make(chan []byte, 100)
	sw.done = make(chan struct{})
	// Start up the message sender and proxy handler
	var workerName string
	if sw.fileRequest != nil {
		workerName = fmt.Sprintf("worker:%d", sw.fileRequest.FileId)
	} else {
		workerName = "shared-worker"
	}

	go sendHandler(sw.sendChan, sw.done, sw.conn, workerName)
	go sw.workerMessageHandler()
}

// disconnect signals teardown (closing done releases the sendHandler and any
// blocked senders) and closes the backend connection. sendChan is intentionally
// never closed, so a concurrent enqueue cannot panic. Idempotent via doneOnce.
func (sw *SessionWorker) disconnect() {
	sw.doneOnce.Do(func() {
		if sw.done != nil {
			close(sw.done)
		}
	})
	if sw.conn != nil {
		helpers.CloseOrLog(sw.conn)
	}
}
