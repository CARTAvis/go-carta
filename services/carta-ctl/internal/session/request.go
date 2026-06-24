package session

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// controllerRequestIDBit is OR-ed into every controller-originated requestId so
// it can never collide with a frontend-originated id (which start at 1 and stay
// well below 2^31).
const controllerRequestIDBit uint32 = 1 << 31

// WorkerMessage is one decoded frame delivered to a controller-originated
// request/stream consumer.
type WorkerMessage struct {
	EventType cartaDefinitions.EventType
	Payload   []byte
}

// pendingRequest is a registered consumer awaiting backend responses for a
// controller-allocated requestId.
type pendingRequest struct {
	ch         chan WorkerMessage
	done       chan struct{} // closed when the request completes (stops the ctx watcher)
	stream     bool
	isTerminal func(cartaDefinitions.EventType, []byte) bool
}

func (sw *SessionWorker) nextRequestId() uint32 {
	return controllerRequestIDBit | sw.reqCounter.Add(1)
}

// Request sends a controller-originated request and returns a channel that
// receives the single matching response, then closes, plus a cancel func bound
// to this request. The channel is closed without a value if the parent ctx is
// done, the returned cancel is called, or the request times out. Callers should
// `defer cancel()` to release resources even on the normal completion path.
func (sw *SessionWorker) Request(ctx context.Context, eventType cartaDefinitions.EventType, msg proto.Message) (<-chan WorkerMessage, context.CancelFunc, error) {
	return sw.track(ctx, eventType, msg, false, nil, 1)
}

// RequestStream is like Request but delivers every matching message until
// isTerminal returns true for a message (that terminal message is delivered),
// the returned cancel is called, or the parent ctx is done. The channel is
// closed when the stream ends. Consumers MUST drain the channel; a full buffer
// back-pressures the worker read goroutine. Callers should `defer cancel()`.
func (sw *SessionWorker) RequestStream(
	ctx context.Context,
	eventType cartaDefinitions.EventType,
	msg proto.Message,
	isTerminal func(cartaDefinitions.EventType, []byte) bool,
	buffer int,
) (<-chan WorkerMessage, context.CancelFunc, error) {
	if buffer <= 0 {
		buffer = 16
	}
	return sw.track(ctx, eventType, msg, true, isTerminal, buffer)
}

func (sw *SessionWorker) track(
	ctx context.Context,
	eventType cartaDefinitions.EventType,
	msg proto.Message,
	stream bool,
	isTerminal func(cartaDefinitions.EventType, []byte) bool,
	buffer int,
) (<-chan WorkerMessage, context.CancelFunc, error) {
	// Derive a cancellable child context so the caller gets a cancel handle bound
	// to this specific request/stream, in addition to the parent ctx's deadline
	// or cancellation. Cancelling either path wakes the watcher below.
	ctx, cancel := context.WithCancel(ctx)
	requestId := sw.nextRequestId()
	pr := &pendingRequest{
		ch:         make(chan WorkerMessage, buffer),
		done:       make(chan struct{}),
		stream:     stream,
		isTerminal: isTerminal,
	}

	sw.reqMu.Lock()
	if sw.pending == nil {
		sw.pending = make(map[uint32]*pendingRequest)
	}
	sw.pending[requestId] = pr
	sw.reqMu.Unlock()

	// Watch ctx (parent cancel/timeout or the returned cancel) so a request that
	// never completes is cleaned up. Exits early (without touching ch) when the
	// request completes normally via done.
	go func() {
		select {
		case <-ctx.Done():
			sw.reqMu.Lock()
			_, stillPending := sw.pending[requestId]
			if stillPending {
				delete(sw.pending, requestId)
			}
			sw.reqMu.Unlock()
			if stillPending {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					slog.Warn("Controller request timed out waiting for backend",
						"eventType", eventType, "requestId", requestId, "fileId", sw.fileRequest.GetFileId())
				}
				close(pr.ch)
			}
		case <-pr.done:
		}
	}()

	if err := sw.proxyMessageToWorker(msg, eventType, requestId); err != nil {
		sw.reqMu.Lock()
		_, stillPending := sw.pending[requestId]
		if stillPending {
			delete(sw.pending, requestId)
		}
		sw.reqMu.Unlock()
		if stillPending {
			close(pr.done) // release the ctx watcher
			close(pr.ch)
		}
		cancel() // release the derived context
		return nil, nil, err
	}
	return pr.ch, cancel, nil
}

// deliverToPending routes a backend frame to its waiting consumer if its
// requestId belongs to a controller-originated request/stream. Returns true if
// the frame was consumed (and must NOT be forwarded to the client).
func (sw *SessionWorker) deliverToPending(requestId uint32, eventType cartaDefinitions.EventType, payload []byte) bool {
	sw.reqMu.Lock()
	pr, ok := sw.pending[requestId]
	if !ok {
		sw.reqMu.Unlock()
		return false
	}
	terminal := !pr.stream || (pr.isTerminal != nil && pr.isTerminal(eventType, payload))
	if terminal {
		delete(sw.pending, requestId)
	}
	sw.reqMu.Unlock()

	// Copy: the websocket read buffer may be reused after this returns.
	pr.ch <- WorkerMessage{EventType: eventType, Payload: append([]byte(nil), payload...)}

	if terminal {
		close(pr.done) // release the ctx watcher
		close(pr.ch)
	}
	return true
}

// failAllPending closes every in-flight request/stream channel on this worker.
// Called when the worker's connection drops (backend crash or disconnect) so
// consumers waiting on a response are released with a closed channel instead of
// blocking forever. Idempotent: a second call sees an empty map.
//
// NOTE: a non-terminal RequestStream delivery that is mid-send on pr.ch when
// this runs could race with close(pr.ch). RequestStream has no production
// consumer yet; guard stream sends under reqMu before it gains one.
func (sw *SessionWorker) failAllPending() {
	sw.reqMu.Lock()
	pending := sw.pending
	sw.pending = nil
	sw.reqMu.Unlock()

	for requestId, pr := range pending {
		slog.Warn("Backend connection lost; failing in-flight request",
			"requestId", requestId, "fileId", sw.fileRequest.GetFileId())
		close(pr.done) // stop the ctx watcher
		close(pr.ch)   // release the consumer with a closed channel
	}
}
