package session

import (
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// controllerRequestIDBit marks request ids allocated by the controller. Client
// request ids with this bit set are rejected so the two can never collide.
const controllerRequestIDBit uint32 = 1 << 31

// WorkerMessage is one decoded frame from a backend.
type WorkerMessage struct {
	EventType cartaDefinitions.EventType
	Payload   []byte
}

// pendingRequest is a controller-originated request awaiting its response.
type pendingRequest struct {
	sw        *SessionWorker
	requestId uint32
	ch        chan WorkerMessage
}

// Response yields the single response and is then closed. It is closed
// without a value if the backend connection drops first.
func (p *pendingRequest) Response() <-chan WorkerMessage {
	return p.ch
}

// Forget stops waiting for the response. It returns false if the response
// has already been claimed, in which case it will arrive on Response shortly.
func (p *pendingRequest) Forget() bool {
	_, ok := p.sw.forgetPending(p.requestId)
	return ok
}

func (sw *SessionWorker) nextRequestId() uint32 {
	return controllerRequestIDBit | (sw.reqCounter.Add(1) &^ controllerRequestIDBit)
}

// Request sends a controller-originated request to the backend.
func (sw *SessionWorker) Request(eventType cartaDefinitions.EventType, msg proto.Message) (*pendingRequest, error) {
	p := &pendingRequest{sw: sw, requestId: sw.nextRequestId(), ch: make(chan WorkerMessage, 1)}

	sw.reqMu.Lock()
	sw.pending[p.requestId] = p.ch
	sw.reqMu.Unlock()

	if err := sw.proxyMessageToWorker(msg, eventType, p.requestId); err != nil {
		p.Forget()
		return nil, err
	}
	return p, nil
}

// forgetPending unregisters a controller request and returns its channel if it
// was still pending.
func (sw *SessionWorker) forgetPending(requestId uint32) (chan WorkerMessage, bool) {
	sw.reqMu.Lock()
	defer sw.reqMu.Unlock()
	ch, ok := sw.pending[requestId]
	if ok {
		delete(sw.pending, requestId)
	}
	return ch, ok
}

// deliverToPending hands a backend frame to the controller request waiting for
// it. It returns false if no request is waiting.
func (sw *SessionWorker) deliverToPending(requestId uint32, eventType cartaDefinitions.EventType, payload []byte) bool {
	ch, ok := sw.forgetPending(requestId)
	if !ok {
		return false
	}
	ch <- WorkerMessage{EventType: eventType, Payload: payload}
	close(ch)
	return true
}

// failAllPending closes every pending request channel. Called once the worker
// has shut down, so no request can be registered afterwards.
func (sw *SessionWorker) failAllPending() {
	sw.reqMu.Lock()
	defer sw.reqMu.Unlock()
	for requestId, ch := range sw.pending {
		slog.Warn("Backend connection lost; failing in-flight request", "requestId", requestId, "workerName", sw.name)
		close(ch)
	}
	clear(sw.pending)
}
