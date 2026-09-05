package session

import (
	"testing"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

func TestRequest_DeliversResponseThenCloses(t *testing.T) {
	sw := newTestWorker(newTestSession(), 0)

	req, err := sw.Request(cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{FileId: 0})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	prefix := expectWorkerEvent(t, sw, cartaDefinitions.EventType_SET_REGION)
	if prefix.RequestId&controllerRequestIDBit == 0 {
		t.Fatalf("controller request id %d must have the high bit set", prefix.RequestId)
	}

	if !sw.deliverToPending(prefix.RequestId, cartaDefinitions.EventType_SET_REGION_ACK, []byte{1, 2}) {
		t.Fatal("response should have been delivered to the pending request")
	}
	wm, ok := <-req.Response()
	if !ok || wm.EventType != cartaDefinitions.EventType_SET_REGION_ACK || len(wm.Payload) != 2 {
		t.Fatalf("unexpected response %+v ok=%v", wm, ok)
	}
	if _, ok := <-req.Response(); ok {
		t.Fatal("channel should be closed after the response")
	}
	if req.Forget() {
		t.Fatal("a delivered request must report that it was already claimed")
	}
}

func TestRequest_ForgetDropsLateResponse(t *testing.T) {
	sw := newTestWorker(newTestSession(), 0)

	req, err := sw.Request(cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	prefix := expectWorkerEvent(t, sw, cartaDefinitions.EventType_SET_REGION)

	if !req.Forget() {
		t.Fatal("a pending request should be forgotten")
	}
	if sw.deliverToPending(prefix.RequestId, cartaDefinitions.EventType_SET_REGION_ACK, nil) {
		t.Fatal("a forgotten request must not accept a response")
	}
}

func TestRequest_FailsWhenWorkerIsShutDown(t *testing.T) {
	sw := newTestWorker(newTestSession(), 0)
	sw.shutdown()

	if _, err := sw.Request(cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{}); err == nil {
		t.Fatal("Request on a shut down worker must fail")
	}
	if len(sw.pending) != 0 {
		t.Fatal("a failed request must not stay pending")
	}
}

func TestFailAllPending_ClosesInflightChannels(t *testing.T) {
	sw := newTestWorker(newTestSession(), 0)

	r1, _ := sw.Request(cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{})
	r2, _ := sw.Request(cartaDefinitions.EventType_SET_REGION, &cartaDefinitions.SetRegion{})

	sw.failAllPending()

	for _, r := range []*pendingRequest{r1, r2} {
		if _, ok := <-r.Response(); ok {
			t.Fatal("in-flight request should be closed without a value")
		}
	}
}
