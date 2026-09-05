package session

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

func newTestSession() *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		Context:        ctx,
		Cancel:         cancel,
		clientSendChan: make(chan outbound, 4),
		multiBackend:   true,
	}
}

// newTestWorker builds a worker that was never started: no backend connection
// and no workerId, so shutdown makes no spawner call.
func newTestWorker(s *Session, fileId int32) *SessionWorker {
	return newSessionWorker(s, &cartaDefinitions.OpenFile{FileId: fileId}, 0)
}

func newSessionWithFiles(fileIds ...int32) *Session {
	s := newTestSession()
	s.sharedWorker = newSessionWorker(s, nil, 0)
	for _, id := range fileIds {
		s.setFileWorker(id, newTestWorker(s, id))
	}
	return s
}

func marshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// expectWorkerEvent waits for one frame on the worker's send queue and returns its prefix.
func expectWorkerEvent(t *testing.T, w *SessionWorker, want cartaDefinitions.EventType) cartaHelpers.MessagePrefix {
	t.Helper()
	select {
	case out := <-w.sendChan:
		prefix, err := cartaHelpers.DecodeMessagePrefix(out.data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if prefix.EventType != want {
			t.Fatalf("worker %s got %v, want %v", w.name, prefix.EventType, want)
		}
		return prefix
	case <-time.After(2 * time.Second):
		t.Fatalf("expected %v to be routed to worker %s, got nothing", want, w.name)
		return cartaHelpers.MessagePrefix{}
	}
}

func expectNoWorkerEvent(t *testing.T, w *SessionWorker) {
	t.Helper()
	select {
	case out := <-w.sendChan:
		prefix, _ := cartaHelpers.DecodeMessagePrefix(out.data)
		t.Fatalf("worker %s unexpectedly received %v", w.name, prefix.EventType)
	default:
	}
}

func closeFile(t *testing.T, s *Session, fileId int32) {
	t.Helper()
	closeFileWithRequestId(t, s, fileId, 1)
}

func closeFileWithRequestId(t *testing.T, s *Session, fileId int32, requestId uint32) {
	t.Helper()
	raw := marshal(t, &cartaDefinitions.CloseFile{FileId: fileId})
	if err := s.handleCloseFile(cartaDefinitions.EventType_CLOSE_FILE, requestId, raw); err != nil {
		t.Fatalf("handleCloseFile(%d): %v", fileId, err)
	}
}

// clientEvent reads one frame from the client queue and returns its type.
func clientEvent(t *testing.T, s *Session) cartaDefinitions.EventType {
	t.Helper()
	select {
	case out := <-s.clientSendChan:
		prefix, err := cartaHelpers.DecodeMessagePrefix(out.data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return prefix.EventType
	case <-time.After(2 * time.Second):
		t.Fatal("expected a frame to be sent to the client, got nothing")
		return cartaDefinitions.EventType_EMPTY_EVENT
	}
}

func TestHandleCloseFile_ShutsDownAndRemovesOne(t *testing.T) {
	s := newSessionWithFiles(0, 1)
	w0, _ := s.getFileWorker(0)

	closeFile(t, s, 0)

	if _, ok := s.getFileWorker(0); ok {
		t.Fatal("file 0 should have been removed")
	}
	if _, ok := s.getFileWorker(1); !ok {
		t.Fatal("file 1 should still be open")
	}
	if !w0.isDone() {
		t.Fatal("closed worker should be shut down")
	}
	expectNoWorkerEvent(t, s.sharedWorker)
}

func TestHandleCloseFile_CloseAllAlsoReachesSharedBackend(t *testing.T) {
	s := newSessionWithFiles(0, 1, 2)

	closeFile(t, s, -1)

	if workers := s.takeFileWorkers(); len(workers) != 0 {
		t.Fatalf("expected all file workers reaped, %d remain", len(workers))
	}
	expectWorkerEvent(t, s.sharedWorker, cartaDefinitions.EventType_CLOSE_FILE)
}

func TestHandleCloseFile_UnknownFileGoesToSharedBackend(t *testing.T) {
	s := newSessionWithFiles(0)

	closeFile(t, s, 99)

	if _, ok := s.getFileWorker(0); !ok {
		t.Fatal("closing an unknown file must not affect existing workers")
	}
	expectWorkerEvent(t, s.sharedWorker, cartaDefinitions.EventType_CLOSE_FILE)
}

func TestHandleDisconnect_ReapsAllWorkers(t *testing.T) {
	s := newSessionWithFiles(0, 1)
	w0, _ := s.getFileWorker(0)
	shared := s.sharedWorker

	s.HandleDisconnect()

	if !s.closed() {
		t.Fatal("session should be closed")
	}
	if !w0.isDone() || !shared.isDone() {
		t.Fatal("all workers should be shut down on disconnect")
	}
	if _, ok := s.setFileWorker(5, newTestWorker(s, 5)); ok {
		t.Fatal("registering a worker after disconnect must be refused")
	}
}

func TestWorkerLost_OnlyUnregistersItself(t *testing.T) {
	s := newSessionWithFiles(0)
	old, _ := s.getFileWorker(0)
	replacement := newTestWorker(s, 0)
	s.setFileWorker(0, replacement)

	s.workerLost(old)

	if w, _ := s.getFileWorker(0); w != replacement {
		t.Fatal("a lost worker must not unregister its replacement")
	}
	if !old.isDone() {
		t.Fatal("lost worker should be shut down")
	}
	if s.closed() {
		t.Fatal("losing a file worker must not end the session")
	}
}

func TestWorkerLost_SharedBackendEndsSession(t *testing.T) {
	s := newSessionWithFiles(0)

	s.workerLost(s.sharedWorker)

	if !s.closed() {
		t.Fatal("losing the shared backend should end the session")
	}
	if s.getSharedWorker() != nil {
		t.Fatal("lost shared worker should be unregistered")
	}
}

func TestClaim_ClosedWhileStartingKeepsNoBackend(t *testing.T) {
	sw := newTestWorker(newTestSession(), 0)
	sw.shutdown()

	if sw.claim("worker-id") {
		t.Fatal("a worker shut down while starting must not keep the backend")
	}
	if sw.attach(nil) {
		t.Fatal("a worker shut down while starting must not attach a connection")
	}
}

func TestStartAsync_ClosedWhileStartingReportsNothing(t *testing.T) {
	s := newSessionWithFiles(0)
	w, _ := s.getFileWorker(0)
	s.takeFileWorker(0)
	w.shutdown()

	reported := make(chan error, 1)
	w.startAsync(func(err error) { reported <- err })

	select {
	case err := <-reported:
		t.Fatalf("a worker closed by request must not report a failure, got %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestEnqueue_ConcurrentShutdownDoesNotPanic(t *testing.T) {
	sw := newTestWorker(newTestSession(), 0)

	drained := make(chan struct{})
	go func() {
		for {
			select {
			case <-sw.sendChan:
			case <-sw.done:
				close(drained)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				_ = sw.enqueue([]byte("x"))
			}
		}()
	}

	sw.shutdown()
	sw.shutdown()
	wg.Wait()
	<-drained

	if err := sw.enqueue([]byte("late")); err == nil {
		t.Fatal("enqueue after shutdown must fail")
	}
}

func TestHandleCloseFile_WithoutRequestIdStillReaps(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	closeFileWithRequestId(t, s, 0, 0)

	if !w0.isDone() {
		t.Fatal("a close carrying no request id must still reap the backend")
	}
}

func TestWorkerLost_FileBackendTellsTheClient(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	s.workerLost(w0)

	if got := clientEvent(t, s); got != cartaDefinitions.EventType_ERROR_DATA {
		t.Fatalf("expected the client to be told, got %v", got)
	}
}

func TestOpenFileAfterRegistration_RefusalReachesTheClient(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	w0.openFileAfterRegistration(marshal(t, &cartaDefinitions.RegisterViewerAck{Success: false, Message: "no"}))

	if got := clientEvent(t, s); got != cartaDefinitions.EventType_OPEN_FILE_ACK {
		t.Fatalf("expected an open file ack, got %v", got)
	}
	if _, ok := s.getFileWorker(0); ok {
		t.Fatal("a backend that refused to register should be unregistered")
	}
	if !w0.isDone() {
		t.Fatal("a backend that refused to register should be shut down")
	}
	expectNoWorkerEvent(t, w0)
}

func TestOpenFileAfterRegistration_SuccessSendsOpenFile(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	w0.openFileAfterRegistration(marshal(t, &cartaDefinitions.RegisterViewerAck{Success: true}))

	expectWorkerEvent(t, w0, cartaDefinitions.EventType_OPEN_FILE)
}
