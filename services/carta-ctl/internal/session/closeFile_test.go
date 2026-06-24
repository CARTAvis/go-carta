package session

import (
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// newTestFileWorker returns a worker with no real connection and an empty
// workerId so shutdownFileWorker skips the spawner HTTP call. done is set so
// disconnect()'s teardown signal can be observed without running handleInit.
func newTestFileWorker() *SessionWorker {
	return &SessionWorker{sendChan: make(chan []byte, 1), done: make(chan struct{})}
}

// closeFilePayload marshals a CLOSE_FILE body for the given file id.
func closeFilePayload(t *testing.T, fileId int32) []byte {
	t.Helper()
	raw, err := proto.Marshal(&cartaDefinitions.CloseFile{FileId: fileId})
	if err != nil {
		t.Fatalf("marshal CloseFile: %v", err)
	}
	return raw
}

func newSessionWithFiles(workers map[int32]*SessionWorker) *Session {
	return &Session{
		sharedWorker: &SessionWorker{}, // non-nil so checkAndParse passes
		fileMap:      workers,
	}
}

func TestHandleCloseFile_ShutsDownAndRemovesOne(t *testing.T) {
	w0, w1 := newTestFileWorker(), newTestFileWorker()
	s := newSessionWithFiles(map[int32]*SessionWorker{0: w0, 1: w1})

	if err := s.handleCloseFile(cartaDefinitions.EventType_CLOSE_FILE, 1, closeFilePayload(t, 0)); err != nil {
		t.Fatalf("handleCloseFile: %v", err)
	}

	if _, ok := s.getFileWorker(0); ok {
		t.Fatal("file 0 should have been removed from fileMap")
	}
	if _, ok := s.getFileWorker(1); !ok {
		t.Fatal("file 1 should still be open")
	}
	// disconnect() closes done (the teardown signal); sendChan is never closed.
	select {
	case <-w0.done:
	default:
		t.Fatal("closed worker's done channel should be closed")
	}
}

func TestHandleCloseFile_CloseAll(t *testing.T) {
	s := newSessionWithFiles(map[int32]*SessionWorker{
		0: newTestFileWorker(),
		1: newTestFileWorker(),
		2: newTestFileWorker(),
	})

	if err := s.handleCloseFile(cartaDefinitions.EventType_CLOSE_FILE, 1, closeFilePayload(t, -1)); err != nil {
		t.Fatalf("handleCloseFile(-1): %v", err)
	}

	if got := len(s.fileWorkerIds()); got != 0 {
		t.Fatalf("expected all file workers reaped, %d remain", got)
	}
}

func TestHandleCloseFile_UnknownIsNoop(t *testing.T) {
	w0 := newTestFileWorker()
	s := newSessionWithFiles(map[int32]*SessionWorker{0: w0})

	if err := s.handleCloseFile(cartaDefinitions.EventType_CLOSE_FILE, 1, closeFilePayload(t, 99)); err != nil {
		t.Fatalf("handleCloseFile(unknown): %v", err)
	}
	if _, ok := s.getFileWorker(0); !ok {
		t.Fatal("closing an unknown file must not affect existing workers")
	}
}

func TestHandleDisconnect_ReapsAllFileWorkers(t *testing.T) {
	s := &Session{
		clientSendChan: make(chan []byte, 1),
		sharedWorker:   &SessionWorker{}, // workerId "" -> no spawner call
		fileMap: map[int32]*SessionWorker{
			0: newTestFileWorker(),
			1: newTestFileWorker(),
		},
		// Info.WorkerId left empty so HandleDisconnect skips the shared-worker
		// spawner shutdown (no fake spawner in this unit test).
	}

	s.HandleDisconnect()

	if got := len(s.fileWorkerIds()); got != 0 {
		t.Fatalf("expected all file workers reaped on disconnect, %d remain", got)
	}
}

// TestEnqueue_ConcurrentDisconnectDoesNotPanic drives many senders against a
// worker while it is torn down. Pre-fix, disconnect() closed sendChan and a
// concurrent send panicked ("send on closed channel"); now disconnect() only
// closes done, which both senders and the drainer select on, so no send ever
// touches a closed channel. Run under -race.
func TestEnqueue_ConcurrentDisconnectDoesNotPanic(t *testing.T) {
	sw := &SessionWorker{sendChan: make(chan []byte, 8), done: make(chan struct{})}

	// Stand in for sendHandler: drain the buffer until teardown.
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
				sw.enqueue([]byte("x"))
			}
		}()
	}

	sw.disconnect()
	sw.disconnect() // idempotent: doneOnce must not double-close
	wg.Wait()
	<-drained
}

// TestFileMap_ConcurrentOpenRouteClose hammers the fileMap helpers from many
// goroutines so `go test -race` can flag any unsynchronized access. Mirrors the
// production paths: setFileWorker (OPEN_FILE), getFileWorker (routing), and
// shutdownFileWorker (CLOSE_FILE / disconnect).
func TestFileMap_ConcurrentOpenRouteClose(t *testing.T) {
	s := &Session{}
	const goroutines = 16
	const iterations = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				fileId := int32((g + i) % 8) // contend on a small set of ids
				s.setFileWorker(fileId, newTestFileWorker())
				s.getFileWorker(fileId)
				_ = s.fileWorkerIds()
				s.shutdownFileWorker(fileId)
			}
		}(g)
	}
	wg.Wait()
}
