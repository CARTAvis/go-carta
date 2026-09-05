package session

import (
	"testing"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

func momentResponse(t *testing.T, requestId uint32, acks ...*cartaDefinitions.OpenFileAck) []byte {
	t.Helper()
	framed, err := cartaHelpers.PrepareMessagePayload(&cartaDefinitions.MomentResponse{Success: true, OpenFileAcks: acks},
		cartaDefinitions.EventType_MOMENT_RESPONSE, requestId)
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	return framed
}

func TestDerivedFileIds_OnlySuccessfulAcks(t *testing.T) {
	raw := momentResponse(t, 1,
		&cartaDefinitions.OpenFileAck{Success: true, FileId: 1},
		&cartaDefinitions.OpenFileAck{Success: false, FileId: 2},
		&cartaDefinitions.OpenFileAck{Success: true, FileId: 3},
	)
	ids := derivedFileIds(cartaDefinitions.EventType_MOMENT_RESPONSE, raw[8:])
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 3 {
		t.Fatalf("unexpected ids %v", ids)
	}

	pv := marshal(t, &cartaDefinitions.PvResponse{Success: true, OpenFileAck: &cartaDefinitions.OpenFileAck{Success: true, FileId: 7}})
	if ids := derivedFileIds(cartaDefinitions.EventType_PV_RESPONSE, pv); len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("unexpected pv ids %v", ids)
	}
	if ids := derivedFileIds(cartaDefinitions.EventType_PV_RESPONSE, marshal(t, &cartaDefinitions.PvResponse{Success: true})); len(ids) != 0 {
		t.Fatalf("a preview response opens no file, got %v", ids)
	}
}

func TestHandleMessage_RoutesDerivedImagesToTheirBackend(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	w0.handleMessage(momentResponse(t, 1, &cartaDefinitions.OpenFileAck{Success: true, FileId: 1}))

	if out := <-s.clientSendChan; len(out.data) == 0 {
		t.Fatal("response should still be forwarded to the client")
	}
	if w, ok := s.getFileWorker(1); !ok || w != w0 {
		t.Fatal("derived image should route to the backend that created it")
	}
}

func TestHandleCloseFile_DerivedImageIsClosedOnItsBackend(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)
	s.addFileAlias(1, w0)

	closeFile(t, s, 1)

	expectWorkerEvent(t, w0, cartaDefinitions.EventType_CLOSE_FILE)
	if w0.isDone() {
		t.Fatal("closing a derived image must not shut down the backend")
	}
	if _, ok := s.getFileWorker(1); ok {
		t.Fatal("derived image should be unregistered")
	}
	if _, ok := s.getFileWorker(0); !ok {
		t.Fatal("primary file should still be open")
	}
}

func TestHandleCloseFile_PrimaryTakesDerivedImagesWithIt(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)
	s.addFileAlias(1, w0)
	s.setPvPreviewFile(42, 1)

	closeFile(t, s, 0)

	if !w0.isDone() {
		t.Fatal("backend should be shut down")
	}
	if _, ok := s.getFileWorker(1); ok {
		t.Fatal("derived image should go with its backend")
	}
	if _, ok := s.pvPreviewFile(42); ok {
		t.Fatal("preview on the derived image should be dropped")
	}
}

func TestAddFileAlias_CollisionKeepsExistingOwner(t *testing.T) {
	s := newSessionWithFiles(0, 1)
	w0, _ := s.getFileWorker(0)
	w1, _ := s.getFileWorker(1)

	if s.addFileAlias(1, w0) {
		t.Fatal("an id already owned by another backend must be refused")
	}
	if w, _ := s.getFileWorker(1); w != w1 {
		t.Fatal("existing owner must be kept")
	}
}
