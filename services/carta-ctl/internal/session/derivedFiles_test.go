package session

import (
	"testing"

	"google.golang.org/protobuf/proto"

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

// clientFrame reads one frame from the client queue and decodes its payload.
func clientFrame(t *testing.T, s *Session, msg proto.Message) cartaHelpers.MessagePrefix {
	t.Helper()
	out := <-s.clientSendChan
	prefix, err := cartaHelpers.DecodeMessagePrefix(out.data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := proto.Unmarshal(out.data[8:], msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return prefix
}

func TestAdoptDerivedFiles_RenumbersTheImagesAndRoutesThem(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	// The backend numbers its moment map 1, which the client already uses.
	w0.handleMessage(momentResponse(t, 4,
		&cartaDefinitions.OpenFileAck{Success: true, FileId: 1, FileInfo: &cartaDefinitions.FileInfo{Name: "moment"}},
		&cartaDefinitions.OpenFileAck{Success: false, FileId: 2},
	))

	var response cartaDefinitions.MomentResponse
	clientFrame(t, s, &response)
	if len(response.OpenFileAcks) != 2 {
		t.Fatalf("expected both acks forwarded, got %d", len(response.OpenFileAcks))
	}
	fileId := response.OpenFileAcks[0].FileId
	if fileId <= derivedFileIdBase {
		t.Fatalf("the image should have been renumbered, got %d", fileId)
	}
	if response.OpenFileAcks[0].FileInfo.GetName() != "moment" {
		t.Fatal("the rest of the response should survive renumbering")
	}
	if response.OpenFileAcks[1].FileId != 2 {
		t.Fatal("an image the backend failed to open should not be renumbered")
	}
	if w, ok := s.getFileWorker(fileId); !ok || w != w0 {
		t.Fatal("the image should route to the backend that opened it")
	}
	if backendFileId, ok := w0.backendFileId(fileId); !ok || backendFileId != 1 {
		t.Fatalf("expected a translation back to 1, got %d ok=%v", backendFileId, ok)
	}
}

func TestDerivedFile_MessagesAreTranslatedBothWays(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)
	const fileId, backendFileId = derivedFileIdBase + 1, 1
	s.addFileAlias(fileId, w0)
	w0.mapDerivedFile(fileId, backendFileId)

	// The client asks about the image by the id it was given.
	raw := marshal(t, &cartaDefinitions.SetImageChannels{FileId: fileId, Channel: 7})
	if err := s.handleProxiedMessage(cartaDefinitions.EventType_SET_IMAGE_CHANNELS, 3, raw); err != nil {
		t.Fatalf("handleProxiedMessage: %v", err)
	}
	out := <-w0.sendChan
	var request cartaDefinitions.SetImageChannels
	if err := proto.Unmarshal(out.data[8:], &request); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if request.FileId != backendFileId || request.Channel != 7 {
		t.Fatalf("the backend should be asked about its own id, got %+v", &request)
	}

	// The backend answers with its own id, which the client never saw.
	tile, err := cartaHelpers.PrepareMessagePayload(&cartaDefinitions.RasterTileData{FileId: backendFileId, Channel: 7},
		cartaDefinitions.EventType_RASTER_TILE_DATA, 0)
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	w0.handleMessage(tile)

	var data cartaDefinitions.RasterTileData
	clientFrame(t, s, &data)
	if data.FileId != fileId || data.Channel != 7 {
		t.Fatalf("the client should see the id it was given, got %+v", &data)
	}
}

func TestDerivedFile_UntranslatedMessagesAreLeftAlone(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)

	raw := marshal(t, &cartaDefinitions.SetImageChannels{FileId: 0, Channel: 2})
	if err := s.handleProxiedMessage(cartaDefinitions.EventType_SET_IMAGE_CHANNELS, 3, raw); err != nil {
		t.Fatalf("handleProxiedMessage: %v", err)
	}

	out := <-w0.sendChan
	var request cartaDefinitions.SetImageChannels
	if err := proto.Unmarshal(out.data[8:], &request); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if request.FileId != 0 || request.Channel != 2 {
		t.Fatalf("a file the client opened itself should pass through, got %+v", &request)
	}
}

func TestHandleCloseFile_DerivedImageIsClosedOnItsBackend(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)
	const fileId, backendFileId = derivedFileIdBase + 1, 1
	s.addFileAlias(fileId, w0)
	w0.mapDerivedFile(fileId, backendFileId)

	closeFile(t, s, fileId)

	out := <-w0.sendChan
	var closed cartaDefinitions.CloseFile
	if err := proto.Unmarshal(out.data[8:], &closed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if closed.FileId != backendFileId {
		t.Fatalf("the backend should be told its own id, got %d", closed.FileId)
	}
	if w0.isDone() {
		t.Fatal("closing an image the backend opened must not shut the backend down")
	}
	if _, ok := s.getFileWorker(fileId); ok {
		t.Fatal("the image should be unregistered")
	}
	if _, ok := w0.backendFileId(fileId); ok {
		t.Fatal("the translation should be forgotten")
	}
}

func TestHandleCloseFile_PrimaryTakesDerivedImagesWithIt(t *testing.T) {
	s := newSessionWithFiles(0)
	w0, _ := s.getFileWorker(0)
	const fileId = derivedFileIdBase + 1
	s.addFileAlias(fileId, w0)
	w0.mapDerivedFile(fileId, 1)
	s.setPvPreviewFile(42, fileId)

	closeFile(t, s, 0)

	if !w0.isDone() {
		t.Fatal("backend should be shut down")
	}
	if _, ok := s.getFileWorker(fileId); ok {
		t.Fatal("images the backend opened should go with it")
	}
	if _, ok := s.pvPreviewFile(42); ok {
		t.Fatal("a preview on one of those images should be dropped")
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
