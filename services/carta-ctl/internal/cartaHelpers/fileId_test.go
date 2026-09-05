package cartaHelpers

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

func TestFileIdFromBytes_ReadsBothDirections(t *testing.T) {
	// A client request, whose file id the old routing table also knew.
	req, _ := proto.Marshal(&cartaDefinitions.SetCursor{FileId: 7})
	if id, ok := FileIdFromBytes(cartaDefinitions.EventType_SET_CURSOR, req); !ok || id != 7 {
		t.Fatalf("client message: got %d ok=%v", id, ok)
	}
	// A backend stream, which it did not.
	tile, _ := proto.Marshal(&cartaDefinitions.RasterTileData{FileId: 9})
	if id, ok := FileIdFromBytes(cartaDefinitions.EventType_RASTER_TILE_DATA, tile); !ok || id != 9 {
		t.Fatalf("backend message: got %d ok=%v", id, ok)
	}
	// A message that names no image.
	none, _ := proto.Marshal(&cartaDefinitions.RegisterViewer{SessionId: 1})
	if _, ok := FileIdFromBytes(cartaDefinitions.EventType_REGISTER_VIEWER, none); ok {
		t.Fatal("a message with no file id should report none")
	}
}

func TestRewriteFileId_PreservesTheRestOfTheMessage(t *testing.T) {
	in, _ := proto.Marshal(&cartaDefinitions.RasterTileData{FileId: 9, Channel: 3, Stokes: 1})

	out, err := RewriteFileId(cartaDefinitions.EventType_RASTER_TILE_DATA, in, 42)
	if err != nil {
		t.Fatalf("RewriteFileId: %v", err)
	}

	var tile cartaDefinitions.RasterTileData
	if err := proto.Unmarshal(out, &tile); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tile.FileId != 42 || tile.Channel != 3 || tile.Stokes != 1 {
		t.Fatalf("unexpected message %+v", &tile)
	}
}

func TestRewriteFileId_RefusesMessagesThatNameNoFile(t *testing.T) {
	in, _ := proto.Marshal(&cartaDefinitions.RegisterViewer{SessionId: 1})

	if _, err := RewriteFileId(cartaDefinitions.EventType_REGISTER_VIEWER, in, 42); err == nil {
		t.Fatal("expected an error for a message that names no file")
	}
}
