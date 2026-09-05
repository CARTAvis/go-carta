package session

import (
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

// derivedFileIdBase is where the controller starts numbering images a backend
// opened on its own. It sits far above the ids a frontend allocates, so the
// two never meet in a log or a bug report.
const derivedFileIdBase = 1 << 20

// derivedAcks returns the open-file acknowledgements a backend response
// carries for images it opened while answering a request, along with a
// function that re-encodes the response once they have been rewritten.
func derivedAcks(eventType cartaDefinitions.EventType, payload []byte) ([]*cartaDefinitions.OpenFileAck, func() ([]byte, error)) {
	switch eventType {
	case cartaDefinitions.EventType_MOMENT_RESPONSE:
		var m cartaDefinitions.MomentResponse
		if proto.Unmarshal(payload, &m) != nil {
			return nil, nil
		}
		return m.GetOpenFileAcks(), func() ([]byte, error) { return proto.Marshal(&m) }
	case cartaDefinitions.EventType_PV_RESPONSE:
		var m cartaDefinitions.PvResponse
		if proto.Unmarshal(payload, &m) != nil {
			return nil, nil
		}
		return []*cartaDefinitions.OpenFileAck{m.GetOpenFileAck()}, func() ([]byte, error) { return proto.Marshal(&m) }
	case cartaDefinitions.EventType_FITTING_RESPONSE:
		var m cartaDefinitions.FittingResponse
		if proto.Unmarshal(payload, &m) != nil {
			return nil, nil
		}
		return []*cartaDefinitions.OpenFileAck{m.GetModelImage(), m.GetResidualImage()}, func() ([]byte, error) { return proto.Marshal(&m) }
	case cartaDefinitions.EventType_CONCAT_STOKES_FILES_ACK:
		var m cartaDefinitions.ConcatStokesFilesAck
		if proto.Unmarshal(payload, &m) != nil {
			return nil, nil
		}
		return []*cartaDefinitions.OpenFileAck{m.GetOpenFileAck()}, func() ([]byte, error) { return proto.Marshal(&m) }
	case cartaDefinitions.EventType_REMOTE_FILE_RESPONSE:
		var m cartaDefinitions.RemoteFileResponse
		if proto.Unmarshal(payload, &m) != nil {
			return nil, nil
		}
		return []*cartaDefinitions.OpenFileAck{m.GetOpenFileAck()}, func() ([]byte, error) { return proto.Marshal(&m) }
	default:
		return nil, nil
	}
}

// adoptDerivedFiles gives every image the backend opened on its own a
// controller-allocated id, routes that id back to this backend, and returns
// the response re-encoded with the new ids. It returns nil when the response
// opens no images, in which case the original is forwarded unchanged.
func (sw *SessionWorker) adoptDerivedFiles(eventType cartaDefinitions.EventType, payload []byte, requestId uint32) []byte {
	if sw.fileRequest == nil {
		return nil
	}
	acks, reencode := derivedAcks(eventType, payload)
	if reencode == nil {
		return nil
	}

	adopted := false
	for _, ack := range acks {
		if !ack.GetSuccess() {
			continue
		}
		backendFileId := ack.GetFileId()
		fileId := sw.owner.nextDerivedFileId()
		if !sw.owner.addFileAlias(fileId, sw) {
			continue
		}
		sw.mapDerivedFile(fileId, backendFileId)
		cartaHelpers.SetFileId(ack, fileId)
		adopted = true
		slog.Info("Backend opened an image of its own", "fileId", fileId, "backendFileId", backendFileId, "workerName", sw.name)
	}
	if !adopted {
		return nil
	}

	out, err := reencode()
	if err != nil {
		slog.Error("Failed to re-encode a response opening new images", "eventType", eventType, "workerName", sw.name, "error", err)
		return nil
	}
	framed, err := cartaHelpers.PrepareMessagePayloadBytes(out, eventType, requestId)
	if err != nil {
		slog.Error("Failed to frame a response opening new images", "eventType", eventType, "workerName", sw.name, "error", err)
		return nil
	}
	return framed
}
