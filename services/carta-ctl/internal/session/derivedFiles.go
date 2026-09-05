package session

import (
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// derivedFileIds returns the ids of images a backend has opened on its own
// while answering a request, such as moment maps, PV images and fitting
// results. The frontend addresses them by these ids from then on.
func derivedFileIds(eventType cartaDefinitions.EventType, payload []byte) []int32 {
	var acks []*cartaDefinitions.OpenFileAck
	switch eventType {
	case cartaDefinitions.EventType_MOMENT_RESPONSE:
		var m cartaDefinitions.MomentResponse
		if proto.Unmarshal(payload, &m) != nil {
			return nil
		}
		acks = m.GetOpenFileAcks()
	case cartaDefinitions.EventType_PV_RESPONSE:
		var m cartaDefinitions.PvResponse
		if proto.Unmarshal(payload, &m) != nil {
			return nil
		}
		acks = []*cartaDefinitions.OpenFileAck{m.GetOpenFileAck()}
	case cartaDefinitions.EventType_FITTING_RESPONSE:
		var m cartaDefinitions.FittingResponse
		if proto.Unmarshal(payload, &m) != nil {
			return nil
		}
		acks = []*cartaDefinitions.OpenFileAck{m.GetModelImage(), m.GetResidualImage()}
	default:
		return nil
	}

	var ids []int32
	for _, ack := range acks {
		if ack.GetSuccess() {
			ids = append(ids, ack.GetFileId())
		}
	}
	return ids
}

// registerDerivedFiles routes the images a backend opened while answering a
// request to that backend.
func (sw *SessionWorker) registerDerivedFiles(eventType cartaDefinitions.EventType, payload []byte) {
	if sw.fileRequest == nil {
		return
	}
	for _, fileId := range derivedFileIds(eventType, payload) {
		if !sw.owner.addFileAlias(fileId, sw) {
			slog.Error("Backend-generated file id is already in use by another backend", "fileId", fileId, "workerName", sw.name)
			sw.owner.sendErrorToClient(fmt.Sprintf(
				"The backend numbered a generated image %d, which is already open on another backend. Close some images and try again.", fileId))
			continue
		}
		slog.Info("Backend opened a derived image", "fileId", fileId, "workerName", sw.name)
	}
}
