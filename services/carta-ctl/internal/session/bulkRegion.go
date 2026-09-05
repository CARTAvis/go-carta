package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

// bulkAckTimeout bounds how long a BULK_SET_REGION waits for its backends.
const bulkAckTimeout = 10 * time.Second

// pendingSetRegion is one entry of a BULK_SET_REGION awaiting its ack.
type pendingSetRegion struct {
	index int
	req   *pendingRequest
}

// relabelRegionForBackend returns a copy of a bulk entry naming the id its
// backend knows the image by, or the entry unchanged when no translation
// applies.
func relabelRegionForBackend[T proto.Message](worker *SessionWorker, entry T) T {
	fileId, ok := cartaHelpers.ExtractFileId(entry)
	if !ok {
		return entry
	}
	backendFileId, ok := worker.backendFileId(fileId)
	if !ok {
		return entry
	}
	relabelled, _ := proto.Clone(entry).(T)
	cartaHelpers.SetFileId(relabelled, backendFileId)
	return relabelled
}

func failedSetRegionAck(sr *cartaDefinitions.SetRegion, msg string) *cartaDefinitions.SetRegionAck {
	return &cartaDefinitions.SetRegionAck{Success: false, Message: msg, RegionId: sr.GetRegionId(), FileId: sr.GetFileId()}
}

// handleBulkSetRegion sends one SET_REGION per file to the backend serving it
// and gathers the acks, in request order, into a single BULK_SET_REGION_ACK.
func (s *Session) handleBulkSetRegion(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.BulkSetRegion
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing bulk set region: %v", err)
	}
	setRegions := payload.GetSetRegions()
	acks := make([]*cartaDefinitions.SetRegionAck, len(setRegions))

	var pendings []pendingSetRegion

	for i, sr := range setRegions {
		worker := s.workerForFile(sr.GetFileId())
		if worker == nil {
			acks[i] = failedSetRegionAck(sr, fmt.Sprintf("no backend for file_id=%d", sr.GetFileId()))
			continue
		}
		sr = relabelRegionForBackend(worker, sr)
		// The backend does not acknowledge preview regions, so the entry is
		// forwarded under a controller id, which swallows any stray reply, and
		// reported as delivered rather than applied.
		if sr.GetPreviewRegion() {
			if err := worker.proxyMessageToWorker(sr, cartaDefinitions.EventType_SET_REGION, worker.nextRequestId()); err != nil {
				acks[i] = failedSetRegionAck(sr, fmt.Sprintf("failed to dispatch to backend: %v", err))
			} else {
				acks[i] = &cartaDefinitions.SetRegionAck{Success: true, RegionId: sr.GetRegionId(), FileId: sr.GetFileId(), Message: "preview region forwarded without acknowledgement"}
			}
			continue
		}
		req, err := worker.Request(cartaDefinitions.EventType_SET_REGION, sr)
		if err != nil {
			acks[i] = failedSetRegionAck(sr, fmt.Sprintf("failed to dispatch to backend: %v", err))
			continue
		}
		pendings = append(pendings, pendingSetRegion{index: i, req: req})
	}

	// The dispatch above is ordered with the rest of the session's messages;
	// waiting for the backends is not, so it runs on its own.
	go s.gatherBulkSetRegionAcks(setRegions, acks, pendings, requestId)
	return nil
}

func (s *Session) gatherBulkSetRegionAcks(setRegions []*cartaDefinitions.SetRegion, acks []*cartaDefinitions.SetRegionAck, pendings []pendingSetRegion, requestId uint32) {
	ctx, cancel := context.WithTimeout(s.Context, bulkAckTimeout)
	defer cancel()

	for _, p := range pendings {
		sr := setRegions[p.index]
		select {
		case wm, ok := <-p.req.Response():
			acks[p.index] = parseSetRegionAck(sr, wm, ok)
		case <-ctx.Done():
			if s.closed() {
				return
			}
			if p.req.Forget() {
				slog.Warn("Timed out waiting for backend", "eventType", cartaDefinitions.EventType_SET_REGION, "fileId", sr.GetFileId(), "regionId", sr.GetRegionId())
				acks[p.index] = failedSetRegionAck(sr, "timed out waiting for backend")
				continue
			}
			// The response was claimed just as the deadline passed and is on its way.
			wm, ok := <-p.req.Response()
			acks[p.index] = parseSetRegionAck(sr, wm, ok)
		}
	}

	s.sendAckToClient(&cartaDefinitions.BulkSetRegionAck{Acks: acks}, cartaDefinitions.EventType_BULK_SET_REGION_ACK, requestId)
}

func parseSetRegionAck(sr *cartaDefinitions.SetRegion, wm WorkerMessage, ok bool) *cartaDefinitions.SetRegionAck {
	if !ok {
		return failedSetRegionAck(sr, "backend connection lost")
	}
	if wm.EventType != cartaDefinitions.EventType_SET_REGION_ACK {
		return failedSetRegionAck(sr, fmt.Sprintf("unexpected %v from backend", wm.EventType))
	}
	var ack cartaDefinitions.SetRegionAck
	if err := proto.Unmarshal(wm.Payload, &ack); err != nil {
		return failedSetRegionAck(sr, "malformed ack from backend")
	}
	ack.FileId = sr.GetFileId()
	return &ack
}

// handleBulkRemoveRegion sends one REMOVE_REGION per file to the backend
// serving it. REMOVE_REGION has no ack.
func (s *Session) handleBulkRemoveRegion(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.BulkRemoveRegion
	if err := s.parse(&payload, msg); err != nil {
		return fmt.Errorf("error parsing bulk remove region: %v", err)
	}

	var errs []error
	for _, rr := range payload.GetRemoveRegions() {
		worker := s.workerForFile(rr.GetFileId())
		if worker == nil {
			errs = append(errs, fmt.Errorf("no backend for file_id=%d", rr.GetFileId()))
			continue
		}
		rr = relabelRegionForBackend(worker, rr)
		if err := worker.proxyMessageToWorker(rr, cartaDefinitions.EventType_REMOVE_REGION, requestId); err != nil {
			errs = append(errs, fmt.Errorf("file_id=%d: %w", rr.GetFileId(), err))
		}
	}
	return errors.Join(errs...)
}
