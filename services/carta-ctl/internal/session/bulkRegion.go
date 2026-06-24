package session

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/cartaHelpers"
)

// bulkAckTimeout bounds how long the controller waits for all per-file
// SET_REGION_ACKs before flushing a partial BULK_SET_REGION_ACK.
const bulkAckTimeout = 10 * time.Second

// handleBulkSetRegion splits a BULK_SET_REGION into per-file SET_REGION requests
// issued through the per-worker request layer, then gathers the acks into a
// single BULK_SET_REGION_ACK for the client.
func (s *Session) handleBulkSetRegion(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.BulkSetRegion
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing bulk set region: %v", err)
	}
	setRegions := payload.GetSetRegions()
	if len(setRegions) == 0 {
		return fmt.Errorf("bulk set region contained no regions")
	}

	ctx, cancel := context.WithTimeout(s.Context, bulkAckTimeout)
	defer cancel()

	type pending struct {
		fileId   int32
		regionId int32
		ch       <-chan WorkerMessage
	}
	var pendings []pending
	var acks []*cartaDefinitions.SetRegionAck

	for _, sr := range setRegions {
		worker, ok := s.getFileWorker(sr.GetFileId())
		if !ok || worker == nil {
			acks = append(acks, &cartaDefinitions.SetRegionAck{
				Success:  false,
				Message:  fmt.Sprintf("no backend for file_id=%d", sr.GetFileId()),
				RegionId: sr.GetRegionId(),
				FileId:   sr.GetFileId(),
			})
			continue
		}
		ch, cancel, err := worker.Request(ctx, cartaDefinitions.EventType_SET_REGION, sr)
		if err != nil {
			acks = append(acks, &cartaDefinitions.SetRegionAck{
				Success:  false,
				Message:  fmt.Sprintf("failed to dispatch to backend: %v", err),
				RegionId: sr.GetRegionId(),
				FileId:   sr.GetFileId(),
			})
			continue
		}
		defer cancel()
		pendings = append(pendings, pending{fileId: sr.GetFileId(), regionId: sr.GetRegionId(), ch: ch})
	}

	for _, p := range pendings {
		wm, ok := <-p.ch
		if !ok {
			acks = append(acks, &cartaDefinitions.SetRegionAck{
				Success:  false,
				Message:  fmt.Sprintf("timed out waiting for backend (file_id=%d, region_id=%d)", p.fileId, p.regionId),
				RegionId: p.regionId,
				FileId:   p.fileId,
			})
			continue
		}
		var ack cartaDefinitions.SetRegionAck
		if err := proto.Unmarshal(wm.Payload, &ack); err != nil {
			slog.Error("Failed to unmarshal set region ack", "error", err, "fileId", p.fileId)
			acks = append(acks, &cartaDefinitions.SetRegionAck{
				Success:  false,
				Message:  "malformed ack from backend",
				RegionId: p.regionId,
				FileId:   p.fileId,
			})
			continue
		}
		ack.FileId = p.fileId // tag from worker context (backend may leave it unset)
		acks = append(acks, &ack)
	}

	out, err := cartaHelpers.PrepareMessagePayload(
		&cartaDefinitions.BulkSetRegionAck{Acks: acks},
		cartaDefinitions.EventType_BULK_SET_REGION_ACK,
		requestId,
	)
	if err != nil {
		return fmt.Errorf("failed to marshal bulk set region ack: %v", err)
	}
	s.sendToClient(out)
	return nil
}

// handleBulkRemoveRegion splits a BULK_REMOVE_REGION into per-file REMOVE_REGION
// messages routed to each worker. REMOVE_REGION has no ack, so this is
// fire-and-forget.
func (s *Session) handleBulkRemoveRegion(_ cartaDefinitions.EventType, requestId uint32, msg []byte) error {
	var payload cartaDefinitions.BulkRemoveRegion
	if err := s.checkAndParse(&payload, requestId, msg); err != nil {
		return fmt.Errorf("error parsing bulk remove region: %v", err)
	}
	removals := payload.GetRemoveRegions()
	if len(removals) == 0 {
		return fmt.Errorf("bulk remove region contained no regions")
	}

	var firstErr error
	for _, rr := range removals {
		worker, ok := s.getFileWorker(rr.GetFileId())
		if !ok || worker == nil {
			slog.Warn("No backend for file_id; skipping region removal", "fileId", rr.GetFileId(), "regionId", rr.GetRegionId())
			continue
		}
		if err := worker.proxyMessageToWorker(rr, cartaDefinitions.EventType_REMOVE_REGION, requestId); err != nil {
			slog.Error("Failed to fan out remove region", "fileId", rr.GetFileId(), "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
