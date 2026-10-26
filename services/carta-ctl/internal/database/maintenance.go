package database

import (
	"context"
	"log/slog"
	"time"
)

// RunAuthMaintenance purges expired pending device logins and expired/revoked
// device sessions on independent schedules until ctx is cancelled. It blocks,
// so callers typically start it with `go`.
func (h *DbConfig) RunAuthMaintenance(ctx context.Context, pendingInterval, sessionInterval time.Duration) {
	pending := time.NewTicker(pendingInterval)
	sessions := time.NewTicker(sessionInterval)
	defer pending.Stop()
	defer sessions.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping auth maintenance")
			return
		case <-pending.C:
			if err := h.PurgeExpiredPendingAuth(); err != nil {
				slog.Warn("Failed to purge expired pending device logins", "err", err)
			}
		case <-sessions.C:
			if err := h.PurgeExpiredAuthSessions(); err != nil {
				slog.Warn("Failed to purge expired device sessions", "err", err)
			}
		}
	}
}
