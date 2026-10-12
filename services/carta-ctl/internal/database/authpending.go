package database

import "time"

// PurgeExpiredPendingAuth deletes pending device logins that have expired.
func (h *DbConfig) PurgeExpiredPendingAuth() error {
	_, err := h.db.Exec(`DELETE FROM auth_pending WHERE expires_at < NOW()`)
	return err
}

// CreatePendingAuth inserts a new pending device login.
func (h *DbConfig) CreatePendingAuth(pollHandle, deviceCode string, expiresAt time.Time, minIntervalSecs int) error {
	_, err := h.db.Exec(
		`INSERT INTO auth_pending (poll_handle, device_code, expires_at, min_interval_secs)
		 VALUES ($1, $2, $3, $4)`,
		pollHandle, deviceCode, expiresAt, minIntervalSecs,
	)
	return err
}
