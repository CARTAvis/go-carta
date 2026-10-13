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

// LinkPendingAuth associates a pending device login with a user. It reports
// whether a link was made: false means the code is unknown, expired, or was
// already linked.
func (h *DbConfig) LinkPendingAuth(deviceCode, username string) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_pending
		 SET username = $2, linked_at = NOW()
		 WHERE device_code = $1 AND expires_at > NOW() AND username IS NULL`,
		deviceCode, username,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
