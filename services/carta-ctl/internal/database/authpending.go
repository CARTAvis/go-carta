package database

import (
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

// PurgeExpiredPendingAuth deletes pending device logins that have expired.
func (h *DbConfig) PurgeExpiredPendingAuth() error {
	_, err := h.db.Exec(`DELETE FROM auth_pending WHERE expires_at < NOW()`)
	return err
}

// CreatePendingAuth inserts a new pending device login keyed by the public key fingerprint.
// It returns auth.ErrKeyAlreadyRegistered if that key is already pending.
func (h *DbConfig) CreatePendingAuth(keyFingerprint, clientPublicKey string, expiresAt time.Time) error {
	_, err := h.db.Exec(
		`INSERT INTO auth_pending (key_fingerprint, client_public_key, expires_at)
		 VALUES ($1, $2, $3)`,
		keyFingerprint, clientPublicKey, expiresAt,
	)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return auth.ErrKeyAlreadyRegistered
	}
	return err
}

// LinkPendingAuth associates a pending device login with a user. It reports
// whether a link was made: false means the fingerprint is unknown, expired, or
// was already linked.
func (h *DbConfig) LinkPendingAuth(keyFingerprint, username string) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_pending
		 SET username = $2, linked_at = NOW()
		 WHERE key_fingerprint = $1 AND expires_at > NOW() AND username IS NULL`,
		keyFingerprint, username,
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
