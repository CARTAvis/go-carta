package database

import (
	"database/sql"
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

// GetPendingAuth loads a pending device login by key fingerprint. It returns
// auth.ErrPendingAuthNotFound when there is no matching record.
func (h *DbConfig) GetPendingAuth(keyFingerprint string) (*auth.PendingAuthRecord, error) {
	var row struct {
		ClientPublicKey string         `db:"client_public_key"`
		ExpiresAt       time.Time      `db:"expires_at"`
		LastPollTS      sql.NullInt64  `db:"last_poll_ts"`
		Username        sql.NullString `db:"username"`
		Source          sql.NullString `db:"source"`
	}
	err := h.db.Get(
		&row,
		`SELECT client_public_key, expires_at, last_poll_ts, username, source
		 FROM auth_pending
		 WHERE key_fingerprint = $1`,
		keyFingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrPendingAuthNotFound
	}
	if err != nil {
		return nil, err
	}

	source := auth.Source("")
	if row.Source.Valid && row.Source.String != "" {
		source = auth.NormalizeSource(auth.Source(row.Source.String))
	}

	record := &auth.PendingAuthRecord{
		ClientPublicKey: row.ClientPublicKey,
		ExpiresAt:       row.ExpiresAt,
		Username:        row.Username.String,
		Source:          source,
	}
	if row.LastPollTS.Valid {
		timestamp := row.LastPollTS.Int64
		record.LastPollTS = &timestamp
	}
	return record, nil
}

// RecordPendingAuthPoll stores the client timestamp of an accepted poll. It
// reports whether the timestamp was stored: false means the record no longer
// exists or a newer poll was already recorded.
func (h *DbConfig) RecordPendingAuthPoll(keyFingerprint string, timestamp int64) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_pending
		 SET last_poll_ts = $2
		 WHERE key_fingerprint = $1
		   AND expires_at > NOW()
		   AND (last_poll_ts IS NULL OR last_poll_ts < $2)`,
		keyFingerprint, timestamp,
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

// ConsumePendingAuth deletes a linked, unexpired pending login and returns the
// username it was linked to. It reports false when the fingerprint is unknown,
// expired, or was already collected.
func (h *DbConfig) ConsumePendingAuth(keyFingerprint string) (string, bool, error) {
	var username string
	err := h.db.QueryRow(
		`DELETE FROM auth_pending
		 WHERE key_fingerprint = $1 AND username IS NOT NULL AND expires_at > NOW()
		 RETURNING username`,
		keyFingerprint,
	).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return username, true, nil
}

// LinkPendingAuth associates a pending device login with a user and records
// the authentication source. It reports whether a link was made: false means
// the fingerprint is unknown, expired, or was already linked.
func (h *DbConfig) LinkPendingAuth(keyFingerprint, username string, source auth.Source) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_pending
		 SET username = $2, linked_at = NOW(), source = $3
		 WHERE key_fingerprint = $1 AND expires_at > NOW() AND username IS NULL`,
		keyFingerprint, username, string(auth.NormalizeSource(source)),
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
