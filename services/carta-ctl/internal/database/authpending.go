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
// It returns auth.ErrKeyAlreadyRegistered if that key is already pending, and
// auth.ErrTooManyPendingAuths if maxPendingPerIP is positive and there are
// already that many unexpired pending logins from requestIP.
//
// The count check and insert run in a single transaction guarded by a per-IP
// advisory lock so concurrent requests from the same IP cannot both pass the
// check and exceed the cap.
func (h *DbConfig) CreatePendingAuth(keyFingerprint, clientPublicKey, requestIP string, expiresAt time.Time, maxPendingPerIP int) error {
	tx, err := h.db.Beginx()
	if err != nil {
		return err
	}
	defer func() {
		// Rollback is a no-op after a successful commit (sql.ErrTxDone).
		_ = tx.Rollback()
	}()

	// Serialize device-init for this IP so the count check and insert are atomic.
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, requestIP); err != nil {
		return err
	}

	if maxPendingPerIP > 0 {
		var count int
		if err := tx.Get(&count,
			`SELECT count(*) FROM auth_pending WHERE request_ip = $1 AND expires_at > NOW()`,
			requestIP,
		); err != nil {
			return err
		}
		if count >= maxPendingPerIP {
			return auth.ErrTooManyPendingAuths
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO auth_pending (key_fingerprint, client_public_key, request_ip, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		keyFingerprint, clientPublicKey, requestIP, expiresAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return auth.ErrKeyAlreadyRegistered
		}
		return err
	}

	return tx.Commit()
}

// GetPendingAuth loads a pending device login by key fingerprint. It returns
// auth.ErrPendingAuthNotFound when there is no matching record.
func (h *DbConfig) GetPendingAuth(keyFingerprint string) (*auth.PendingAuthRecord, error) {
	var row struct {
		ClientPublicKey  string         `db:"client_public_key"`
		RequestIP        string         `db:"request_ip"`
		ExpiresAt        time.Time      `db:"expires_at"`
		LastPollTS       sql.NullInt64  `db:"last_poll_ts"`
		ApprovedAt       sql.NullTime   `db:"approved_at"`
		Username         sql.NullString `db:"username"`
		Source           sql.NullString `db:"source"`
		OIDCRefreshToken []byte         `db:"oidc_refresh_token"`
		OIDCAccessExpiry sql.NullTime   `db:"oidc_access_expiry"`
	}
	err := h.db.Get(
		&row,
		`SELECT client_public_key, request_ip, expires_at, last_poll_ts, approved_at,
		        username, source, oidc_refresh_token, oidc_access_expiry
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
		ClientPublicKey:  row.ClientPublicKey,
		RequestIP:        row.RequestIP,
		ExpiresAt:        row.ExpiresAt,
		Username:         row.Username.String,
		Source:           source,
		OIDCRefreshToken: row.OIDCRefreshToken,
	}
	if row.LastPollTS.Valid {
		timestamp := row.LastPollTS.Int64
		record.LastPollTS = &timestamp
	}
	if row.ApprovedAt.Valid {
		approvedAt := row.ApprovedAt.Time
		record.ApprovedAt = &approvedAt
	}
	if row.OIDCAccessExpiry.Valid {
		expiry := row.OIDCAccessExpiry.Time
		record.OIDCAccessExpiry = &expiry
	}
	return record, nil
}

// RecordPendingAuthPoll records the server time (Unix seconds) of an accepted
// poll. It reports whether the time was stored: false means the record no
// longer exists or a newer poll was already recorded.
func (h *DbConfig) RecordPendingAuthPoll(keyFingerprint string, pollAt int64) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_pending
		 SET last_poll_ts = $2
		 WHERE key_fingerprint = $1
		   AND expires_at > NOW()
		   AND (last_poll_ts IS NULL OR last_poll_ts < $2)`,
		keyFingerprint, pollAt,
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

// ApprovePendingAuth records that the browser user verified the key
// fingerprint shown on the device-link page. It reports false when the login is
// unknown, expired, or already linked. Approving an already-approved login is
// idempotent.
func (h *DbConfig) ApprovePendingAuth(keyFingerprint string) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_pending
		 SET approved_at = COALESCE(approved_at, NOW())
		 WHERE key_fingerprint = $1 AND expires_at > NOW() AND username IS NULL`,
		keyFingerprint,
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

// LinkPendingAuth associates an approved pending device login with a user and
// records the authentication source, the encrypted offline token, and the
// upstream access-token expiry in a single atomic UPDATE so the token is bound
// to the identity that links it. oidcRefreshToken/oidcAccessExpiry are nil/zero
// for PAM logins, in which case those columns are written as NULL. It reports
// whether a link was made: false means the fingerprint is unknown, expired,
// unapproved, or was already linked.
func (h *DbConfig) LinkPendingAuth(keyFingerprint, username string, source auth.Source, oidcRefreshToken []byte, oidcAccessExpiry int64) (bool, error) {
	// A nil/zero token writes NULL; otherwise pass the concrete value so the
	// driver emits a proper BYTEA/TIMESTAMPTZ.
	var refreshToken any
	if oidcRefreshToken != nil {
		refreshToken = oidcRefreshToken
	}
	var accessExpiry any
	if oidcAccessExpiry > 0 {
		accessExpiry = time.Unix(oidcAccessExpiry, 0)
	}

	res, err := h.db.Exec(
		`UPDATE auth_pending
		 SET username = $2, linked_at = NOW(), source = $3,
		     oidc_refresh_token = $4, oidc_access_expiry = $5
		 WHERE key_fingerprint = $1 AND expires_at > NOW() AND username IS NULL
		   AND approved_at IS NOT NULL`,
		keyFingerprint, username, string(auth.NormalizeSource(source)), refreshToken, accessExpiry,
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
