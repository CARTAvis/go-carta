package database

import (
	"database/sql"
	"errors"
	"time"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

// PurgeExpiredAuthSessions deletes device sessions that have expired or been
// revoked. Revoked sessions can never be used again, so they are removed along
// with expired ones to keep the table from growing without bound.
func (h *DbConfig) PurgeExpiredAuthSessions() error {
	_, err := h.db.Exec(`DELETE FROM auth_sessions WHERE expires_at < NOW() OR revoked`)
	return err
}

// CreateAuthSession records a device session for a key fingerprint, replacing
// any previous session for the same key (including a revoked one).
func (h *DbConfig) CreateAuthSession(session auth.AuthSession) error {
	_, err := h.db.Exec(
		`INSERT INTO auth_sessions
		   (key_fingerprint, client_public_key, username, source,
		    oidc_refresh_token, oidc_access_expiry, expires_at, last_request_ts)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (key_fingerprint) DO UPDATE
		 SET client_public_key  = EXCLUDED.client_public_key,
		     username           = EXCLUDED.username,
		     source             = EXCLUDED.source,
		     oidc_refresh_token = EXCLUDED.oidc_refresh_token,
		     oidc_access_expiry = EXCLUDED.oidc_access_expiry,
		     expires_at         = EXCLUDED.expires_at,
		     last_request_ts    = EXCLUDED.last_request_ts,
		     revoked            = FALSE,
		     last_used_at       = NULL,
		     created_at         = NOW()`,
		session.KeyFingerprint,
		session.ClientPublicKey,
		session.Username,
		string(auth.NormalizeSource(session.Source)),
		session.OIDCRefreshToken,
		session.OIDCAccessExpiry,
		session.ExpiresAt,
		session.LastRequestTS,
	)
	return err
}

// GetAuthSession loads a device session by key fingerprint, whether or not it
// has been revoked or has expired. It returns auth.ErrAuthSessionNotFound when
// there is no matching record.
func (h *DbConfig) GetAuthSession(keyFingerprint string) (*auth.AuthSessionRecord, error) {
	var row struct {
		KeyFingerprint   string         `db:"key_fingerprint"`
		ClientPublicKey  string         `db:"client_public_key"`
		Username         string         `db:"username"`
		Source           sql.NullString `db:"source"`
		ExpiresAt        time.Time      `db:"expires_at"`
		LastRequestTS    sql.NullInt64  `db:"last_request_ts"`
		Revoked          bool           `db:"revoked"`
		OIDCRefreshToken []byte         `db:"oidc_refresh_token"`
		OIDCAccessExpiry sql.NullTime   `db:"oidc_access_expiry"`
	}
	err := h.db.Get(
		&row,
		`SELECT key_fingerprint, client_public_key, username, source,
		        expires_at, last_request_ts, revoked,
		        oidc_refresh_token, oidc_access_expiry
		 FROM auth_sessions
		 WHERE key_fingerprint = $1`,
		keyFingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrAuthSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	source := auth.SourcePAM
	if row.Source.Valid && row.Source.String != "" {
		source = auth.NormalizeSource(auth.Source(row.Source.String))
	}

	record := &auth.AuthSessionRecord{
		KeyFingerprint:   row.KeyFingerprint,
		ClientPublicKey:  row.ClientPublicKey,
		Username:         row.Username,
		Source:           source,
		ExpiresAt:        row.ExpiresAt,
		Revoked:          row.Revoked,
		OIDCRefreshToken: row.OIDCRefreshToken,
	}
	if row.LastRequestTS.Valid {
		timestamp := row.LastRequestTS.Int64
		record.LastRequestTS = &timestamp
	}
	if row.OIDCAccessExpiry.Valid {
		expiry := row.OIDCAccessExpiry.Time
		record.OIDCAccessExpiry = &expiry
	}
	return record, nil
}

// UpdateAuthSessionOIDC updates the encrypted offline token and upstream
// access-token expiry for an existing OIDC device session.
func (h *DbConfig) UpdateAuthSessionOIDC(keyFingerprint string, encryptedOfflineToken []byte, accessExpiry time.Time) error {
	_, err := h.db.Exec(
		`UPDATE auth_sessions
		 SET oidc_refresh_token = $2, oidc_access_expiry = $3
		 WHERE key_fingerprint = $1`,
		keyFingerprint, encryptedOfflineToken, accessExpiry,
	)
	return err
}

// UseAuthSession records the timestamp of an accepted signed request when it
// is newer than the last one. It reports whether the session is still active
// and the timestamp was accepted.
func (h *DbConfig) UseAuthSession(keyFingerprint string, timestamp int64) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_sessions
		 SET last_request_ts = $2, last_used_at = NOW()
		 WHERE key_fingerprint = $1
		   AND revoked = FALSE
		   AND expires_at > NOW()
		   AND (last_request_ts IS NULL OR last_request_ts < $2)`,
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

// RevokeAuthSession marks an active session revoked when timestamp is newer
// than the last accepted signed request. It reports whether a session was
// actually revoked.
func (h *DbConfig) RevokeAuthSession(keyFingerprint string, timestamp int64) (bool, error) {
	res, err := h.db.Exec(
		`UPDATE auth_sessions
		 SET revoked = TRUE, last_request_ts = $2, last_used_at = NOW()
		 WHERE key_fingerprint = $1
		   AND revoked = FALSE
		   AND expires_at > NOW()
		   AND (last_request_ts IS NULL OR last_request_ts < $2)`,
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
