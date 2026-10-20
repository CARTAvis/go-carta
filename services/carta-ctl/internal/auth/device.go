package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CARTAvis/go-carta/pkg/config"
)

const (
	// DeviceVerifyPath is the page where the user logs in and links the device code to their account.
	DeviceVerifyPath = "/device_link"
	// DeviceLinkAPIPath is where that page submits the credentials and device code.
	DeviceLinkAPIPath = "/api/auth/device_link"
)

// ErrKeyAlreadyRegistered is returned when a public key already has a pending login.
var ErrKeyAlreadyRegistered = errors.New("public key already registered")

// ErrPendingAuthNotFound is returned when no pending login matches a key fingerprint.
var ErrPendingAuthNotFound = errors.New("pending device login not found")

// ErrAuthSessionNotFound is returned when no device session matches a key fingerprint.
var ErrAuthSessionNotFound = errors.New("device session not found")

// fingerprintLen is the length of a base64url (unpadded) SHA-256 digest.
const fingerprintLen = 43

// KeyFingerprint returns the base64url SHA-256 of a raw Ed25519 public key.
func KeyFingerprint(rawPublicKey []byte) string {
	sum := sha256.Sum256(rawPublicKey)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// FingerprintPrefix is the short form shown to users to confirm they are linking the right device.
func FingerprintPrefix(fingerprint string) string {
	if len(fingerprint) < 8 {
		return fingerprint
	}
	return fingerprint[:8]
}

// validFingerprint checks that a value has the shape of a key fingerprint.
func validFingerprint(code string) bool {
	if len(code) != fingerprintLen {
		return false
	}
	for _, c := range code {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// deviceSignedMessage builds the canonical message a client signs for an
// action. The action prefix keeps signatures from being valid in any other
// context (poll, refresh, logout).
func deviceSignedMessage(action, keyFingerprint string, timestamp int64) []byte {
	return []byte(action + "\n" + keyFingerprint + "\n" + strconv.FormatInt(timestamp, 10))
}

// devicePollMessage is the canonical message a client signs when polling:
//
//	carta-device-poll\n<key_fingerprint>\n<timestamp>
func devicePollMessage(keyFingerprint string, timestamp int64) []byte {
	return deviceSignedMessage("carta-device-poll", keyFingerprint, timestamp)
}

// deviceRefreshMessage is the canonical message a client signs to refresh an
// access token:
//
//	carta-device-refresh\n<key_fingerprint>\n<timestamp>
func deviceRefreshMessage(keyFingerprint string, timestamp int64) []byte {
	return deviceSignedMessage("carta-device-refresh", keyFingerprint, timestamp)
}

// deviceLogoutMessage is the canonical message a client signs to revoke its session:
//
//	carta-device-logout\n<key_fingerprint>\n<timestamp>
func deviceLogoutMessage(keyFingerprint string, timestamp int64) []byte {
	return deviceSignedMessage("carta-device-logout", keyFingerprint, timestamp)
}

// PendingAuthRecord is a pending device login as stored by a PendingAuthStore.
type PendingAuthRecord struct {
	// ClientPublicKey is the base64url (unpadded) Ed25519 public key registered at device_init.
	ClientPublicKey string
	// ExpiresAt is when the pending login stops being valid.
	ExpiresAt time.Time
	// LastPollTS is the client timestamp of the last accepted poll, if any.
	LastPollTS *int64
	// Username is empty until the login has been linked to a user account.
	Username string
	// Source is the authentication source used when the login was linked. It is
	// empty until linking, and older rows may leave it empty (treated as PAM).
	Source Source
}

// PendingAuthStore persists in-flight device logins.
type PendingAuthStore interface {
	// PurgeExpiredPendingAuth removes pending records that have expired.
	PurgeExpiredPendingAuth() error
	// CreatePendingAuth stores a new pending device login, keyed by the fingerprint of the client's public key.
	CreatePendingAuth(keyFingerprint, clientPublicKey string, expiresAt time.Time) error
	// GetPendingAuth loads a pending device login by key fingerprint, returning
	// ErrPendingAuthNotFound when there is no matching record.
	GetPendingAuth(keyFingerprint string) (*PendingAuthRecord, error)
	// LinkPendingAuth links an unexpired, unlinked login to a user and records
	// the authentication source, reporting whether it did so.
	LinkPendingAuth(keyFingerprint, username string, source Source) (bool, error)
	// RecordPendingAuthPoll stores the client timestamp of an accepted poll.
	// It reports false when a newer poll timestamp was already recorded.
	RecordPendingAuthPoll(keyFingerprint string, timestamp int64) (bool, error)
	// ConsumePendingAuth deletes a linked, unexpired login and returns the
	// username it was linked to. It reports false when there is nothing to
	// collect, so exactly one polling client obtains the session.
	ConsumePendingAuth(keyFingerprint string) (string, bool, error)
}

// AuthSession describes a device session to persist. ExpiresAt is the hard
// deadline for the key registration: it is the configured maximum refresh
// interval for PAM, and will be capped at the OIDC offline-token expiry when
// OIDC device sessions are supported.
type AuthSession struct {
	KeyFingerprint  string
	ClientPublicKey string
	Username        string
	// Source is the authentication source that created the session.
	Source Source
	// ExpiresAt is the hard deadline for refreshing access tokens.
	ExpiresAt time.Time
	// LastRequestTS is the client timestamp of the preceding signed request.
	LastRequestTS int64
	// OIDCRefreshToken and OIDCAccessExpiry are reserved for OIDC device
	// sessions and are nil for PAM sessions. The refresh token must already be
	// encrypted (AES-GCM) by the OIDC integration. OIDCAccessExpiry caps ExpiresAt.
	OIDCRefreshToken []byte
	OIDCAccessExpiry *time.Time
}

// AuthSessionRecord is a device session as stored by an AuthSessionStore.
type AuthSessionRecord struct {
	// KeyFingerprint identifies the session and its registered public key.
	KeyFingerprint string
	// ClientPublicKey is the base64url (unpadded) Ed25519 public key that owns the session.
	ClientPublicKey string
	// Username is the account the session is linked to.
	Username string
	// Source is the authentication source that created the session.
	Source Source
	// ExpiresAt is the hard deadline for refreshing access tokens.
	ExpiresAt time.Time
	// LastRequestTS is the client timestamp of the last accepted signed request, if any.
	LastRequestTS *int64
	// Revoked reports whether the session has been logged out.
	Revoked bool
	// OIDCRefreshToken and OIDCAccessExpiry are populated only for OIDC
	// device sessions. The token is stored encrypted.
	OIDCRefreshToken []byte
	OIDCAccessExpiry *time.Time
}

// AuthSessionStore persists device sessions and their revocation state.
type AuthSessionStore interface {
	// CreateAuthSession records a session for a key fingerprint, replacing any
	// previous session for the same key (including a revoked one).
	CreateAuthSession(session AuthSession) error
	// GetAuthSession loads a device session by key fingerprint, whether or not
	// it has been revoked or has expired. It returns ErrAuthSessionNotFound
	// when there is no matching record.
	GetAuthSession(keyFingerprint string) (*AuthSessionRecord, error)
	// UseAuthSession records the timestamp of an accepted signed request when
	// it is newer than the previous one. It reports whether it did so.
	UseAuthSession(keyFingerprint string, timestamp int64) (bool, error)
	// RevokeAuthSession marks an active session revoked when timestamp is newer
	// than the last accepted signed request. It reports whether it revoked.
	RevokeAuthSession(keyFingerprint string, timestamp int64) (bool, error)
}

// CredentialAuthenticator verifies a username and password.
type CredentialAuthenticator interface {
	AuthenticateCredentials(ctx context.Context, username, password string) (*User, error)
}

// requestOrigin derives the origin from the request. Used only when no public URL is configured.
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status_code": status,
		"message":     message,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

// deviceSessionExpiry returns the hard deadline for a device session. For PAM
// the key registration lasts the configured maximum refresh interval. When
// OIDC device sessions are supported, oidcAccessExpiry will carry the
// provider's offline-token expiry and the earlier deadline wins.
func deviceSessionExpiry(now time.Time, maxRefreshInterval time.Duration, oidcAccessExpiry *time.Time) time.Time {
	expiresAt := now.Add(maxRefreshInterval)
	if oidcAccessExpiry != nil && oidcAccessExpiry.Before(expiresAt) {
		expiresAt = *oidcAccessExpiry
	}
	return expiresAt
}

// deviceSignedRequest is the JSON body shared by the poll, refresh and logout
// endpoints. The client signs the action-specific canonical message with the
// Ed25519 private key whose public key is registered for the session.
type deviceSignedRequest struct {
	KeyFingerprint string `json:"key_fingerprint"`
	Timestamp      int64  `json:"timestamp"`
	Signature      string `json:"signature"`
}

// readDeviceSignedRequest parses and validates a deviceSignedRequest. It writes
// an error response and returns ok=false when the request is invalid.
func readDeviceSignedRequest(w http.ResponseWriter, r *http.Request) (deviceSignedRequest, []byte, bool) {
	var req deviceSignedRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Request body must be JSON containing key_fingerprint, timestamp and signature")
		return req, nil, false
	}
	if !validFingerprint(req.KeyFingerprint) {
		writeJSONError(w, http.StatusBadRequest, "Missing or invalid key_fingerprint")
		return req, nil, false
	}
	if req.Timestamp <= 0 {
		writeJSONError(w, http.StatusBadRequest, "timestamp must be a positive Unix time in seconds")
		return req, nil, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		writeJSONError(w, http.StatusBadRequest, "signature must be a base64url (unpadded) Ed25519 signature")
		return req, nil, false
	}
	return req, signature, true
}

// verifyDeviceSignature checks a signature against a stored public key. It
// returns ok=false when the stored key is malformed (a server-side error).
func verifyDeviceSignature(storedPublicKey, keyFingerprint string, signature, message []byte) (valid, ok bool) {
	publicKey, err := base64.RawURLEncoding.DecodeString(storedPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || KeyFingerprint(publicKey) != keyFingerprint {
		return false, false
	}
	return ed25519.Verify(publicKey, message, signature), true
}

// DeviceInitHandler starts a device-style login flow. The client registers an
// Ed25519 public key; the base64url SHA-256 of that key (its fingerprint) identifies
// the pending login and is embedded in the verification URL the user opens in a browser.
func DeviceInitHandler(store PendingAuthStore, cfg config.DeviceAuthConfig) (http.Handler, error) {
	lifetime, err := time.ParseDuration(cfg.Lifetime)
	if err != nil || lifetime <= 0 {
		return nil, fmt.Errorf("invalid controller.device_auth.lifetime %q: must be a positive duration", cfg.Lifetime)
	}
	minInterval, err := time.ParseDuration(cfg.MinInterval)
	if err != nil || minInterval < time.Second {
		return nil, fmt.Errorf("invalid controller.device_auth.min_interval %q: must be a duration of at least 1s", cfg.MinInterval)
	}
	minIntervalSecs := int(minInterval.Seconds())

	publicURL := strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/")
	if publicURL != "" {
		u, err := url.Parse(publicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid controller.device_auth.public_url %q: must be an absolute http(s) URL", cfg.PublicURL)
		}
	} else {
		slog.Warn("controller.device_auth.public_url is not set; deriving device verification URLs from the request Host header")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// The client's Ed25519 public key is bound to this login up front, so only
		// the holder of the private key can later collect the session.
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var req struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "Request body must be JSON containing public_key")
			return
		}
		keyBytes, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
		if err != nil || len(keyBytes) != ed25519.PublicKeySize {
			writeJSONError(w, http.StatusBadRequest, "public_key must be a base64url (unpadded) Ed25519 public key")
			return
		}

		fingerprint := KeyFingerprint(keyBytes)

		// Purge stale records so unauthenticated calls can't grow the table forever.
		if err := store.PurgeExpiredPendingAuth(); err != nil {
			slog.Warn("Failed to purge expired pending auth records", "err", err)
		}

		if err := store.CreatePendingAuth(fingerprint, req.PublicKey, time.Now().Add(lifetime)); err != nil {
			if errors.Is(err, ErrKeyAlreadyRegistered) {
				writeJSONError(w, http.StatusConflict, "This public key is already registered; generate a new keypair")
				return
			}
			slog.Error("Failed to create pending auth record", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		base := publicURL
		if base == "" {
			base = requestOrigin(r)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		resp := map[string]any{
			"key_fingerprint":  fingerprint,
			"confirm_code":     FingerprintPrefix(fingerprint),
			"verification_uri": base + DeviceVerifyPath + "?code=" + url.QueryEscape(fingerprint),
			"expires_in":       int(lifetime.Seconds()),
			"interval":         minIntervalSecs,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("Error encoding device init response", "err", err)
		}
	}), nil
}

// DevicePollHandler lets the client that started a device login collect an
// access token once the user has linked it in the browser. Each request must
// be signed with the registered private key and carry a strictly increasing
// timestamp, which enforces the polling interval and prevents replay.
//
// Responses:
//   - 202 Accepted: the login is still pending.
//   - 200 OK: the login was linked; an access token and the session expiry are returned.
//   - 429 Too Many Requests: the client polled again before the minimum interval.
//   - 409 Conflict: the signed timestamp is not newer than the previous poll.
//   - 410 Gone: the login is unknown, expired, or was already collected.
func DevicePollHandler(store PendingAuthStore, sessions AuthSessionStore, cfg config.DeviceAuthConfig) (http.Handler, error) {
	minInterval, err := time.ParseDuration(cfg.MinInterval)
	if err != nil || minInterval < time.Second {
		return nil, fmt.Errorf("invalid controller.device_auth.min_interval %q: must be a duration of at least 1s", cfg.MinInterval)
	}
	intervalSecs := int(minInterval.Seconds())

	maxRefreshInterval, err := time.ParseDuration(cfg.MaxRefreshInterval)
	if err != nil || maxRefreshInterval <= 0 {
		return nil, fmt.Errorf("invalid controller.device_auth.max_refresh_interval %q: must be a positive duration", cfg.MaxRefreshInterval)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		req, signature, ok := readDeviceSignedRequest(w, r)
		if !ok {
			return
		}

		record, err := store.GetPendingAuth(req.KeyFingerprint)
		if errors.Is(err, ErrPendingAuthNotFound) {
			writeJSONError(w, http.StatusGone, "This login is invalid, expired, or already used")
			return
		}
		if err != nil {
			slog.Error("Failed to load pending auth record", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		// Only the holder of the private key registered at device_init can poll.
		valid, keyOK := verifyDeviceSignature(record.ClientPublicKey, req.KeyFingerprint, signature, devicePollMessage(req.KeyFingerprint, req.Timestamp))
		if !keyOK {
			slog.Error("Stored device public key is invalid", "key_fingerprint", req.KeyFingerprint)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !valid {
			writeJSONError(w, http.StatusForbidden, "Invalid signature")
			return
		}

		if !time.Now().Before(record.ExpiresAt) {
			if err := store.PurgeExpiredPendingAuth(); err != nil {
				slog.Warn("Failed to purge expired pending auth records", "err", err)
			}
			writeJSONError(w, http.StatusGone, "This login is invalid, expired, or already used")
			return
		}

		// The client timestamp enforces the polling interval and rejects replays.
		if record.LastPollTS != nil {
			if req.Timestamp <= *record.LastPollTS {
				writeJSONError(w, http.StatusConflict, "Poll timestamp is not newer than the previous poll")
				return
			}
			if req.Timestamp < *record.LastPollTS+int64(intervalSecs) {
				w.Header().Set("Retry-After", strconv.Itoa(intervalSecs))
				writeJSONError(w, http.StatusTooManyRequests, fmt.Sprintf("Polling too frequently; retry after %d seconds", intervalSecs))
				return
			}
		}

		if record.Username == "" {
			accepted, err := store.RecordPendingAuthPoll(req.KeyFingerprint, req.Timestamp)
			if err != nil {
				slog.Error("Failed to record device poll", "err", err)
				writeJSONError(w, http.StatusInternalServerError, "Internal server error")
				return
			}
			if !accepted {
				w.Header().Set("Retry-After", strconv.Itoa(intervalSecs))
				writeJSONError(w, http.StatusTooManyRequests, fmt.Sprintf("Polling too frequently; retry after %d seconds", intervalSecs))
				return
			}

			expiresIn := max(int(time.Until(record.ExpiresAt).Seconds()), 0)
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status":          "pending",
				"key_fingerprint": req.KeyFingerprint,
				"confirm_code":    FingerprintPrefix(req.KeyFingerprint),
				"interval":        intervalSecs,
				"expires_in":      expiresIn,
			})
			return
		}

		// The browser linked the login: consume it so exactly one poller
		// collects the session, then issue an access token for that user.
		username, collected, err := store.ConsumePendingAuth(req.KeyFingerprint)
		if err != nil {
			slog.Error("Failed to consume pending auth record", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !collected {
			writeJSONError(w, http.StatusGone, "This login is invalid, expired, or already used")
			return
		}

		source := record.Source
		if source == "" {
			// Rows linked before sources were recorded were PAM logins.
			source = SourcePAM
		}

		now := time.Now()
		sessionExpiresAt := deviceSessionExpiry(now, maxRefreshInterval, nil)
		accessExpiresAt := now.Add(accessTokenAgeDur)
		if sessionExpiresAt.Before(accessExpiresAt) {
			accessExpiresAt = sessionExpiresAt
		}

		accessToken, err := GenerateToken(username, source, TokenTypeAccess, accessExpiresAt)
		if err != nil {
			slog.Error("Failed to generate device access token", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		// Record the session so access tokens can be refreshed and the session
		// revoked. OIDC device sessions will pass the provider's refresh token
		// and offline-token expiry here; the expiry is capped in
		// deviceSessionExpiry.
		if err := sessions.CreateAuthSession(AuthSession{
			KeyFingerprint:  req.KeyFingerprint,
			ClientPublicKey: record.ClientPublicKey,
			Username:        username,
			Source:          source,
			ExpiresAt:       sessionExpiresAt,
			LastRequestTS:   req.Timestamp,
		}); err != nil {
			slog.Error("Failed to record device session", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		slog.Info("Device login completed", "username", username, "key_fingerprint", req.KeyFingerprint)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":             "linked",
			"key_fingerprint":    req.KeyFingerprint,
			"username":           username,
			"token_type":         "bearer",
			"access_token":       accessToken,
			"expires_in":         max(int(time.Until(accessExpiresAt).Seconds()), 0),
			"session_expires_in": max(int(time.Until(sessionExpiresAt).Seconds()), 0),
		})
	}), nil
}

// DeviceRefreshHandler issues a new access token to a client that holds a
// registered device key. The request is signed with that key, so no refresh
// token is needed. The key registration (session) has a hard expiry and cannot
// be extended by refreshing.
//
// Responses:
//   - 200 OK: a new access token and the remaining session lifetime.
//   - 400 Bad Request: the request is malformed.
//   - 401 Unauthorized: the session is revoked or has expired.
//   - 403 Forbidden: the signature is invalid.
//   - 409 Conflict: the signed timestamp is not newer than the previous one.
//   - 410 Gone: no session exists for the key fingerprint.
func DeviceRefreshHandler(sessions AuthSessionStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		req, signature, ok := readDeviceSignedRequest(w, r)
		if !ok {
			return
		}

		record, err := sessions.GetAuthSession(req.KeyFingerprint)
		if errors.Is(err, ErrAuthSessionNotFound) {
			writeJSONError(w, http.StatusGone, "This session is invalid or has already been revoked")
			return
		}
		if err != nil {
			slog.Error("Failed to load device session", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		valid, keyOK := verifyDeviceSignature(record.ClientPublicKey, req.KeyFingerprint, signature, deviceRefreshMessage(req.KeyFingerprint, req.Timestamp))
		if !keyOK {
			slog.Error("Stored device public key is invalid", "key_fingerprint", req.KeyFingerprint)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !valid {
			writeJSONError(w, http.StatusForbidden, "Invalid signature")
			return
		}

		if record.Revoked || !time.Now().Before(record.ExpiresAt) {
			writeJSONError(w, http.StatusUnauthorized, "This session has expired or been revoked; log in again")
			return
		}

		if record.LastRequestTS != nil && req.Timestamp <= *record.LastRequestTS {
			writeJSONError(w, http.StatusConflict, "Request timestamp is not newer than the previous signed request")
			return
		}

		used, err := sessions.UseAuthSession(req.KeyFingerprint, req.Timestamp)
		if err != nil {
			slog.Error("Failed to record device refresh", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !used {
			writeJSONError(w, http.StatusUnauthorized, "This session has expired or been revoked; log in again")
			return
		}

		source := record.Source
		if source == "" {
			// Sessions created before sources were recorded were PAM logins.
			source = SourcePAM
		}

		accessExpiresAt := time.Now().Add(accessTokenAgeDur)
		if record.ExpiresAt.Before(accessExpiresAt) {
			accessExpiresAt = record.ExpiresAt
		}

		accessToken, err := GenerateToken(record.Username, source, TokenTypeAccess, accessExpiresAt)
		if err != nil {
			slog.Error("Failed to generate device access token", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		slog.Debug("Device access token refreshed", "username", record.Username, "key_fingerprint", req.KeyFingerprint)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":       accessToken,
			"token_type":         "bearer",
			"expires_in":         max(int(time.Until(accessExpiresAt).Seconds()), 0),
			"session_expires_in": max(int(time.Until(record.ExpiresAt).Seconds()), 0),
			"username":           record.Username,
		})
	})
}

// DeviceLogoutHandler revokes the device session associated with a key
// fingerprint. Like polling, the request must be signed with the registered
// Ed25519 private key and carry a timestamp newer than the last accepted
// signed request, so a captured logout request cannot be replayed.
//
// Responses:
//   - 200 OK: the session is revoked (or was already revoked or expired).
//   - 400 Bad Request: the request is malformed.
//   - 403 Forbidden: the signature is invalid.
//   - 409 Conflict: the signed timestamp is not newer than the previous one.
//   - 410 Gone: no session exists for the key fingerprint.
func DeviceLogoutHandler(sessions AuthSessionStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		req, signature, ok := readDeviceSignedRequest(w, r)
		if !ok {
			return
		}

		record, err := sessions.GetAuthSession(req.KeyFingerprint)
		if errors.Is(err, ErrAuthSessionNotFound) {
			writeJSONError(w, http.StatusGone, "This session is invalid or has already been revoked")
			return
		}
		if err != nil {
			slog.Error("Failed to load device session", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		// Only the holder of the private key that owns the session can revoke it.
		valid, keyOK := verifyDeviceSignature(record.ClientPublicKey, req.KeyFingerprint, signature, deviceLogoutMessage(req.KeyFingerprint, req.Timestamp))
		if !keyOK {
			slog.Error("Stored device public key is invalid", "key_fingerprint", req.KeyFingerprint)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !valid {
			writeJSONError(w, http.StatusForbidden, "Invalid signature")
			return
		}

		// Revoking an already inactive session is idempotent.
		if record.Revoked || !time.Now().Before(record.ExpiresAt) {
			writeJSON(w, http.StatusOK, map[string]any{
				"status":          "revoked",
				"key_fingerprint": req.KeyFingerprint,
				"username":        record.Username,
			})
			return
		}

		if record.LastRequestTS != nil && req.Timestamp <= *record.LastRequestTS {
			writeJSONError(w, http.StatusConflict, "Request timestamp is not newer than the previous signed request")
			return
		}

		revoked, err := sessions.RevokeAuthSession(req.KeyFingerprint, req.Timestamp)
		if err != nil {
			slog.Error("Failed to revoke device session", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !revoked {
			// The session may have been revoked by a concurrent request or
			// expired between the checks above; either way it is unusable now.
			slog.Warn("Device session was already inactive when revoking", "key_fingerprint", req.KeyFingerprint)
		} else {
			slog.Info("Device session revoked", "username", record.Username, "key_fingerprint", req.KeyFingerprint)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":          "revoked",
			"key_fingerprint": req.KeyFingerprint,
			"username":        record.Username,
		})
	})
}

func redirectToDeviceLinkWithError(w http.ResponseWriter, r *http.Request, code, message string) {
	v := url.Values{}
	v.Set("code", code)
	v.Set("error", message)
	http.Redirect(w, r, DeviceVerifyPath+"?"+v.Encode(), http.StatusSeeOther)
}

// DeviceLinkHandler handles the submission of the /device_link page: it
// authenticates the user's credentials and links the device code to them.
// The linked session is later collected by the polling client.
func DeviceLinkHandler(store PendingAuthStore, authenticator CredentialAuthenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		if authenticator == nil {
			writeJSONError(w, http.StatusNotImplemented, "Credential login is not enabled")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		code := r.PostForm.Get("code")
		if !validFingerprint(code) {
			writeJSONError(w, http.StatusBadRequest, "Missing or invalid code")
			return
		}

		if r.PostForm.Get("confirm") != "yes" {
			redirectToDeviceLinkWithError(w, r, code, "Please confirm that the code matches the one shown in your terminal")
			return
		}

		username := r.PostForm.Get("username")
		password := r.PostForm.Get("password")
		if username == "" || password == "" {
			redirectToDeviceLinkWithError(w, r, code, "Please enter both username and password")
			return
		}

		user, err := authenticator.AuthenticateCredentials(r.Context(), username, password)
		if err != nil {
			slog.Warn("Device link login failed", "username", username, "error", err)
			redirectToDeviceLinkWithError(w, r, code, "Invalid username or password")
			return
		}

		linked, err := store.LinkPendingAuth(code, user.Username, user.Source)
		if err != nil {
			slog.Error("Failed to link login", "username", user.Username, "error", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !linked {
			redirectToDeviceLinkWithError(w, r, code, "This login code is invalid, expired, or already used")
			return
		}

		slog.Info("Linked device login to user", "username", user.Username)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := deviceLinkedTmpl.Execute(w, map[string]string{"Username": user.Username}); err != nil {
			slog.Error("Failed to render device linked page", "error", err)
		}
	})
}
