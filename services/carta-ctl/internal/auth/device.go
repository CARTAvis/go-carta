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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CARTAvis/go-carta/pkg/config"
)

const (
	// DeviceVerifyPath is the page where the user confirms linking a device
	// code to their account after signing in.
	DeviceVerifyPath = "/device_link"

	// deviceLinkCookieName holds a short-lived token proving that the browser
	// user authenticated for a specific device login.
	deviceLinkCookieName = "carta_device_link"
	deviceLinkTicketAge  = 5 * time.Minute

	// deviceTimestampSkew is the maximum allowed difference between a client's
	// signed request timestamp and the server clock. Timestamps outside this
	// window are rejected so a mis-set client clock can neither bypass the poll
	// interval nor lock the client out of its own login, and so a captured
	// signed request has only a bounded replay window.
	deviceTimestampSkew = 5 * time.Minute
)

// ErrKeyAlreadyRegistered is returned when a public key already has a pending login.
var ErrKeyAlreadyRegistered = errors.New("public key already registered")

// ErrTooManyPendingAuths is returned when the number of outstanding pending
// device logins from a single client IP has reached the configured limit.
var ErrTooManyPendingAuths = errors.New("too many pending device logins from this address")

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

// ValidFingerprint reports whether a value has the shape of a key fingerprint.
// It is exported so other auth backends can validate a device code before
// carrying it through their own login flow.
func ValidFingerprint(code string) bool {
	return validFingerprint(code)
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
	// RequestIP is the client IP address recorded at device_init, used for
	// per-IP rate limiting. It is empty for rows created before this field was
	// introduced.
	RequestIP string
	// ExpiresAt is when the pending login stops being valid.
	ExpiresAt time.Time
	// LastPollTS is the server time (Unix seconds) of the last accepted poll, if
	// any. It is used to enforce the polling interval against the server clock,
	// never against the client-supplied timestamp.
	LastPollTS *int64
	// Username is empty until the login has been linked to a user account.
	Username string
	// Source is the authentication source used when the login was linked. It is
	// empty until linking, and older rows may leave it empty (treated as PAM).
	Source Source
	// OIDCRefreshToken and OIDCAccessExpiry are populated only for OIDC device
	// logins. The offline (refresh) token is stored encrypted (AES-GCM);
	// OIDCAccessExpiry is the expiry of the upstream access token issued with
	// it. Both are nil for PAM logins.
	OIDCRefreshToken []byte
	OIDCAccessExpiry *time.Time
}

// PendingAuthStore persists in-flight device logins.
type PendingAuthStore interface {
	// CreatePendingAuth stores a new pending device login, keyed by the fingerprint of the client's public key.
	// requestIP is the client IP address used for per-IP rate limiting; maxPendingPerIP caps the number of
	// outstanding pending logins allowed from that IP (<= 0 disables the limit).
	CreatePendingAuth(keyFingerprint, clientPublicKey, requestIP string, expiresAt time.Time, maxPendingPerIP int) error
	// GetPendingAuth loads a pending device login by key fingerprint, returning
	// ErrPendingAuthNotFound when there is no matching record.
	GetPendingAuth(keyFingerprint string) (*PendingAuthRecord, error)
	// LinkPendingAuth links an unexpired, unlinked login to a user and records
	// the authentication source, the encrypted offline token, and the upstream
	// access-token expiry in a single atomic operation so the token is bound to
	// the linking identity. oidcRefreshToken and oidcAccessExpiry are nil/zero
	// for PAM logins. It reports whether it did so.
	LinkPendingAuth(keyFingerprint, username string, source Source, oidcRefreshToken []byte, oidcAccessExpiry int64) (bool, error)
	// RecordPendingAuthPoll records the server time (Unix seconds) of an accepted
	// poll. It reports false when a newer server time was already recorded.
	RecordPendingAuthPoll(keyFingerprint string, pollAt int64) (bool, error)
	// ConsumePendingAuth deletes a linked, unexpired login and returns the
	// username it was linked to. It reports false when there is nothing to
	// collect, so exactly one polling client obtains the session.
	ConsumePendingAuth(keyFingerprint string) (string, bool, error)
}

// AuthSession describes a device session to persist. ExpiresAt is the hard
// deadline for the key registration: it is the configured maximum refresh
// interval for PAM, and is unchanged for OIDC (each issued access token is
// additionally capped at the upstream access-token expiry).
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
	// OIDCRefreshToken and OIDCAccessExpiry are populated only for OIDC device
	// sessions and are nil for PAM sessions. The offline (refresh) token is
	// stored encrypted (AES-GCM). OIDCAccessExpiry is the expiry of the most
	// recently retrieved upstream access token.
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
	// device sessions. The offline (refresh) token is stored encrypted;
	// OIDCAccessExpiry is the expiry of the most recently retrieved upstream
	// access token.
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
	// UpdateAuthSessionOIDC updates the encrypted offline token and upstream
	// access-token expiry for an existing OIDC device session.
	UpdateAuthSessionOIDC(keyFingerprint string, encryptedOfflineToken []byte, accessExpiry time.Time) error
	// UseAuthSession records the timestamp of an accepted signed request when
	// it is newer than the previous one. It reports whether it did so.
	UseAuthSession(keyFingerprint string, timestamp int64) (bool, error)
	// RevokeAuthSession marks an active session revoked when timestamp is newer
	// than the last accepted signed request. It reports whether it revoked.
	RevokeAuthSession(keyFingerprint string, timestamp int64) (bool, error)
}

// OIDCTokenRefresher issues a new upstream OIDC access token from a stored
// offline token. It is implemented by the OIDC integration and injected into
// the device-session handlers when OIDC device sessions are enabled. The
// encrypted offline token is opaque to this package.
type OIDCTokenRefresher interface {
	// RefreshAccessToken exchanges the encrypted offline token for a new
	// upstream access token. It returns the (re-encrypted) offline token and
	// the new access token's expiry.
	RefreshAccessToken(ctx context.Context, encryptedOfflineToken []byte) (newEncryptedOfflineToken []byte, accessTokenExpiry time.Time, err error)
}

// normalizeIP parses s as an IP address and returns its canonical string form.
// IPv4-mapped IPv6 addresses are un-mapped to their IPv4 form so a client
// always maps to the same key. When s is not a valid IP, it is returned
// trimmed and unchanged.
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().String()
	}
	return s
}

// clientIP returns the client IP address for a request. When headerName is
// non-empty and the named header is present, its first comma-separated value is
// used (for X-Forwarded-For style headers); otherwise the peer address from
// RemoteAddr is used.
func clientIP(r *http.Request, headerName string) string {
	if headerName != "" {
		if v := r.Header.Get(headerName); v != "" {
			if i := strings.IndexByte(v, ','); i >= 0 {
				v = v[:i]
			}
			return normalizeIP(v)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return normalizeIP(host)
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

// needsOIDCAccessRefresh reports whether the stored upstream OIDC access
// token would expire within the local access-token lifetime and should be
// refreshed before issuing a new access token. A nil or zero expiry means no
// upstream access token has been stored yet, so a refresh is required.
func needsOIDCAccessRefresh(now time.Time, accessExpiry *time.Time) bool {
	if accessExpiry == nil || accessExpiry.IsZero() {
		return true
	}
	return !accessExpiry.After(now.Add(accessTokenAgeDur))
}

// deviceAccessExpiry returns the expiry for a locally issued device access
// token, capped at the earlier of the session deadline and (for OIDC) the
// upstream access-token expiry. A nil or zero upstream expiry applies no cap.
func deviceAccessExpiry(now, sessionExpiresAt time.Time, upstreamAccessExpiry *time.Time) time.Time {
	expiry := now.Add(accessTokenAgeDur)
	if sessionExpiresAt.Before(expiry) {
		expiry = sessionExpiresAt
	}
	if upstreamAccessExpiry != nil && !upstreamAccessExpiry.IsZero() && upstreamAccessExpiry.Before(expiry) {
		expiry = *upstreamAccessExpiry
	}
	return expiry
}

// refreshOIDCAccessToken exchanges the stored offline token for a new
// upstream access token and returns the (re-encrypted) offline token and the
// new access-token expiry.
func refreshOIDCAccessToken(ctx context.Context, refresher OIDCTokenRefresher, encryptedOfflineToken []byte) ([]byte, *time.Time, error) {
	newEncrypted, newExpiry, err := refresher.RefreshAccessToken(ctx, encryptedOfflineToken)
	if err != nil {
		return nil, nil, err
	}
	return newEncrypted, &newExpiry, nil
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

	// The client timestamp must be within a bounded window of the server clock.
	// This prevents a mis-set clock from bypassing the poll interval or locking
	// the client out, and bounds the replay window for a captured signed request.
	if diff := time.Now().Unix() - req.Timestamp; diff > int64(deviceTimestampSkew/time.Second) || diff < -int64(deviceTimestampSkew/time.Second) {
		writeJSONError(w, http.StatusBadRequest, "timestamp is too far from the server clock")
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

	// Device verification links must be built from a configured, trusted base
	// URL. Deriving them from the request's Host header would let an attacker
	// poison the link, so public_url is required when device auth is enabled.
	publicURL := strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/")
	if publicURL == "" {
		return nil, fmt.Errorf("controller.device_auth.public_url must be set to enable device authorization")
	}
	u, err := url.Parse(publicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid controller.device_auth.public_url %q: must be an absolute http(s) URL", cfg.PublicURL)
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
		requestIP := clientIP(r, cfg.ClientIPHeader)

		if err := store.CreatePendingAuth(fingerprint, req.PublicKey, requestIP, time.Now().Add(lifetime), cfg.MaxPendingPerIP); err != nil {
			switch {
			case errors.Is(err, ErrKeyAlreadyRegistered):
				writeJSONError(w, http.StatusConflict, "This public key is already registered; generate a new keypair")
			case errors.Is(err, ErrTooManyPendingAuths):
				w.Header().Set("Retry-After", strconv.Itoa(minIntervalSecs))
				writeJSONError(w, http.StatusTooManyRequests, "Too many pending device logins from this address; try again later")
			default:
				slog.Error("Failed to create pending auth record", "err", err)
				writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			}
			return
		}

		base := publicURL

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
// be signed with the registered private key and carry a timestamp within a
// bounded window of the server clock (see deviceTimestampSkew). The polling
// interval is enforced against the server clock, not the client timestamp.
//
// For OIDC device sessions, the offline token stored with the pending login is
// used to obtain a fresh upstream access token when needed (see
// OIDCTokenRefresher); refresher may be nil when only PAM sessions are used.
//
// Responses:
//   - 202 Accepted: the login is still pending.
//   - 200 OK: the login was linked; an access token and the session expiry are returned.
//   - 429 Too Many Requests: the client polled again before the minimum interval.
//   - 410 Gone: the login is unknown, expired, or was already collected.
func DevicePollHandler(store PendingAuthStore, sessions AuthSessionStore, cfg config.DeviceAuthConfig, refresher OIDCTokenRefresher) (http.Handler, error) {
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
			writeJSONError(w, http.StatusGone, "This login is invalid, expired, or already used")
			return
		}

		if record.Username == "" {
			// Enforce the polling interval against the server clock, not the
			// client-supplied timestamp, so a client cannot shorten the interval
			// by advancing its own clock.
			nowUnix := time.Now().Unix()
			if record.LastPollTS != nil && nowUnix < *record.LastPollTS+int64(intervalSecs) {
				w.Header().Set("Retry-After", strconv.Itoa(intervalSecs))
				writeJSONError(w, http.StatusTooManyRequests, fmt.Sprintf("Polling too frequently; retry after %d seconds", intervalSecs))
				return
			}

			accepted, err := store.RecordPendingAuthPoll(req.KeyFingerprint, nowUnix)
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
		sessionExpiresAt := now.Add(maxRefreshInterval)

		// For OIDC device sessions, ensure the upstream access token is still
		// usable for the lifetime of the token being issued, refreshing it with
		// the stored offline token when necessary.
		oidcRefreshToken := record.OIDCRefreshToken
		oidcAccessExpiry := record.OIDCAccessExpiry
		if source == SourceOIDC && oidcRefreshToken != nil {
			if refresher == nil {
				slog.Error("OIDC device session has no token refresher", "key_fingerprint", req.KeyFingerprint)
				writeJSONError(w, http.StatusInternalServerError, "Internal server error")
				return
			}
			if needsOIDCAccessRefresh(now, oidcAccessExpiry) {
				oidcRefreshToken, oidcAccessExpiry, err = refreshOIDCAccessToken(r.Context(), refresher, oidcRefreshToken)
				if err != nil {
					slog.Error("Failed to refresh OIDC access token", "username", username, "err", err)
					writeJSONError(w, http.StatusInternalServerError, "Internal server error")
					return
				}
			}
		}

		accessExpiresAt := deviceAccessExpiry(now, sessionExpiresAt, oidcAccessExpiry)

		accessToken, err := GenerateToken(username, source, TokenTypeAccess, accessExpiresAt)
		if err != nil {
			slog.Error("Failed to generate device access token", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		// Record the session so access tokens can be refreshed and the session
		// revoked. OIDC device sessions carry the (encrypted) offline token and
		// the upstream access-token expiry.
		if err := sessions.CreateAuthSession(AuthSession{
			KeyFingerprint:   req.KeyFingerprint,
			ClientPublicKey:  record.ClientPublicKey,
			Username:         username,
			Source:           source,
			ExpiresAt:        sessionExpiresAt,
			LastRequestTS:    req.Timestamp,
			OIDCRefreshToken: oidcRefreshToken,
			OIDCAccessExpiry: oidcAccessExpiry,
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
// For OIDC device sessions, when the stored upstream access token would expire
// within the local access-token lifetime it is refreshed using the stored
// offline token (see OIDCTokenRefresher), and the returned access token's
// lifetime is capped at the earlier of the local lifetime and the upstream
// access token's expiry. refresher may be nil when only PAM sessions are used.
//
// Responses:
//   - 200 OK: a new access token and the remaining session lifetime.
//   - 400 Bad Request: the request is malformed.
//   - 401 Unauthorized: the session is revoked or has expired.
//   - 403 Forbidden: the signature is invalid.
//   - 409 Conflict: the signed timestamp is not newer than the previous one.
//   - 410 Gone: no session exists for the key fingerprint.
func DeviceRefreshHandler(sessions AuthSessionStore, refresher OIDCTokenRefresher) http.Handler {
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

		now := time.Now()

		// For OIDC device sessions, refresh the upstream access token with the
		// stored offline token when it would expire within the local lifetime.
		oidcAccessExpiry := record.OIDCAccessExpiry
		if record.OIDCRefreshToken != nil {
			if refresher == nil {
				slog.Error("OIDC device session has no token refresher", "key_fingerprint", req.KeyFingerprint)
				writeJSONError(w, http.StatusInternalServerError, "Internal server error")
				return
			}
			if needsOIDCAccessRefresh(now, oidcAccessExpiry) {
				newEncrypted, newExpiry, err := refreshOIDCAccessToken(r.Context(), refresher, record.OIDCRefreshToken)
				if err != nil {
					slog.Error("Failed to refresh OIDC access token", "username", record.Username, "err", err)
					writeJSONError(w, http.StatusInternalServerError, "Internal server error")
					return
				}
				if err := sessions.UpdateAuthSessionOIDC(req.KeyFingerprint, newEncrypted, *newExpiry); err != nil {
					slog.Error("Failed to persist refreshed OIDC session", "err", err)
					writeJSONError(w, http.StatusInternalServerError, "Internal server error")
					return
				}
				oidcAccessExpiry = newExpiry
			}
		}

		accessExpiresAt := deviceAccessExpiry(now, record.ExpiresAt, oidcAccessExpiry)

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

// SetDeviceLinkCookie records that the browser user authenticated for a
// specific device login. The signed token is bound to the device code and is
// accepted only by the device confirmation page. For OIDC device logins it also
// carries the encrypted offline token and its upstream access-token expiry
// (nil/zero for PAM) so they can be persisted together with the identity at
// link time.
func SetDeviceLinkCookie(w http.ResponseWriter, username string, source Source, deviceCode string, oidcRefreshToken []byte, oidcAccessExpiry int64) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if !validFingerprint(deviceCode) {
		return fmt.Errorf("invalid device code")
	}

	expiresAt := time.Now().Add(deviceLinkTicketAge)
	token, err := GenerateDeviceLinkToken(username, source, deviceCode, oidcRefreshToken, oidcAccessExpiry, expiresAt)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     deviceLinkCookieName,
		Value:    token,
		Path:     DeviceVerifyPath,
		Expires:  expiresAt,
		MaxAge:   int(deviceLinkTicketAge.Seconds()),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// clearDeviceLinkCookie removes the pending device-link ticket.
func clearDeviceLinkCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     deviceLinkCookieName,
		Value:    "",
		Path:     DeviceVerifyPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

// deviceLinkUser returns the authenticated user and the ticket claims from a
// device-link ticket when the ticket was issued for the given device code. The
// claims are returned so the caller can persist the ticket's OIDC offline token
// and expiry together with the linking identity.
func deviceLinkUser(r *http.Request, deviceCode string) (*User, *TokenClaims, bool) {
	cookie, err := r.Cookie(deviceLinkCookieName)
	if err != nil {
		return nil, nil, false
	}

	claims, err := VerifyToken(cookie.Value)
	if err != nil || claims.Type != TokenTypeDeviceLink || claims.DeviceCode != deviceCode || claims.Username == "" {
		return nil, nil, false
	}

	user := &User{
		Username: claims.Username,
		Source:   NormalizeSource(claims.Source),
		Claims:   map[string]any{},
	}
	return user, claims, true
}

// WriteDeviceLinkedPage renders the page shown after a device login has been
// linked to a user account.
func WriteDeviceLinkedPage(w http.ResponseWriter, username string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := deviceLinkedTmpl.Execute(w, map[string]string{"Username": username}); err != nil {
		slog.Error("Failed to render device linked page", "error", err)
	}
}
