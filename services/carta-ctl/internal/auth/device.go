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

// PendingAuthStore persists in-flight device logins.
type PendingAuthStore interface {
	// PurgeExpiredPendingAuth removes pending records that have expired.
	PurgeExpiredPendingAuth() error
	// CreatePendingAuth stores a new pending device login, keyed by the fingerprint of the client's public key.
	CreatePendingAuth(keyFingerprint, clientPublicKey string, expiresAt time.Time) error
	// LinkPendingAuth links an unexpired, unlinked login to a user, reporting whether it did so.
	LinkPendingAuth(keyFingerprint, username string) (bool, error)
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

func notImplementedHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Warn("Device auth endpoint called but not implemented", "endpoint", name, "method", r.Method)
		writeJSONError(w, http.StatusNotImplemented, name+" is not implemented yet")
	})
}

// DevicePollHandler is a placeholder for the endpoint clients poll, signing with their registered key.
func DevicePollHandler() http.Handler { return notImplementedHandler("device_poll") }

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

		linked, err := store.LinkPendingAuth(code, user.Username)
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
