package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

// validDeviceCode checks that a device code looks like one we generate (base64url, bounded length).
func validDeviceCode(code string) bool {
	if len(code) == 0 || len(code) > 64 {
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
	// CreatePendingAuth stores a new pending device login.
	CreatePendingAuth(pollHandle, deviceCode string, expiresAt time.Time, minIntervalSecs int) error
	// LinkPendingAuth links an unexpired, unlinked device code to a user, reporting whether it did so.
	LinkPendingAuth(deviceCode, username string) (bool, error)
}

// CredentialAuthenticator verifies a username and password.
type CredentialAuthenticator interface {
	AuthenticateCredentials(ctx context.Context, username, password string) (*User, error)
}

// randomToken returns a URL-safe random string with n bytes of entropy.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
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

// DeviceInitHandler starts a device-style login flow. It creates a pending
// record and returns a secret poll_handle (kept by the client) and a device_code
// (embedded in the verification URL the user opens in a browser).
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

		pollHandle, err := randomToken(32)
		if err != nil {
			slog.Error("Failed to generate poll handle", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		deviceCode, err := randomToken(24)
		if err != nil {
			slog.Error("Failed to generate device code", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		// Purge stale records so unauthenticated calls can't grow the table forever.
		if err := store.PurgeExpiredPendingAuth(); err != nil {
			slog.Warn("Failed to purge expired pending auth records", "err", err)
		}

		if err := store.CreatePendingAuth(pollHandle, deviceCode, time.Now().Add(lifetime), minIntervalSecs); err != nil {
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
			"poll_handle":      pollHandle,
			"device_code":      deviceCode,
			"verification_uri": base + DeviceVerifyPath + "?code=" + url.QueryEscape(deviceCode),
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

// DevicePollHandler is a placeholder for the endpoint clients poll with their poll_handle.
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

		code := r.PostForm.Get("device_code")
		if !validDeviceCode(code) {
			writeJSONError(w, http.StatusBadRequest, "Missing or invalid device code")
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
			slog.Error("Failed to link device code", "username", user.Username, "error", err)
			writeJSONError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if !linked {
			redirectToDeviceLinkWithError(w, r, code, "This device code is invalid, expired, or already used")
			return
		}

		slog.Info("Linked device code to user", "username", user.Username)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := deviceLinkedTmpl.Execute(w, map[string]string{"Username": user.Username}); err != nil {
			slog.Error("Failed to render device linked page", "error", err)
		}
	})
}
