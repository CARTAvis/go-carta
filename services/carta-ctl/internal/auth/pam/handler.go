package pam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

// loginAuthenticator captures only what the login handler needs,
// avoiding a package import cycle with pamwrap.
type loginAuthenticator interface {
	AuthenticateCredentials(ctx context.Context, username, password string) (*auth.User, error)
}

// deviceLinkStore captures the pending-login operations needed to approve and
// link a device login. It is nil when device authorization is disabled.
type deviceLinkStore interface {
	GetPendingAuth(keyFingerprint string) (*auth.PendingAuthRecord, error)
	LinkPendingAuth(keyFingerprint, username string, source auth.Source, oidcRefreshToken []byte, oidcAccessExpiry int64) (bool, error)
}

func redirectToLoginWithError(w http.ResponseWriter, r *http.Request, message string) {
	v := url.Values{}
	if redirectParams := r.URL.Query().Get("redirectParams"); redirectParams != "" {
		v.Set("redirectParams", redirectParams)
	}
	if deviceCode := r.URL.Query().Get("device_code"); deviceCode != "" {
		v.Set("device_code", deviceCode)
	}
	v.Set("error", message)
	http.Redirect(w, r, "/login?"+v.Encode(), http.StatusFound)
}

func NewLoginHandler(p loginAuthenticator, devices deviceLinkStore) http.Handler {
	slog.Info("Setting up PAM login handler")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Handling PAM login request", "method", r.Method)

		switch r.Method {
		case http.MethodPost:
			defer func() { _ = r.Body.Close() }()
			if err := r.ParseForm(); err != nil {
				redirectToLoginWithError(w, r, "Invalid login request")
				return
			}

			// A device login may only be completed after the user has seen and
			// approved the key fingerprint. This check runs before credentials
			// are accepted so a crafted login URL cannot skip that step.
			deviceCode := r.URL.Query().Get("device_code")
			if deviceCode != "" {
				if !auth.ValidFingerprint(deviceCode) {
					redirectToLoginWithError(w, r, "Invalid device login request")
					return
				}
				if devices == nil {
					http.Error(w, "Device login is not enabled", http.StatusBadRequest)
					return
				}
				record, err := devices.GetPendingAuth(deviceCode)
				if errors.Is(err, auth.ErrPendingAuthNotFound) {
					http.Error(w, "This device code is invalid, expired, or already used", http.StatusGone)
					return
				}
				if err != nil {
					slog.Error("Failed to load pending device login", "error", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				if record.Username != "" || !time.Now().Before(record.ExpiresAt) {
					http.Error(w, "This device code is invalid, expired, or already used", http.StatusGone)
					return
				}
				if record.ApprovedAt == nil {
					v := url.Values{}
					v.Set("code", deviceCode)
					http.Redirect(w, r, auth.DeviceVerifyPath+"?"+v.Encode(), http.StatusSeeOther)
					return
				}
			}

			username := r.Form.Get("username")
			password := r.Form.Get("password")

			if username == "" || password == "" {
				redirectToLoginWithError(w, r, "Please enter both username and password")
				return
			}

			user, err := p.AuthenticateCredentials(r.Context(), username, password)
			if err != nil {
				slog.Error("PAM login failed", "username", username, "error", err)
				redirectToLoginWithError(w, r, "Invalid username or password")
				return
			}

			if deviceCode != "" {
				// Link the device login directly now that the user has
				// authenticated; there is no second confirmation page.
				linked, err := devices.LinkPendingAuth(deviceCode, user.Username, user.Source, nil, 0)
				if err != nil {
					slog.Error("Failed to link device login", "username", user.Username, "error", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				if !linked {
					http.Error(w, "This device code is invalid, expired, or already used", http.StatusGone)
					return
				}

				slog.Info("Linked device login to user", "username", user.Username, "source", user.Source)
				auth.WriteDeviceLinkedPage(w, user.Username)
				return
			}

			slog.Info("About to set PAM session cookie", "username", user.Username)

			if err := auth.SetRefreshTokenCookie(w, user.Username, auth.SourcePAM); err != nil {
				slog.Error("Failed to set PAM session cookie", "username", user.Username, "error", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			if cookieCount := len(w.Header()["Set-Cookie"]); cookieCount > 0 {
				slog.Info("Set-Cookie headers set", "count", cookieCount)
			}

			redirectURL := "/"
			if r.URL.RawQuery != "" {
				redirectURL = "/?" + r.URL.RawQuery
			}

			slog.Info("Cookie set, redirecting", "to", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return

		default:
			slog.Warn("Ignoring unsupported method", "method", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	})
}
