package pam

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

// loginAuthenticator captures only what the login handler needs,
// avoiding a package import cycle with pamwrap.
type loginAuthenticator interface {
	AuthenticateCredentials(ctx context.Context, username, password string) (*auth.User, error)
}

func redirectToLoginWithError(w http.ResponseWriter, r *http.Request, message string) {
	v := url.Values{}
	if redirectParams := r.URL.Query().Get("redirectParams"); redirectParams != "" {
		v.Set("redirectParams", redirectParams)
	}
	v.Set("error", message)
	http.Redirect(w, r, "/login?"+v.Encode(), http.StatusFound)
}

func NewLoginHandler(p loginAuthenticator) http.Handler {
	slog.Info("Setting up PAM login handler")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Handling PAM login request", "method", r.Method)

		switch r.Method {
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				redirectToLoginWithError(w, r, "Invalid login request")
				return
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
