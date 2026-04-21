package pam

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

// loginAuthenticator captures only what the login handler needs,
// avoiding a package import cycle with pamwrap.
type loginAuthenticator interface {
	AuthenticateCredentials(ctx context.Context, username, password string) (*auth.User, error)
}

func NewLoginHandler(p loginAuthenticator) http.Handler {
	slog.Info("Setting up PAM login handler")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Handling PAM login request", "method", r.Method)

		switch r.Method {
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "Bad form"}); err != nil {
					slog.Error("Failed to encode bad form response", "error", err)
				}
				return
			}

			username := r.Form.Get("username")
			password := r.Form.Get("password")

			if username == "" || password == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "Missing username or password"}); err != nil {
					slog.Error("Failed to encode missing credentials response", "error", err)
				}
				return
			}

			user, err := p.AuthenticateCredentials(r.Context(), username, password)
			if err != nil {
				slog.Error("PAM login failed", "username", username, "error", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				if err := json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"}); err != nil {
					slog.Error("Failed to encode invalid credentials response", "error", err)
				}
				return
			}
			slog.Info("About to set PAM session cookie", "username", user.Username)

			if err := auth.SetRefreshTokenCookie(w, user.Username, auth.SourcePAM); err != nil {
				slog.Error("Failed to set PAM session cookie", "username", user.Username, "error", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			for _, c := range w.Header()["Set-Cookie"] {
				slog.Info("Set-Cookie", "value", c)
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
