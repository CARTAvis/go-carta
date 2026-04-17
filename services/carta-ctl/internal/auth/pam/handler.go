package pam

import (
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

// loginAuthenticator captures only what the login handler needs,
// avoiding a package import cycle with pamwrap.
type loginAuthenticator interface {
	AuthenticateCredentials(ctx context.Context, username, password string) (*auth.User, error)
}

func NewLoginHandler(p loginAuthenticator, tmpl *template.Template) http.Handler {
	slog.Info("Setting up PAM login handler")

	type pageData struct {
		Title   string
		Heading string
		Error   string
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Handling PAM login request", "method", r.Method)

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := tmpl.Execute(w, pageData{
				Title:   "CARTA Login",
				Heading: "CARTA Login (PAM)",
			}); err != nil {
				slog.Error("Failed to render PAM login page", "error", err)
			}

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

			if err := auth.SetRefreshTokenCookie(w, user.Username); err != nil {
				slog.Error("Failed to set PAM session cookie", "username", user.Username, "error", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			for _, c := range w.Header()["Set-Cookie"] {
				slog.Info("Set-Cookie", "value", c)
			}

			slog.Info("Cookie set, redirecting", "to", "/")
			http.Redirect(w, r, "/", http.StatusFound)
			return

		default:
			slog.Warn("Ignoring unsupported method", "method", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	})
}
