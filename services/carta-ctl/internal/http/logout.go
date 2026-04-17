package cthttp

import (
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/CARTAvis/go-carta/pkg/config"
)

func LogoutHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear the refresh token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/api/auth/refresh",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		})

		// Clear any stored OIDC logout cookies
		for _, name := range []string{"oidc_id_token", "oidc_logout_endpoint"} {
			http.SetCookie(w, &http.Cookie{
				Name:     name,
				Value:    "",
				Path:     "/logout",
				MaxAge:   -1,
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
				Secure:   false,
				SameSite: http.SameSiteLaxMode,
			})
		}

		// If OIDC ID token and logout endpoint cookies exist, redirect through provider's logout endpoint
		idTokenCookie, idTokenErr := r.Cookie("oidc_id_token")
		logoutEndpointCookie, endpointErr := r.Cookie("oidc_logout_endpoint")
		if idTokenErr == nil && endpointErr == nil && idTokenCookie.Value != "" && logoutEndpointCookie.Value != "" {
			logoutURL := buildOIDCLogoutURL(logoutEndpointCookie.Value, idTokenCookie.Value, cfg.Controller.OIDC.AppURL)
			http.Redirect(w, r, logoutURL, http.StatusFound)
			return
		}

		// Default: redirect to login page
		loginAddr := "/login"
		switch cfg.Controller.AuthMode {
		case config.AuthPAM:
			loginAddr = "/pam-login"
		case config.AuthOIDC:
			loginAddr = "/oidc/login"
		case config.AuthBoth:
			loginAddr = "/login"
		}
		http.Redirect(w, r, loginAddr, http.StatusFound)
	}
}

func buildOIDCLogoutURL(logoutEndpoint, idTokenHint, postLogoutRedirectURI string) string {
	u, err := url.Parse(logoutEndpoint)
	if err != nil {
		return logoutEndpoint
	}
	q := u.Query()
	q.Set("id_token_hint", idTokenHint)
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	} else {
		slog.Warn("OIDC app_url not configured, logout will not redirect to login page after logout")
	}
	u.RawQuery = q.Encode()
	return u.String()
}
