package auth

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/CARTAvis/go-carta/pkg/config"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed static/carta_logo.svg
var cartaLogoSVG []byte

var loginTmpl = template.Must(
	template.New("login.html").Funcs(template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
	}).ParseFS(templates, "templates/login.html"),
)

// LoginPageData holds all the data needed to render the login page.
type LoginPageData struct {
	Title       string
	WelcomeText string
	SupportText string
	HasBanner   bool
	BannerURL   string
	ShowPAM     bool
	ShowOIDC    bool
	PAMAction   string
	OIDCAction  string
	Error       string
}

// LoginPageHandler returns an http.Handler that renders the unified login page.
// Elements specific to PAM and OIDC are included only when those auth modes are active.
func LoginPageHandler(cfg *config.Config) http.Handler {
	authMode := cfg.Controller.AuthMode
	lp := cfg.Controller.LoginPage

	showPAM := authMode == config.AuthPAM || authMode == config.AuthBoth
	showOIDC := authMode == config.AuthOIDC || authMode == config.AuthBoth

	hasBanner := false
	if lp.SiteBanner != "" {
		if _, err := os.Stat(lp.SiteBanner); err == nil {
			hasBanner = true
		} else {
			slog.Warn("Site banner file not found", "path", lp.SiteBanner)
		}
	}

	title := lp.Title
	if title == "" {
		title = "CARTA"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		pamAction := "/api/auth/pam_login"
		oidcAction := "/api/auth/oidc_login"
		if rp := r.URL.Query().Get("redirectParams"); rp != "" {
			escaped := url.QueryEscape(rp)
			pamAction += "?redirectParams=" + escaped
			oidcAction += "?redirectParams=" + escaped
		}

		data := LoginPageData{
			Title:       title,
			WelcomeText: lp.WelcomeText,
			SupportText: lp.SupportText,
			HasBanner:   hasBanner,
			BannerURL:   "/login/banner",
			ShowPAM:     showPAM,
			ShowOIDC:    showOIDC,
			PAMAction:   pamAction,
			OIDCAction:  oidcAction,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := loginTmpl.Execute(w, data); err != nil {
			slog.Error("Failed to render login page", "error", err)
		}
	})
}

// ServeCartaLogo returns a handler that serves the embedded CARTA logo SVG.
func ServeCartaLogo() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if _, err := w.Write(cartaLogoSVG); err != nil {
			slog.Error("Failed to serve CARTA logo", "error", err)
		}
	})
}

// ServeSiteBanner returns a handler that serves the site banner from the filesystem.
func ServeSiteBanner(path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, path)
	})
}
