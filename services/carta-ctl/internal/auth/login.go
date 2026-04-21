package auth

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/CARTAvis/go-carta/pkg/config"
	xhtml "golang.org/x/net/html"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed static/carta_logo.svg
var cartaLogoSVG []byte

var loginTmpl = template.Must(
	template.ParseFS(templates, "templates/login.html"),
)

func sanitizeSupportText(raw string) template.HTML {
	if raw == "" {
		return ""
	}

	var b strings.Builder
	z := xhtml.NewTokenizer(strings.NewReader(raw))

	for {
		tt := z.Next()
		switch tt {
		case xhtml.ErrorToken:
			return template.HTML(b.String())
		case xhtml.TextToken:
			b.WriteString(template.HTMLEscapeString(string(z.Text())))
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			tok := z.Token()
			if tok.Data != "a" {
				continue
			}

			href := ""
			title := ""
			for _, attr := range tok.Attr {
				switch attr.Key {
				case "href":
					href = attr.Val
				case "title":
					title = attr.Val
				}
			}

			if !isAllowedAnchorHref(href) {
				continue
			}

			b.WriteString("<a href=\"")
			b.WriteString(template.HTMLEscapeString(href))
			b.WriteString("\"")
			if title != "" {
				b.WriteString(" title=\"")
				b.WriteString(template.HTMLEscapeString(title))
				b.WriteString("\"")
			}
			b.WriteString(">")
		case xhtml.EndTagToken:
			tok := z.Token()
			if tok.Data == "a" {
				b.WriteString("</a>")
			}
		}
	}
}

func isAllowedAnchorHref(href string) bool {
	href = strings.TrimSpace(href)
	if href == "" {
		return false
	}

	u, err := url.Parse(href)
	if err != nil {
		return false
	}

	if u.IsAbs() {
		scheme := strings.ToLower(u.Scheme)
		return scheme == "http" || scheme == "https" || scheme == "mailto"
	}

	// Allow relative links only when rooted to avoid ambiguous pseudo-protocol patterns.
	return strings.HasPrefix(href, "/")
}

// LoginPageData holds all the data needed to render the login page.
type LoginPageData struct {
	Title       string
	WelcomeText string
	SupportText template.HTML
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
			SupportText: sanitizeSupportText(lp.SupportText),
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
