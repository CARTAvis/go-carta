package auth

import (
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/CARTAvis/go-carta/pkg/config"
	"github.com/microcosm-cc/bluemonday"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed static/carta_logo.svg
var cartaLogoSVG []byte

var loginTmpl = template.Must(
	template.ParseFS(templates, "templates/login.html"),
)

var deviceLinkedTmpl = template.Must(
	template.ParseFS(templates, "templates/device_linked.html"),
)

var deviceLinkTmpl = template.Must(
	template.ParseFS(templates, "templates/device_link.html"),
)

var supportTextPolicy = func() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	p.RequireParseableURLs(true)
	p.AllowURLSchemes("https", "mailto")
	return p
}()

func sanitizeSupportText(raw string) template.HTML {
	if raw == "" {
		return ""
	}

	return template.HTML(supportTextPolicy.Sanitize(raw))
}

// loginAction builds a login endpoint URL, carrying the optional redirect
// parameters and device code through the auth flow.
func loginAction(base, redirectParams, deviceCode string) string {
	query := url.Values{}
	if redirectParams != "" {
		query.Set("redirectParams", redirectParams)
	}
	if deviceCode != "" {
		query.Set("device_code", deviceCode)
	}
	if len(query) == 0 {
		return base
	}
	return base + "?" + query.Encode()
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

// DeviceLinkPageData holds the data for the post-authentication device
// confirmation page.
type DeviceLinkPageData struct {
	Title       string
	Code        string
	ConfirmCode string
	Username    string
	Action      string
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

		deviceCode := r.URL.Query().Get("device_code")
		if deviceCode != "" && !validFingerprint(deviceCode) {
			http.Error(w, "Invalid device code", http.StatusBadRequest)
			return
		}

		pamAction := loginAction("/api/auth/pam_login", r.URL.Query().Get("redirectParams"), deviceCode)
		oidcAction := loginAction("/api/auth/oidc_login", r.URL.Query().Get("redirectParams"), deviceCode)

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
			Error:       r.URL.Query().Get("error"),
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

// DeviceLinkPageHandler renders the post-authentication device confirmation
// page. The user signs in through the normal login page first; the login
// handlers then issue a short-lived device-link ticket and redirect here. On
// confirmation the pending device login is linked to the authenticated user.
func DeviceLinkPageHandler(store PendingAuthStore, cfg *config.Config) http.Handler {
	title := cfg.Controller.LoginPage.Title
	if title == "" {
		title = "CARTA"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		code := r.URL.Query().Get("code")
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			if submitted := r.PostForm.Get("code"); submitted != "" {
				code = submitted
			}
		}
		if !validFingerprint(code) {
			http.Error(w, "Missing or invalid device code", http.StatusBadRequest)
			return
		}

		record, err := store.GetPendingAuth(code)
		if errors.Is(err, ErrPendingAuthNotFound) {
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

		user, claims, ok := deviceLinkUser(r, code)
		if !ok {
			clearDeviceLinkCookie(w)
			query := url.Values{}
			query.Set("device_code", code)
			http.Redirect(w, r, "/login?"+query.Encode(), http.StatusSeeOther)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if r.Method == http.MethodPost {
			// Write the identity and the (encrypted) OIDC offline token together
			// so the token is bound to the user who linked the login.
			linked, err := store.LinkPendingAuth(code, user.Username, user.Source, claims.OIDCRefreshToken, claims.OIDCAccessExpiry)
			if err != nil {
				slog.Error("Failed to link device login", "username", user.Username, "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !linked {
				clearDeviceLinkCookie(w)
				http.Error(w, "This device code is invalid, expired, or already used", http.StatusGone)
				return
			}

			clearDeviceLinkCookie(w)
			slog.Info("Linked device login to user", "username", user.Username)
			WriteDeviceLinkedPage(w, user.Username)
			return
		}

		data := DeviceLinkPageData{
			Title:       title,
			Code:        code,
			ConfirmCode: FingerprintPrefix(code),
			Username:    user.Username,
			Action:      DeviceVerifyPath,
			Error:       r.URL.Query().Get("error"),
		}
		if err := deviceLinkTmpl.Execute(w, data); err != nil {
			slog.Error("Failed to render device link page", "error", err)
		}
	})
}
