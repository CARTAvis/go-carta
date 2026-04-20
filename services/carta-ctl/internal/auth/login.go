package auth

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
)

//go:embed templates/*.html
var templates embed.FS

var loginTmpl = template.Must(
	template.ParseFS(templates, "templates/pam_login.html"),
)

func LoginPageHandler() http.Handler {
	type pageData struct {
		Title   string
		Heading string
		Error   string
		Action  string
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		action := "/pam-login"
		if redirectParams := r.URL.Query().Get("redirectParams"); redirectParams != "" {
			action = "/pam-login?redirectParams=" + url.QueryEscape(redirectParams)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := loginTmpl.Execute(w, pageData{
			Title:   "CARTA Login",
			Heading: "CARTA Login",
			Action:  action,
		}); err != nil {
			slog.Error("Failed to render login page", "error", err)
		}
	})
}
