package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/spf13/pflag"

	"github.com/CARTAvis/go-carta/pkg/config"
	helpers "github.com/CARTAvis/go-carta/pkg/shared"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/session"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
	authoidc "github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth/oidc"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth/pamwrap"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/database"

	"encoding/json"
)

var (
	runtimeSpawnerAddress string
	pamAuth               pamwrap.Authenticator
)

var upgrader = websocket.Upgrader{
	// Ignore Origin header
	CheckOrigin: func(r *http.Request) bool {
		slog.Debug("Upgrading WebSocket connection", "origin", r.Header.Get("Origin"))
		return true
	},
}

// spaHandler serves static files if they exist, otherwise falls back to index.html
type spaHandler struct {
	root string
	fs   http.Handler
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// We can create a sub-logger for this handler from the default handler
	logger := slog.With("service", "spaHandler")
	// If this is a WebSocket upgrade (e.g. ws://localhost:8081), hand it to wsHandler
	logger.Debug("Received request", "path", r.URL.Path)
	if websocket.IsWebSocketUpgrade(r) {
		logger.Debug("Upgrading to WebSocket", "path", r.URL.Path)
		wsHandler(w, r)
		return
	}

	logger.Debug("Serving HTTP request", "path", r.URL.Path)
	// Clean and resolve requested path
	path := r.URL.Path
	if path == "" || path == "/" {
		logger.Debug("Serving root, returning index.html")
		logger.Debug("Serving root", "path", filepath.Join(h.root, "index.html"))
		http.ServeFile(w, r, filepath.Join(h.root, "index.html"))
		return
	}

	// Map URL path to filesystem path
	fullPath := filepath.Join(h.root, filepath.Clean(path))

	// If the file exists and is not a directory, serve it
	if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
		h.fs.ServeHTTP(w, r)
		return
	}

	// For everything else (including React routes), serve index.html
	http.ServeFile(w, r, filepath.Join(h.root, "index.html"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Handling WebSocket connection", "remoteAddr", r.RemoteAddr)
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Problem with HTTP upgrade", "error", err)
		return
	}
	defer helpers.CloseOrLog(c)

	user, _ := r.Context().Value(session.UserContextKey).(*auth.User)

	s := session.NewSession(c, runtimeSpawnerAddress, user)
	slog.Info("Created new session", "user", user)

	// Send messages back to client through websocket
	s.HandleConnection()

	// Close worker on exit if it exists
	defer s.HandleDisconnect()

	// Basic handler based on gorilla/websocket example
	for {
		messageType, message, err := c.ReadMessage()
		if err != nil {
			slog.Error("Error reading message", "error", err)
			break
		}

		// Ping/pong sequence
		if messageType == websocket.TextMessage && string(message) == "PING" {
			slog.Debug("Received PING from client, sending PONG")
			err := c.WriteMessage(websocket.TextMessage, []byte("PONG"))
			if err != nil {
				slog.Error("Failed to send pong message", "error", err)
			}
			continue
		}

		// Ignore all other non-binary messages
		if messageType != websocket.BinaryMessage {
			slog.Warn("Ignoring non-binary message", "type", messageType, "message", message)
			continue
		}

		go func() {
			err := s.HandleMessage(message)
			if err != nil {
				slog.Warn("Failed to handle message", "error", err)
			}
		}()
	}

	// defer should shut down the worker afterwards
	slog.Info("Client disconnected")
}

func withAuth(a auth.Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.AuthenticateHTTP(w, r)
		if err != nil {
			// Expected when we just redirected to /oidc/login
			if strings.Contains(err.Error(), "no OIDC session") {
				// optional: log at debug level instead
				slog.Debug("Redirecting to OIDC login")
				return
			}
			slog.Error("Auth failed", "error", err)
			return
		}

		// Attach user to context
		ctx := context.WithValue(r.Context(), session.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("Surrogate-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

//go:embed templates/*.html
var templates embed.FS
var pamLoginTmpl *template.Template

func pamLoginHandler(p pamwrap.Authenticator) http.Handler {
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

			_ = pamLoginTmpl.Execute(w, pageData{
				Title:   "CARTA Login",
				Heading: "CARTA Login (PAM)",
			})

		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Bad form", http.StatusBadRequest)
				return
			}

			username := r.Form.Get("username")
			password := r.Form.Get("password")

			if username == "" || password == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = pamLoginTmpl.Execute(w, pageData{
					Title:   "CARTA Login",
					Heading: "CARTA Login (PAM)",
					Error:   "Missing username or password",
				})
				return
			}

			user, err := p.AuthenticateCredentials(r.Context(), username, password)
			if err != nil {
				slog.Error("PAM login failed", "username", username, "error", err)
				w.WriteHeader(http.StatusUnauthorized)
				_ = pamLoginTmpl.Execute(w, pageData{
					Title:   "CARTA Login",
					Heading: "CARTA Login (PAM)",
					Error:   "Invalid credentials",
				})
				return
			}
			slog.Info("About to set PAM session cookie", "username", user.Username)

			if err := pamwrap.SetSessionCookie(w, user.Username); err != nil {
				slog.Error("Failed to set PAM session cookie", "username", user.Username, "error", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			// Dump Set-Cookie headers to confirm what we sent
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

var oidcAuth *authoidc.OIDCAuthenticator

func main() {
	logger := helpers.NewLogger("carta-ctl", "info")
	slog.SetDefault(logger)

	id := uuid.New()
	slog.Info("Starting controller", "uuid", id.String())

	pflag.String("config", "", "Path to config file (default: /etc/carta/config.toml)")
	pflag.String("log_level", "info", "Log level (debug|info|warn|error)")
	pflag.Int("port", 8081, "TCP server port")
	pflag.String("hostname", "", "Hostname to listen on")
	pflag.String("spawner_address", "", "Address of the process spawner")
	pflag.String("frontend_dir", "", "Directory with carta_frontend")
	pflag.String("auth_mode", "none", "Authentication mode: none|pam|oidc|both")
	pflag.String("override", "", "Override simple config values (string, int, bool) as comma-separated key:value pairs (e.g., controller.port:9000,log_level:debug)")
	pflag.String("db_conn_string", "", "Database connection string")

	pflag.Parse()

	slog.Info("Parsed flags",
		"auth_mode", pflag.Lookup("auth_mode").Value.String(),
		"override", pflag.Lookup("override").Value.String(),
		"config", pflag.Lookup("config").Value.String(),
	)

	config.BindFlags(map[string]string{
		"log_level":       "log_level",
		"port":            "controller.port",
		"hostname":        "controller.hostname",
		"spawner_address": "controller.spawner_address",
		"frontend_dir":    "controller.frontend_dir",
		"auth_mode":       "controller.auth_mode",
		"db_conn_string":  "controller.db_conn_string",
	})

	cfg := config.Load(pflag.Lookup("config").Value.String(), pflag.Lookup("override").Value.String())

	slog.Info("Cfg auth_mode", "authMode", cfg.Controller.AuthMode)
	slog.Info("Cfg auth_mode", "cfg.Controller.AuthMode", cfg.Controller.AuthMode)

	// Update the logger to use the configured log level
	logger = helpers.NewLogger("carta-ctl", cfg.LogLevel)
	slog.SetDefault(logger)

	pamLoginTmpl = template.Must(
		template.ParseFS(templates, "templates/pam_login.html"),
	)

	runtimeSpawnerAddress = cfg.Controller.SpawnerAddress
	if runtimeSpawnerAddress == "" {
		runtimeSpawnerAddress = fmt.Sprintf("http://%s:%d", cfg.Spawner.Hostname, cfg.Spawner.Port)
	}

	var authenticator auth.Authenticator

	slog.Debug("Configuring auth", "authMode", cfg.Controller.AuthMode)

	switch cfg.Controller.AuthMode {
	case config.AuthNone:
		authenticator = auth.NoopAuthenticator{}
	case config.AuthPAM:
		p, err := pamwrap.New(cfg.Controller.PAM)
		if err != nil {
			slog.Error("PAM is not available on this platform", "error", err)
			os.Exit(1)
		}
		pamAuth = p
		authenticator = p

	case config.AuthOIDC:
		o := authoidc.New(cfg.Controller.OIDC)
		oidcAuth = o
		authenticator = o

	case config.AuthBoth:
		p, err := pamwrap.New(cfg.Controller.PAM)
		if err != nil {
			slog.Error("Auth mode 'both' requires PAM, but PAM is not available on this platform", "error", err)
			os.Exit(1)
		}
		pamAuth = p
		authenticator = auth.Multi(
			p,
			authoidc.New(cfg.Controller.OIDC),
		)
	default:
		slog.Error("Unknown config option", "authMode", cfg.Controller.AuthMode)
		os.Exit(1)
	}

	if cfg.Controller.DBConnectionString != "" {
		slog.Debug("Database connection string provided", "db_conn_string", cfg.Controller.DBConnectionString)
		db := database.DbConfig{
			ConnString: cfg.Controller.DBConnectionString,
		}
		db.InitDb()
		http.Handle(
			"/api/database/",
			noCache(
				withAuth(authenticator,
					http.StripPrefix("/api/database", http.Handler(db.Router())))))
	} else {
		slog.Debug("Defaulting to backend's filesystem-based state-saving")
	}

	// If a frontend directory is provided, serve carta_frontend from there
	if cfg.Controller.FrontendDir != "" {
		info, err := os.Stat(cfg.Controller.FrontendDir)
		if err != nil || !info.IsDir() {
			slog.Error("Failed to set frontend directory", "error", err, "dirname", cfg.Controller.FrontendDir)
			os.Exit(1)
		}

		slog.Info("Serving carta_frontend", "dirname", cfg.Controller.FrontendDir)
		fs := http.FileServer(http.Dir(cfg.Controller.FrontendDir))

		if oidcAuth != nil && (cfg.Controller.AuthMode == config.AuthOIDC || cfg.Controller.AuthMode == config.AuthBoth) {
			http.Handle("/oidc/login", http.HandlerFunc(oidcAuth.LoginHandler))
			http.Handle("/oidc/callback", http.HandlerFunc(oidcAuth.CallbackHandler))
		}

		// Root handler behaves like carta_backend:
		//  - /           -> index.html
		//  - /static/... -> real files
		//  - /whatever   -> index.html (for SPA routes)
		// Wrap root with the currently-selected authenticator (PAM, OIDC, both, or none).
		http.Handle("/", withAuth(authenticator, spaHandler{
			root: cfg.Controller.FrontendDir,
			fs:   fs,
		}))

		// Expose the PAM login page only when PAM is enabled.
		if pamAuth != nil && (cfg.Controller.AuthMode == config.AuthPAM || cfg.Controller.AuthMode == config.AuthBoth) {
			http.Handle("/pam-login", pamLoginHandler(pamAuth))
		}
	} else {
		slog.Warn("No frontend directory specified: controller will *not* serve the frontend (only /carta WebSocket).")
	}

	cfgHandler := func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		cfg := map[string]string{
			//"dashboardAddress": "/dashboard", // no dashboard
			"apiAddress": "/api",
			//"tokenRefreshAddress":  "/api/auth/refresh",
			//"logoutAddress": "/api/auth/logout",
			//"authPath":      "/api/auth/refresh",
		}

		if err := json.NewEncoder(w).Encode(cfg); err != nil {
			slog.Error("Error encoding config", "err", err)
		}
	}
	http.Handle("/config", http.HandlerFunc(cfgHandler))

	addr := fmt.Sprintf("%s:%d", cfg.Controller.Hostname, cfg.Controller.Port)

	slog.Info("Server listening", "addr", addr)
	if err := http.ListenAndServe(addr, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
}
