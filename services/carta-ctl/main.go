package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"github.com/CARTAvis/go-carta/pkg/config"
	helpers "github.com/CARTAvis/go-carta/pkg/shared"
	authpam "github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth/pam"
	ctlhttp "github.com/CARTAvis/go-carta/services/carta-ctl/internal/http"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
	authoidc "github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth/oidc"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth/pamwrap"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/database"

	"encoding/json"
)

var (
	runtimeSpawnerAddress string
)

func main() {
	logger := helpers.NewLogger("carta-ctl", "info")
	slog.SetDefault(logger)

	var (
		pamAuth  pamwrap.Authenticator
		oidcAuth *authoidc.OIDCAuthenticator
	)

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

	runtimeSpawnerAddress = cfg.Controller.SpawnerAddress
	if runtimeSpawnerAddress == "" {
		runtimeSpawnerAddress = fmt.Sprintf("http://%s:%d", cfg.Spawner.Hostname, cfg.Spawner.Port)
	}

	slog.Debug("Configuring auth", "authMode", cfg.Controller.AuthMode)

	switch cfg.Controller.AuthMode {
	case config.AuthNone:
		// No authentication required - JWT not needed
	case config.AuthPAM:
		// Initialize JWT for token generation and verification
		if err := auth.InitJWT(cfg.Controller.TokenConfig); err != nil {
			slog.Error("Failed to initialize JWT for PAM authentication", "error", err)
			os.Exit(1)
		}
		p, err := pamwrap.New(cfg.Controller.PAM)
		if err != nil {
			slog.Error("PAM is not available on this platform", "error", err)
			os.Exit(1)
		}
		pamAuth = p

	case config.AuthOIDC:
		// Initialize JWT for token generation and verification
		if err := auth.InitJWT(cfg.Controller.TokenConfig); err != nil {
			slog.Error("Failed to initialize JWT for OIDC authentication", "error", err)
			os.Exit(1)
		}
		o, err := authoidc.New(cfg.Controller.OIDC)
		if err != nil {
			slog.Error("Failed to initialize OIDC authentication", "error", err)
			os.Exit(1)
		}
		oidcAuth = o

	case config.AuthBoth:
		// Initialize JWT for token generation and verification
		if err := auth.InitJWT(cfg.Controller.TokenConfig); err != nil {
			slog.Error("Failed to initialize JWT for 'both' authentication mode", "error", err)
			os.Exit(1)
		}
		p, err := pamwrap.New(cfg.Controller.PAM)
		if err != nil {
			slog.Error("Auth mode 'both' requires PAM, but PAM is not available on this platform", "error", err)
			os.Exit(1)
		}
		pamAuth = p

		o, err := authoidc.New(cfg.Controller.OIDC)
		if err != nil {
			slog.Error("Auth mode 'both' requires OIDC, but failed to initialize OIDC", "error", err)
			os.Exit(1)
		}
		oidcAuth = o
	default:
		slog.Error("Unknown config option", "authMode", cfg.Controller.AuthMode)
		os.Exit(1)
	}

	authLoginAddress := "/login"

	if cfg.Controller.DBConnectionString != "" {
		slog.Debug("Database connection string provided")
		db := database.DbConfig{
			ConnString: cfg.Controller.DBConnectionString,
		}
		db.InitDb()
		http.Handle(
			"/api/database/",
			ctlhttp.NoCache(
				ctlhttp.WithAccessToken(
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
		wsHandler := ctlhttp.NewWebSocketHandler(runtimeSpawnerAddress, cfg.Controller.AuthMode != config.AuthNone)

		if oidcAuth != nil && (cfg.Controller.AuthMode == config.AuthOIDC || cfg.Controller.AuthMode == config.AuthBoth) {
			http.Handle("/api/auth/oidc_login", http.HandlerFunc(oidcAuth.LoginHandler))
			http.Handle("/api/auth/oidc_callback", http.HandlerFunc(oidcAuth.CallbackHandler))
		}

		if cfg.Controller.AuthMode != config.AuthNone {
			http.Handle("/login", auth.LoginPageHandler(cfg))
			http.Handle("/login/logo", auth.ServeCartaLogo())
			http.Handle("/login/banner", auth.ServeSiteBanner(cfg.Controller.LoginPage.SiteBanner))
		}

		// Root handler behaves like carta_backend:
		//  - /           -> index.html
		//  - /static/... -> real files
		//  - /whatever   -> index.html (for SPA routes)
		// The SPA itself is public; API and WebSocket upgrade paths require access tokens.
		http.Handle("/", ctlhttp.SPAHandler{
			Root:      cfg.Controller.FrontendDir,
			FS:        fs,
			WSHandler: wsHandler,
		})

		// Expose the PAM login API endpoint only when PAM is enabled.
		if pamAuth != nil && (cfg.Controller.AuthMode == config.AuthPAM || cfg.Controller.AuthMode == config.AuthBoth) {
			http.Handle("/api/auth/pam_login", authpam.NewLoginHandler(pamAuth))
		}
	} else {
		slog.Warn("No frontend directory specified: controller will *not* serve the frontend (only /carta WebSocket).")
	}

	// Token refresh endpoint remains open to refresh cookies only.
	http.Handle("/api/auth/refresh", ctlhttp.NoCache(http.HandlerFunc(ctlhttp.RefreshHandler)))
	// Logout endpoint clears the refresh cookie and redirects to login.
	http.Handle("/api/auth/logout", ctlhttp.NoCache(ctlhttp.LogoutHandler(cfg)))

	// Require access tokens on all other /api/ requests.
	http.Handle("/api/", ctlhttp.NoCache(ctlhttp.WithAccessToken(http.NotFoundHandler())))

	cfgHandler := func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		configResponse := map[string]interface{}{
			"apiAddress":          cfg.Controller.ApiPrefix,
			"tokenRefreshAddress": "/api/auth/refresh",
			"loginAddress":        authLoginAddress,
			"serviceRestartable":  true,
		}
		if cfg.Controller.AuthMode != config.AuthNone {
			configResponse["logoutAddress"] = "/api/auth/logout"
		}

		if err := json.NewEncoder(w).Encode(configResponse); err != nil {
			slog.Error("Error encoding config", "err", err)
		}
	}
	http.Handle("/config", ctlhttp.NoCache(http.HandlerFunc(cfgHandler)))

	addr := fmt.Sprintf("%s:%d", cfg.Controller.Hostname, cfg.Controller.Port)

	slog.Info("Server listening", "addr", addr)
	if err := http.ListenAndServe(addr, nil); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
}
