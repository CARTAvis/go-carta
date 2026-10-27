package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		pamAuth          pamwrap.Authenticator
		oidcAuth         *authoidc.OIDCAuthenticator
		pendingAuthStore auth.PendingAuthStore
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

	// Device authorization is opt-in, but once enabled it must be usable.
	// Validate up front so a misconfiguration fails fast with a clear message
	// instead of silently leaving the device auth endpoints unregistered.
	publicURL, err := config.NormalizePublicURL(cfg.Controller.PublicURL)
	if err != nil {
		slog.Error("Invalid controller configuration", "error", err)
		os.Exit(1)
	}
	cfg.Controller.PublicURL = publicURL

	// OIDC device sessions store the provider's offline token encrypted, so the
	// key is mandatory whenever OIDC authentication is enabled.
	if cfg.Controller.AuthMode == config.AuthOIDC || cfg.Controller.AuthMode == config.AuthBoth {
		if strings.TrimSpace(cfg.Controller.OIDC.EncryptionKeyFile) == "" {
			slog.Error("OIDC authentication requires controller.oidc.encryption_key_file to be set",
				"hint", "generate a 32-byte key (e.g. openssl rand -out /etc/carta/oidc_encryption.key 32) and set its path, or disable OIDC authentication")
			os.Exit(1)
		}
	}

	if cfg.Controller.DeviceAuth.Enabled {
		if publicURL == "" {
			slog.Error("Device authorization is enabled but controller.public_url is not set",
				"hint", "set controller.public_url to this controller's public base URL, or set controller.device_auth.enabled = false")
			os.Exit(1)
		}
		if cfg.Controller.AuthMode == config.AuthNone {
			slog.Error("Device authorization is enabled but controller.auth_mode is \"none\"",
				"hint", "device authorization requires an authentication mode (pam, oidc, or both)")
			os.Exit(1)
		}
		if cfg.Controller.DBConnectionString == "" {
			slog.Error("Device authorization is enabled but controller.db_conn_string is not set",
				"hint", "device authorization requires a database connection")
			os.Exit(1)
		}
	} else if cfg.Controller.AuthMode != config.AuthNone && cfg.Controller.DBConnectionString != "" {
		// The device endpoints are only registered when device auth is enabled.
		// Without them, device login requests fall through to the authenticated
		// /api/ handler and fail with a confusing 401.
		slog.Warn("Device authorization is not enabled; device login endpoints are not registered",
			"hint", "set controller.device_auth.enabled = true and configure controller.public_url to enable device login")
	}

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

	// OIDC endpoints must also be available without a frontend directory: a
	// CLI-only deployment still uses them to link device credentials.
	if oidcAuth != nil {
		http.Handle("/api/auth/oidc_login", http.HandlerFunc(oidcAuth.LoginHandler))
		http.Handle("/api/auth/oidc_callback", http.HandlerFunc(oidcAuth.CallbackHandler))
	}

	authLoginAddress := "/login"

	if cfg.Controller.DBConnectionString != "" {
		slog.Debug("Database connection string provided")
		db := database.DbConfig{
			ConnString: cfg.Controller.DBConnectionString,
		}
		db.InitDb()
		// Device authorization is opt-in: only register it when explicitly
		// enabled. When enabled, DeviceInitHandler requires public_url so the
		// verification link cannot be built from a spoofed Host header.
		if cfg.Controller.AuthMode != config.AuthNone && cfg.Controller.DeviceAuth.Enabled {
			pendingAuthStore = &db

			// OIDC device sessions need the OIDC authenticator both to store
			// encrypted offline tokens at login and to refresh upstream access
			// tokens afterwards. It is nil for PAM-only deployments.
			var oidcRefresher auth.OIDCTokenRefresher
			if oidcAuth != nil {
				oidcAuth.SetPendingAuthStore(&db)
				oidcRefresher = oidcAuth
			}

			deviceInit, err := auth.DeviceInitHandler(&db, cfg.Controller.DeviceAuth, publicURL)
			if err != nil {
				slog.Error("Failed to configure device authorization", "error", err)
				os.Exit(1)
			}
			devicePoll, err := auth.DevicePollHandler(&db, &db, cfg.Controller.DeviceAuth, oidcRefresher)
			if err != nil {
				slog.Error("Failed to configure device authorization polling", "error", err)
				os.Exit(1)
			}
			deviceRefresh := auth.DeviceRefreshHandler(&db, oidcRefresher)
			deviceLogout := auth.DeviceLogoutHandler(&db)
			http.Handle(auth.DeviceVerifyPath, auth.DeviceLinkPageHandler(&db, cfg))
			http.Handle("/api/auth/device_init", ctlhttp.NoCache(deviceInit))
			http.Handle("/api/auth/device_poll", ctlhttp.NoCache(devicePoll))
			http.Handle("/api/auth/device_refresh", ctlhttp.NoCache(deviceRefresh))
			http.Handle("/api/auth/device_logout", ctlhttp.NoCache(deviceLogout))

			// Periodically remove expired pending device logins and expired or
			// revoked device sessions so the auth tables don't grow unbounded.
			pendingPurge, err := cfg.Controller.DeviceAuth.PendingPurgeDuration()
			if err != nil {
				slog.Error("Failed to configure device auth maintenance", "error", err)
				os.Exit(1)
			}
			sessionPurge, err := cfg.Controller.DeviceAuth.SessionPurgeDuration()
			if err != nil {
				slog.Error("Failed to configure device auth maintenance", "error", err)
				os.Exit(1)
			}
			go db.RunAuthMaintenance(ctx, pendingPurge, sessionPurge)
		}
		http.Handle(
			"/api/database/",
			ctlhttp.NoCache(
				ctlhttp.WithAccessToken(
					http.StripPrefix("/api/database", http.Handler(db.Router())))))
	} else {
		slog.Debug("Defaulting to backend's filesystem-based state-saving")
	}

	// Login pages and endpoints are also needed by CLI-only deployments, where
	// a device login still requires a browser to authenticate.
	if cfg.Controller.AuthMode != config.AuthNone {
		http.Handle("/login", auth.LoginPageHandler(pendingAuthStore, cfg))
		http.Handle("/login/logo", auth.ServeCartaLogo())
		http.Handle("/login/banner", auth.ServeSiteBanner(cfg.Controller.LoginPage.SiteBanner))

		if pamAuth != nil && (cfg.Controller.AuthMode == config.AuthPAM || cfg.Controller.AuthMode == config.AuthBoth) {
			http.Handle("/api/auth/pam_login", authpam.NewLoginHandler(pamAuth, pendingAuthStore))
		}
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

	srv := &http.Server{
		Addr:    addr,
		Handler: nil, // serve http.DefaultServeMux, where all handlers are registered
	}

	// On SIGINT/SIGTERM, stop accepting new connections, let in-flight requests
	// finish, and allow the maintenance goroutine to exit via ctx cancellation.
	go func() {
		<-ctx.Done()
		slog.Info("Shutting down controller")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Graceful shutdown failed", "err", err)
		}
	}()

	slog.Info("Server listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
}
