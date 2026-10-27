// Package config provides shared configuration functionality using Viper
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type AuthMode string

const (
	AuthNone AuthMode = "none"
	AuthPAM  AuthMode = "pam"
	AuthOIDC AuthMode = "oidc"
	AuthBoth AuthMode = "both" // optional
)

type OIDCConfig struct {
	IssuerURL     string   `mapstructure:"issuer_url"`
	ClientID      string   `mapstructure:"client_id"`
	ClientSecret  string   `mapstructure:"client_secret"`
	RedirectURL   string   `mapstructure:"redirect_url"`
	AppURL        string   `mapstructure:"app_url"`
	AllowedAud    []string `mapstructure:"allowed_aud"`
	AllowedGroups []string `mapstructure:"allowed_groups"`

	// EncryptionKeyFile is the path to a file containing the key used to
	// encrypt OIDC offline tokens before they are stored in the database for
	// device sessions. The file must contain the raw key bytes (32 bytes for
	// AES-256-GCM). When empty, OIDC device sessions cannot be created.
	EncryptionKeyFile string `mapstructure:"encryption_key_file"`
}

type PAMConfig struct {
	ServiceName string `mapstructure:"service_name"` // e.g. "login" or "carta"
}

type TokenConfig struct {
	PrivateKeyLocation string `mapstructure:"private_key_location"`
	PublicKeyLocation  string `mapstructure:"public_key_location"`
	Issuer             string `mapstructure:"issuer"`
	AccessTokenAge     string `mapstructure:"access_token_age"`
	RefreshTokenAge    string `mapstructure:"refresh_token_age"`
}

type DeviceAuthConfig struct {
	Lifetime           string `mapstructure:"lifetime"`
	MinInterval        string `mapstructure:"min_interval"`
	MaxRefreshInterval string `mapstructure:"max_refresh_interval"`
	PublicURL          string `mapstructure:"public_url"`

	// PendingPurgeInterval is how often expired pending device logins are
	// removed. When unset it defaults to half the pending login lifetime.
	PendingPurgeInterval string `mapstructure:"pending_purge_interval"`

	// SessionPurgeInterval is how often expired or revoked device sessions are
	// removed. When unset it defaults to max_refresh_interval / 24 (hourly for
	// the default 24h registration lifetime).
	SessionPurgeInterval string `mapstructure:"session_purge_interval"`

	// MaxPendingPerIP caps the number of unexpired, unlinked device logins that
	// may be pending from a single client IP address. A value <= 0 disables the
	// limit. The default is deliberately generous: a controller may be deployed
	// on a compute cluster where many distinct users share a single egress IP.
	MaxPendingPerIP int `mapstructure:"max_pending_per_ip"`

	// ClientIPHeader, when non-empty, names a request header (for example
	// "X-Forwarded-For" or "X-Real-IP") whose value is used as the client IP for
	// device-init rate limiting instead of the peer address in RemoteAddr. Only
	// set this when the controller sits behind a trusted reverse proxy; the
	// header is otherwise client-controlled and can bypass the per-IP limit.
	ClientIPHeader string `mapstructure:"client_ip_header"`
}

// parseDeviceDuration parses a device_auth duration value that must be positive.
func parseDeviceDuration(name, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid controller.device_auth.%s %q: must be a duration", name, s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid controller.device_auth.%s %q: must be a positive duration", name, s)
	}
	return d, nil
}

// PendingPurgeDuration resolves how often expired pending device logins are
// purged. It returns the configured PendingPurgeInterval when set, otherwise
// defaults to half the pending login lifetime (so each pending login is swept
// roughly twice over its lifetime).
func (d DeviceAuthConfig) PendingPurgeDuration() (time.Duration, error) {
	if d.PendingPurgeInterval != "" {
		return parseDeviceDuration("pending_purge_interval", d.PendingPurgeInterval)
	}
	lifetime, err := parseDeviceDuration("lifetime", d.Lifetime)
	if err != nil {
		return 0, err
	}
	if interval := lifetime / 2; interval >= time.Second {
		return interval, nil
	}
	return time.Second, nil
}

// SessionPurgeDuration resolves how often expired or revoked device sessions
// are purged. It returns the configured SessionPurgeInterval when set,
// otherwise defaults to max_refresh_interval / 24 (hourly for the default 24h
// lifetime), with a floor of one minute.
func (d DeviceAuthConfig) SessionPurgeDuration() (time.Duration, error) {
	if d.SessionPurgeInterval != "" {
		return parseDeviceDuration("session_purge_interval", d.SessionPurgeInterval)
	}
	maxRefresh, err := parseDeviceDuration("max_refresh_interval", d.MaxRefreshInterval)
	if err != nil {
		return 0, err
	}
	interval := maxRefresh / 24
	if interval < time.Minute {
		interval = time.Minute
	}
	return interval, nil
}

type LoginPageConfig struct {
	Title       string `mapstructure:"title"`
	WelcomeText string `mapstructure:"welcome_text"`
	SiteBanner  string `mapstructure:"site_banner"`
	SupportText string `mapstructure:"support_text"`
}

type ControllerConfig struct {
	OIDC               OIDCConfig       `mapstructure:"oidc"`
	PAM                PAMConfig        `mapstructure:"pam"`
	TokenConfig        TokenConfig      `mapstructure:"token_config"`
	LoginPage          LoginPageConfig  `mapstructure:"login_page"`
	DeviceAuth         DeviceAuthConfig `mapstructure:"device_auth"`
	Port               int              `mapstructure:"port"`
	Hostname           string           `mapstructure:"hostname"`
	FrontendDir        string           `mapstructure:"frontend_dir"`
	SpawnerAddress     string           `mapstructure:"spawner_address"`
	AuthMode           AuthMode         `mapstructure:"auth_mode"`
	DBConnectionString string           `mapstructure:"db_conn_string"`
	ApiPrefix          string           `mapstructure:"api_prefix"`
}

type SpawnerConfig struct {
	WorkerExec  string        `mapstructure:"worker_exec"`
	Timeout     time.Duration `mapstructure:"timeout"`
	Port        int           `mapstructure:"port"`
	Hostname    string        `mapstructure:"hostname"`
	BaseDirTmpl string        `mapstructure:"base_dir_tmpl"`
	TopLevelDir string        `mapstructure:"top_level_dir"`
}

// Config holds common configuration values shared across all services
type Config struct {
	// Basic configuration
	Environment string `mapstructure:"environment"`
	LogLevel    string `mapstructure:"log_level"`

	Controller ControllerConfig `mapstructure:"controller"`
	Spawner    SpawnerConfig    `mapstructure:"spawner"`
}

func setControllerDefaults(v *viper.Viper) {
	v.SetDefault("controller.port", 8081)
	v.SetDefault("controller.hostname", "")
	v.SetDefault("controller.frontend_dir", "")
	v.SetDefault("controller.spawner_address", "http://localhost:8080")
	v.SetDefault("controller.auth_mode", AuthNone)

	v.SetDefault("controller.pam.service_name", "carta")
	v.SetDefault("controller.oidc.issuer_url", "")
	v.SetDefault("controller.oidc.client_id", "")
	v.SetDefault("controller.oidc.client_secret", "")
	v.SetDefault("controller.oidc.redirect_url", "")
	v.SetDefault("controller.oidc.app_url", "")
	v.SetDefault("controller.oidc.encryption_key_file", "")
	v.SetDefault("controller.db_conn_string", "")
	v.SetDefault("controller.api_prefix", "/api")

	v.SetDefault("controller.login_page.title", "CARTA")
	v.SetDefault("controller.login_page.welcome_text", "Welcome to the CARTA server.")
	v.SetDefault("controller.login_page.site_banner", "")
	v.SetDefault("controller.login_page.support_text", "")

	v.SetDefault("controller.token_config.private_key_location", "/etc/carta/carta_private.pem")
	v.SetDefault("controller.token_config.public_key_location", "/etc/carta/carta_public.pem")
	v.SetDefault("controller.token_config.issuer", "carta-ctl")
	v.SetDefault("controller.token_config.access_token_age", "10m")
	v.SetDefault("controller.token_config.refresh_token_age", "24h")

	v.SetDefault("controller.device_auth.lifetime", "10m")
	v.SetDefault("controller.device_auth.min_interval", "5s")
	v.SetDefault("controller.device_auth.max_refresh_interval", "24h")
	v.SetDefault("controller.device_auth.public_url", "")
	v.SetDefault("controller.device_auth.max_pending_per_ip", 10)
	v.SetDefault("controller.device_auth.client_ip_header", "")

}

func setSpawnerDefaults(v *viper.Viper) {
	v.SetDefault("spawner.worker_exec", "carta-worker")
	v.SetDefault("spawner.timeout", 5*time.Second)
	v.SetDefault("spawner.port", 8080)
	v.SetDefault("spawner.hostname", "")
	v.SetDefault("spawner.base_dir_tmpl", "{{.home}}")
	v.SetDefault("spawner.top_level_dir", "")
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("environment", "development")
	v.SetDefault("log_level", "info")

	setControllerDefaults(v)
	setSpawnerDefaults(v)
	// TODO Allowed aud and groups
}

func ConfigureViper() {
	// We can pull config from env variables with a `CARTA_` prefix if we want
	viper.SetEnvPrefix("CARTA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigFile("/etc/carta/config.toml")
}

func init() {
	ConfigureViper()
}

// Load loads shared configuration using Viper with defaults
func Load(configPath string, overrideStr string) *Config {
	setDefaults(viper.GetViper())

	// If a custom config path is provided, use it
	if configPath != "" {
		viper.SetConfigFile(configPath)
	}

	err := viper.ReadInConfig()
	if err != nil {
		// Ignore failure to read default config (config is optional)
		if configPath != "" {
			slog.Error("Failed to read config file", "error", err, "config_file", viper.ConfigFileUsed())
			os.Exit(1)
		}
		slog.Info("No config file found, using defaults")
	} else {
		slog.Info("Loaded config file", "path", viper.ConfigFileUsed())
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		panic(fmt.Errorf("unable to unmarshal config: %w", err))
	}

	// Process override flag if provided (after loading config to ensure highest precedence)
	if overrideStr != "" {
		// Split into key-value pairs
		pairs := strings.Split(overrideStr, ",")
		for _, pair := range pairs {
			// Split into key and value
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) != 2 {
				slog.Error("Invalid override format", "pair", pair, "expected", "key:value")
				os.Exit(1)
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			viper.Set(key, value)
		}
		// Reload config struct to pick up overrides
		if err := viper.Unmarshal(&cfg); err != nil {
			slog.Error("Failed to apply overrides to config", "error", err)
			os.Exit(1)
		}
	}
	return &cfg
}

// BindFlags binds pflags to viper keys. bindFlags is a map of pflag names to viper keys.
func BindFlags(bindFlags map[string]string) {
	for flagName, viperKey := range bindFlags {
		if err := viper.BindPFlag(viperKey, pflag.Lookup(flagName)); err != nil {
			slog.Error("Failed to bind flag", "flag", flagName, "error", err)
			os.Exit(1)
		}
	}
}
