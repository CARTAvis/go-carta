// Package config provides shared configuration functionality using Viper
package config

import (
	"errors"
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
	IssuerURL     string   `mapstrucutre:"issuer_url"`
	ClientID      string   `mapstrucutre:"client_id"`
	ClientSecret  string   `mapstructure:"client_secret"`
	RedirectURL   string   `mapstructure:"redirect_url"`
	AllowedAud    []string `mapstructure:"allowed_aud"`
	AllowedGroups []string `mapstructure:"allowed_groups"`
}

type PAMConfig struct {
	ServiceName string `mapstructure:"service_name"` // e.g. "login" or "carta"
}

type ControllerConfig struct {
	OIDC               OIDCConfig `mapstructure:"oidc"`
	PAM                PAMConfig  `mapstructure:"pam"`
	Port               int        `mapstructure:"port"`
	Hostname           string     `mapstructure:"hostname"`
	FrontendDir        string     `mapstructure:"frontend_dir"`
	SpawnerAddress     string     `mapstructure:"spawner_address"`
	AuthMode           AuthMode   `mapstructure:"auth_mode"`
	DBConnectionString string     `mapstructure:"db_conn_string"`
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
	v.SetDefault("controller.db_conn_string", "")
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
		// Ignore file not found errors (config is optional)
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
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
