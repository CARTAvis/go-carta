package auth

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CARTAvis/go-carta/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

type TokenClaims struct {
	Username string    `json:"username"`
	Source   Source    `json:"source,omitempty"`
	Type     TokenType `json:"type"`
	jwt.RegisteredClaims
}

var (
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	tokenConfig        config.TokenConfig
	accessTokenAgeDur  time.Duration
	refreshTokenAgeDur time.Duration
)

func InitJWT(cfg config.TokenConfig) error {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return fmt.Errorf("invalid controller.token_config.issuer: must be non-empty")
	}
	cfg.Issuer = issuer

	tokenConfig = cfg

	var err error
	accessTokenAgeDur, err = parseDurationStrict("access_token_age", cfg.AccessTokenAge)
	if err != nil {
		return err
	}

	refreshTokenAgeDur, err = parseDurationStrict("refresh_token_age", cfg.RefreshTokenAge)
	if err != nil {
		return err
	}

	privKeyData, err := os.ReadFile(cfg.PrivateKeyLocation)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	privateKey = privKey

	pubKeyData, err := os.ReadFile(cfg.PublicKeyLocation)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey = pubKey

	return nil
}

func GenerateToken(username string, source Source, tokenType TokenType) (string, error) {
	claims := TokenClaims{
		Username: username,
		Source:   NormalizeSource(source),
		Type:     tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenConfig.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenAgeDur)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	if tokenType == TokenTypeRefresh {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(refreshTokenAgeDur))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// Helper: sets session cookie for a user.
func SetRefreshTokenCookie(w http.ResponseWriter, username string, source Source) error {
	token, err := GenerateToken(username, source, TokenTypeRefresh)
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(refreshTokenAgeDur)
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   false, // set true if serving over HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(refreshTokenAgeDur.Seconds()),
	})
	return nil
}

func VerifyToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		if tokenConfig.Issuer == "" {
			return nil, fmt.Errorf("token issuer validation misconfigured")
		}
		if claims.Issuer == "" || claims.Issuer != tokenConfig.Issuer {
			return nil, fmt.Errorf("invalid token issuer")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func parseDurationStrict(name, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid controller.token_config.%s %q: %w", name, s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid controller.token_config.%s %q: duration must be > 0", name, s)
	}
	return d, nil
}

func GetAccessTokenAgeSeconds() int {
	return int(accessTokenAgeDur.Seconds())
}
