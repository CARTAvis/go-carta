package auth

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
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
	Type     TokenType `json:"type"`
	jwt.RegisteredClaims
}

var (
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	tokenConfig config.TokenConfig
)

func InitJWT(cfg config.TokenConfig) error {
	tokenConfig = cfg

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

func GenerateToken(username string, tokenType TokenType) (string, error) {
	claims := TokenClaims{
		Username: username,
		Type:     tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenConfig.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(parseDuration(tokenConfig.AccessTokenAge))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	if tokenType == TokenTypeRefresh {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(parseDuration(tokenConfig.RefreshTokenAge)))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// Helper: sets session cookie for a user.
func SetRefreshTokenCookie(w http.ResponseWriter, username string) error {
	token, err := GenerateToken(username, TokenTypeRefresh)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   false, // set true if serving over HTTPS
		SameSite: http.SameSiteLaxMode,
		// Expires set by JWT
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
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		// Default to 1 hour
		return time.Hour
	}
	return d
}

func GetAccessTokenAgeSeconds() int {
	return int(parseDuration(tokenConfig.AccessTokenAge).Seconds())
}
