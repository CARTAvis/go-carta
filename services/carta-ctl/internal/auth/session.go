package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

var sessionSecret []byte

// SetSessionSecret initializes the session secret used for signing tokens. It must be called before other token functions.
func SetSessionSecret(secret string) {
	if secret == "" {
		slog.Error("Session secret cannot be empty.")
		os.Exit(-1)
	}
	slog.Info("Setting session secret", "length", len(secret))
	sessionSecret = []byte(secret)
}

// GenerateSessionToken creates a signed token for a username with an expiry time.
func GenerateSessionToken(username string, expiry time.Time) (string, error) {
	payload := fmt.Sprintf("%s|%d", username, expiry.Unix())
	slog.Info("Generating session token", "payload", payload)
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)

	token := payload + "|" + base64.RawURLEncoding.EncodeToString(sig)
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}

// VerifySessionToken checks the token signature and expiry and returns the username.
func VerifySessionToken(token string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("bad token encoding")
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", fmt.Errorf("bad token format")
	}
	username := parts[0]
	expiryStr := parts[1]
	sigB64 := parts[2]

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", fmt.Errorf("bad sig encoding")
	}

	payload := username + "|" + expiryStr

	slog.Info("Verifying session token with payload", "payload", payload)
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return "", fmt.Errorf("invalid signature")
	}

	var expiryUnix int64
	_, err = fmt.Sscanf(expiryStr, "%d", &expiryUnix)
	if err != nil {
		return "", fmt.Errorf("bad expiry")
	}
	if time.Now().Unix() > expiryUnix {
		return "", fmt.Errorf("session expired")
	}

	return username, nil
}
