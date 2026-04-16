// services/carta-ctl/internal/auth/oidc/oidc.go
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/CARTAvis/go-carta/pkg/config"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

type OIDCAuthenticator struct {
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   *oauth2.Config
}

func New(cfg config.OIDCConfig) (*OIDCAuthenticator, error) {
	// Validate required configuration
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("OIDC configuration error: issuer_url is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("OIDC configuration error: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("OIDC configuration error: client_secret is required")
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("OIDC configuration error: redirect_url is required")
	}

	ctx := context.Background()

	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC configuration error: failed to create provider for issuer %s: %w", cfg.IssuerURL, err)
	}

	oidcCfg := &gooidc.Config{
		ClientID: cfg.ClientID,
	}

	verifier := provider.Verifier(oidcCfg)

	oauth2cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			gooidc.ScopeOpenID,
			"profile",
			"email",
		},
	}

	return &OIDCAuthenticator{
		provider: provider,
		verifier: verifier,
		oauth2:   oauth2cfg,
	}, nil
}

// AuthenticateHTTP implements auth.Authenticator.
//
// Behaviour for browser flows:
//
//  1. If path is /oidc/login or /oidc/callback → we *don't* handle here
//     (those handlers are wired separately).
//  2. Try to authenticate from the session cookie (carta_oidc).
//  3. If no valid cookie and no Bearer token → redirect to /oidc/login.
//
// Behaviour for API clients:
//
//  1. If there is an Authorization: Bearer <token> header, verify it.
//  2. If valid → return user; if invalid → 401 via caller.
func (o *OIDCAuthenticator) AuthenticateHTTP(w http.ResponseWriter, r *http.Request) (*auth.User, error) {
	// Allow the OIDC endpoints themselves to run without auth.
	if r.URL.Path == "/oidc/login" || r.URL.Path == "/oidc/callback" {
		return nil, fmt.Errorf("oidc endpoint passthrough")
	}

	// Try Bearer token (API clients and browser with JWT)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		raw := strings.TrimSpace(authHeader[len("bearer "):])
		claims, err := auth.VerifyToken(raw)
		if err != nil || claims.Type != auth.TokenTypeAccess {
			slog.Debug("OIDC: invalid access token", "error", err)
		} else {
			user := &auth.User{
				Username: claims.Username,
				Source:   auth.SourceOIDC,
				Claims:   map[string]any{},
			}
			return user, nil
		}
	}

	// 3. No session → redirect browser to login
	http.Redirect(w, r, "/oidc/login", http.StatusFound)
	return nil, fmt.Errorf("no OIDC session")
}

func generateRandomURLSafeString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func codeChallengeS256(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func setPKCECookies(w http.ResponseWriter, state, verifier string) {
	expires := time.Now().Add(5 * time.Minute)

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/oidc",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_code_verifier",
		Value:    verifier,
		Path:     "/oidc",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

func clearPKCECookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    "",
		Path:     "/oidc",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_code_verifier",
		Value:    "",
		Path:     "/oidc",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

// LoginHandler redirects the user to Keycloak's authorization endpoint.
func (o *OIDCAuthenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomURLSafeString(32)
	if err != nil {
		slog.Error("OIDC: failed to generate state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	verifier, err := generateRandomURLSafeString(64)
	if err != nil {
		slog.Error("OIDC: failed to generate PKCE verifier", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	challenge := codeChallengeS256(verifier)
	setPKCECookies(w, state, verifier)

	url := o.oauth2.AuthCodeURL(state, oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

// CallbackHandler handles the redirect from Keycloak, exchanges the code
// for tokens, validates the ID token, sets the session cookie, and redirects
// back to the main UI (/).
func (o *OIDCAuthenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("OIDC error: %s (%s)", errParam, desc), http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || state == "" || state != stateCookie.Value {
		slog.Error("OIDC: invalid state", "error", err)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie("oidc_code_verifier")
	if err != nil || verifierCookie.Value == "" {
		slog.Error("OIDC: missing PKCE code verifier", "error", err)
		http.Error(w, "Missing PKCE code verifier", http.StatusBadRequest)
		return
	}

	clearPKCECookies(w)

	oauth2Token, err := o.oauth2.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value))
	if err != nil {
		slog.Error("OIDC: code exchange failed", "error", err)
		http.Error(w, "Code exchange failed", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		slog.Error("OIDC: no id_token in token response")
		http.Error(w, "No id_token in token response", http.StatusUnauthorized)
		return
	}

	// Verify and extract user (mainly for logging / sanity)
	user, err := o.verifyRawToken(ctx, rawIDToken)
	if err != nil {
		slog.Error("OIDC: id_token verification failed", "error", err)
		http.Error(w, "Invalid id_token", http.StatusUnauthorized)
		return
	}

	// Set refresh token cookie for unified JWT auth
	if err := auth.SetRefreshTokenCookie(w, user.Username); err != nil {
		slog.Error("OIDC: failed to set refresh token cookie", "error", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	slog.Info("OIDC: login successful", "username", user.Username)

	http.Redirect(w, r, "/", http.StatusFound)
}

// verifyRawToken verifies an ID token string and builds an auth.User from it.
func (o *OIDCAuthenticator) verifyRawToken(ctx context.Context, raw string) (*auth.User, error) {
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verifyRawToken: %w", err)
	}

	var claims struct {
		Email         string `json:"email"`
		PreferredName string `json:"preferred_username"`
		Name          string `json:"name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	username := claims.PreferredName
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Name
	}
	if username == "" {
		username = "unknown"
	}

	// If you want all claims, you can unmarshal into a generic map as well:
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		allClaims = map[string]any{}
	}

	// Be careful not to blow up logs; but store claims in the User struct.
	user := &auth.User{
		Username: username,
		Source:   auth.SourceOIDC,
		Claims:   allClaims,
	}

	return user, nil
}
