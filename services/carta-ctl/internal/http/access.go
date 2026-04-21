package cthttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/session"
)

func AuthorizeAccessToken(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	tokenString := accessTokenFromRequest(r)
	if tokenString == "" {
		http.Error(w, "Missing or invalid access token", http.StatusUnauthorized)
		return nil, false
	}

	claims, err := auth.VerifyToken(tokenString)
	if err != nil || claims.Type != auth.TokenTypeAccess {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return nil, false
	}

	user := &auth.User{
		Username: claims.Username,
		Source:   auth.NormalizeSource(claims.Source),
		Claims:   map[string]any{},
	}

	return user, true
}

func WithAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing or invalid access token", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.VerifyToken(tokenString)
		if err != nil || claims.Type != auth.TokenTypeAccess {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}

		user := &auth.User{
			Username: claims.Username,
			Source:   auth.NormalizeSource(claims.Source),
			Claims:   map[string]any{},
		}
		ctx := context.WithValue(r.Context(), session.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func NoCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("Surrogate-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func accessTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return r.URL.Query().Get("token")
}
