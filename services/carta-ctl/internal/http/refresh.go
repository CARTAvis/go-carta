package cthttp

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Missing refresh token", http.StatusUnauthorized)
		return
	}

	claims, err := auth.VerifyToken(c.Value)
	if err != nil || claims.Type != auth.TokenTypeRefresh {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	sessionToken, err := auth.GenerateToken(claims.Username, auth.NormalizeSource(claims.Source), auth.TokenTypeAccess)
	if err != nil {
		slog.Error("Failed to generate access token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": sessionToken,
		"token_type":   "bearer",
		"expires_in":   auth.GetAccessTokenAgeSeconds(),
	}); err != nil {
		slog.Error("Failed to encode refresh response", "error", err)
	}
}
