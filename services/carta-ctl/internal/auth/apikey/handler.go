package apikey

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

func NewManageHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes := logRequest(r)

		if !hasValidBearerToken(r) {
			http.Error(w, "Access denied", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
		case http.MethodPost:
			var req struct {
				TokenExpirySeconds *int64 `json:"token_expiry_seconds"`
			}
			if len(bodyBytes) > 0 {
				if err := json.Unmarshal(bodyBytes, &req); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid request body"})
					return
				}
			}

			tokenExpirySeconds := int64(3600)
			if req.TokenExpirySeconds != nil {
				if *req.TokenExpirySeconds <= 0 {
					writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "token_expiry_seconds must be > 0"})
					return
				}
				tokenExpirySeconds = *req.TokenExpirySeconds
			}
			expiryTimestamp := time.Now().UTC().Add(time.Duration(tokenExpirySeconds) * time.Second).Format(time.RFC3339)

			writeJSON(w, http.StatusOK, map[string]any{"key_id": "ABC", "access_key": "DEF", "expiry": expiryTimestamp})
		case http.MethodDelete:
			keyID := strings.TrimSpace(r.FormValue("key_id"))
			if keyID == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "missing key_id"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "key_id": keyID})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func logRequest(r *http.Request) []byte {
	var bodyBytes []byte
	if r.Body != nil {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Failed to read apikey_manage request body", "error", err)
			r.Body = io.NopCloser(bytes.NewReader(nil))
			bodyBytes = nil
		} else {
			bodyBytes = payload
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	slog.Info("apikey_manage request", "method", r.Method, "path", r.URL.Path, "headers", r.Header, "body", string(bodyBytes))
	return bodyBytes
}

func hasValidBearerToken(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}

	tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if tokenString == "" {
		return false
	}

	claims, err := auth.VerifyToken(tokenString)
	if err != nil || claims.Type != auth.TokenTypeAccess {
		return false
	}

	return true
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
