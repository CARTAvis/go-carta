package cthttp

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/websocket"
)

// SPAHandler serves static files if they exist, otherwise falls back to index.html.
type SPAHandler struct {
	Root      string
	FS        http.Handler
	WSHandler http.Handler
}

func (h SPAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := slog.With("service", "spaHandler")
	logger.Debug("Received request", "path", r.URL.Path)

	if websocket.IsWebSocketUpgrade(r) {
		logger.Debug("Upgrading to WebSocket", "path", r.URL.Path)
		h.WSHandler.ServeHTTP(w, r)
		return
	}

	logger.Debug("Serving HTTP request", "path", r.URL.Path)
	path := r.URL.Path
	if path == "" || path == "/" {
		logger.Debug("Serving root, returning index.html")
		logger.Debug("Serving root", "path", filepath.Join(h.Root, "index.html"))
		http.ServeFile(w, r, filepath.Join(h.Root, "index.html"))
		return
	}

	fullPath := filepath.Join(h.Root, filepath.Clean(path))
	if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
		h.FS.ServeHTTP(w, r)
		return
	}

	http.ServeFile(w, r, filepath.Join(h.Root, "index.html"))
}
