package cthttp

import (
	"log/slog"
	"net/http"

	helpers "github.com/CARTAvis/go-carta/pkg/shared"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/session"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	// Ignore Origin header
	CheckOrigin: func(r *http.Request) bool {
		slog.Debug("Upgrading WebSocket connection", "origin", r.Header.Get("Origin"))
		return true
	},
}

func NewWebSocketHandler(runtimeSpawnerAddress string, authEnabled bool, multiBackend bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Handling WebSocket connection", "remoteAddr", r.RemoteAddr)

		var user *auth.User
		if authEnabled {
			authorizedUser, ok := AuthorizeAccessToken(w, r)
			if !ok {
				return
			}
			user = authorizedUser
		} else {
			user = &auth.User{
				Username: "anonymous",
				Source:   auth.SourceUnknown,
				Claims:   map[string]any{},
			}
		}

		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("Problem with HTTP upgrade", "error", err)
			return
		}
		defer helpers.CloseOrLog(c)

		s := session.NewSession(c, runtimeSpawnerAddress, user, multiBackend)
		slog.Info("Created new session", "user", user)

		// Send messages back to client through websocket
		s.HandleConnection()
		defer s.HandleDisconnect()

		for {
			messageType, message, err := c.ReadMessage()
			if err != nil {
				slog.Error("Error reading message", "error", err)
				break
			}

			if messageType == websocket.TextMessage && string(message) == "PING" {
				slog.Debug("Received PING from client, sending PONG")
				err := c.WriteMessage(websocket.TextMessage, []byte("PONG"))
				if err != nil {
					slog.Error("Failed to send pong message", "error", err)
				}
				continue
			}

			if messageType != websocket.BinaryMessage {
				slog.Warn("Ignoring non-binary message", "type", messageType, "message", message)
				continue
			}

			go func() {
				err := s.HandleMessage(message)
				if err != nil {
					slog.Warn("Failed to handle message", "error", err)
				}
			}()
		}

		slog.Info("Client disconnected")
	}
}
