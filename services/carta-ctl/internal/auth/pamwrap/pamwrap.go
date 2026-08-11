package pamwrap

import (
	"context"
	"errors"

	"github.com/CARTAvis/go-carta/pkg/config"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

var ErrUnsupported = errors.New("PAM auth is only supported on Linux")

// Authenticator is what main.go needs.
type Authenticator interface {
	AuthenticateCredentials(ctx context.Context, username, password string) (*auth.User, error)
}

func New(cfg config.PAMConfig) (Authenticator, error) {
	return newImpl(cfg)
}
