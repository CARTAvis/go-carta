//go:build pam

package pamwrap

import (
	"github.com/CARTAvis/go-carta/pkg/config"
	authpam "github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth/pam"
)

func newImpl(cfg config.PAMConfig) (Authenticator, error) {
	return authpam.New(cfg), nil
}
