//go:build !pam

package pamwrap

import (
	"github.com/CARTAvis/go-carta/pkg/config"
)

func newImpl(cfg config.PAMConfig) (Authenticator, error) {
	return nil, ErrUnsupported
}
