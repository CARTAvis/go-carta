//go:build !pam

package pamwrap

import (
	"net/http"

	"github.com/CARTAvis/go-carta/pkg/config"
)

func newImpl(cfg config.PAMConfig) (Authenticator, error) {
	return nil, ErrUnsupported
}

func setSessionCookieImpl(w http.ResponseWriter, username string) error {
	return ErrUnsupported
}
