//go:build pam
// +build pam

package pam

import (
	"context"

	"github.com/msteinert/pam"

	"github.com/CARTAvis/go-carta/pkg/config"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
)

type PAMAuthenticator struct {
	serviceName string
}

func New(cfg config.PAMConfig) *PAMAuthenticator {
	return &PAMAuthenticator{serviceName: cfg.ServiceName}
}

// AuthenticateCredentials runs PAM for an explicit username/password pair.
// This is used by the HTML login form handler.
func (p *PAMAuthenticator) AuthenticateCredentials(ctx context.Context, username, password string) (*auth.User, error) {
	t, err := pam.StartFunc(p.serviceName, username,
		func(s pam.Style, msg string) (string, error) {
			switch s {
			case pam.PromptEchoOff, pam.PromptEchoOn:
				return password, nil
			default:
				return "", nil
			}
		},
	)
	if err != nil {
		return nil, err
	}

	if err := t.Authenticate(0); err != nil {
		return nil, err
	}

	// You can look up UID/groups here if you want.
	return &auth.User{
		Username: username,
		Source:   auth.SourcePAM,
		Claims:   map[string]any{},
	}, nil
}
