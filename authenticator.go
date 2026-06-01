package security

import (
	"net/http"
)

// TODO: onAuthenticationSuccess
// TODO: onAuthenticationFailure
type Authenticator interface {
	Supports(r *http.Request) bool
	Authenticate(r *http.Request) (Passport, error)
	CreateToken(passport Passport, firewallName string) (Token, error)
}
