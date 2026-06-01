package security

import (
	"net/http"

	sharedSecurity "github.com/ivan-prykhodko/go-security"
)

type AuthenticationHandler struct {
	sm sharedSecurity.Processor
}

func NewAuthenticationHandler(sm sharedSecurity.Processor) *AuthenticationHandler {
	return &AuthenticationHandler{sm: sm}
}

func (h *AuthenticationHandler) Handle(r *http.Request) error {
	return h.sm.AuthenticateRequest(r)
}
