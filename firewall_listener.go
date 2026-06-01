package security

import "net/http"

type FirewallListener interface {
	AuthenticateRequest(r *http.Request, ctx SecurityContext) error
}
