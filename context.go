package security

type SecurityContext interface {
	FirewallName() string
	SetFirewallName(name string)
	Token() Token
	SetToken(token Token)
	IsGranted(attribute string, object any) bool
}

type securityContext struct {
	firewallName         string
	tokenStorage         TokenStorage
	authorizationChecker AuthorizationChecker
}

func NewSecurityContext(tokenStorage TokenStorage, authorizationChecker AuthorizationChecker) SecurityContext {
	return &securityContext{
		tokenStorage:         tokenStorage,
		authorizationChecker: authorizationChecker,
	}
}

func (sc *securityContext) FirewallName() string {
	return sc.firewallName
}

func (sc *securityContext) SetFirewallName(name string) {
	sc.firewallName = name
}

func (sc *securityContext) Token() Token {
	return sc.tokenStorage.Token()
}

func (sc *securityContext) SetToken(token Token) {
	sc.tokenStorage.SetToken(token)
}

func (sc *securityContext) IsGranted(attribute string, object any) bool {
	return sc.authorizationChecker.IsGranted(attribute, object, sc.Token())
}
