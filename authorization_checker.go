package security

type AuthorizationCheckerAware interface {
	SetAuthorizationChecker(checker AuthorizationChecker)
}

type AuthorizationChecker interface {
	IsGranted(attribute string, object any, token Token) bool
}

type authorizationChecker struct {
	adm AccessDecisionManager
}

func NewAuthorizationChecker(adm AccessDecisionManager) AuthorizationChecker {
	return &authorizationChecker{
		adm: adm,
	}
}

func (a *authorizationChecker) IsGranted(attribute string, object any, token Token) bool {
	if token == nil {
		return false
	}
	return a.adm.Decide(token, []string{attribute}, object)
}
