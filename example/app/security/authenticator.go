package security

import (
	"net/http"

	sharedSecurity "github.com/ivan-prykhodko/go-http-security"
)

type InternalHeaderAuthenticator struct {
	userProvider sharedSecurity.UserProvider
}

func NewInternalHeaderAuthenticator(userProvider sharedSecurity.UserProvider) *InternalHeaderAuthenticator {
	return &InternalHeaderAuthenticator{
		userProvider: userProvider,
	}
}

func (a *InternalHeaderAuthenticator) Supports(r *http.Request) bool {
	return r.Header.Get("x-user-id") != "" &&
		r.Header.Get("x-user-identifier") != "" &&
		r.Header.Get("x-user-roles") != ""
}

func (a *InternalHeaderAuthenticator) Authenticate(r *http.Request) (sharedSecurity.Passport, error) {
	userId := r.Header.Get("x-user-id")
	userIdentifier := r.Header.Get("x-user-identifier")
	userRoles := r.Header.Get("x-user-roles")

	userBadge := sharedSecurity.NewUserBadge(
		userIdentifier,
		func(userIdentifier string, attributes []string) (sharedSecurity.User, error) {
			return a.userProvider.LoadUserByIdentifier(userId, userIdentifier, userRoles), nil
		},
		nil,
	)
	var passport any = sharedSecurity.NewSelfValidatingPassport(userBadge, nil)

	return passport.(sharedSecurity.Passport), nil
}

func (a *InternalHeaderAuthenticator) CreateToken(passport sharedSecurity.Passport, firewallName string) (sharedSecurity.Token, error) {
	user, err := passport.User()
	if err != nil {
		return nil, err
	}
	var token sharedSecurity.Token = sharedSecurity.NewPostAuthenticationToken(user, user.Roles(), firewallName)

	return token, nil
}
