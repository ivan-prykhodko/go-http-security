package security

import (
	"strings"

	sharedSecurity "github.com/ivan-prykhodko/go-security"
)

type UserProvider struct{}

func (p *UserProvider) LoadUserByIdentifier(id, identifier, roles string, args ...string) sharedSecurity.User {
	var user sharedSecurity.User = &User{
		id:         id,
		identifier: identifier,
		roles:      strings.Split(roles, ","),
	}

	return user
}
