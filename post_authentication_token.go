package security

type PostAuthenticationToken struct {
	user         User
	roles        []string
	firewallName string
}

func NewPostAuthenticationToken(user User, roles []string, firewallName string) Token {
	return &PostAuthenticationToken{
		user:         user,
		roles:        roles,
		firewallName: firewallName,
	}
}

func (t *PostAuthenticationToken) User() User {
	return t.user
}

func (t *PostAuthenticationToken) SetUser(user User) {
	t.user = user
}

func (t *PostAuthenticationToken) UserIdentifier() string {
	return t.user.Identifier()
}

func (t *PostAuthenticationToken) Roles() []string {
	return t.roles
}

func (t *PostAuthenticationToken) FirewallName() string {
	return t.firewallName
}
