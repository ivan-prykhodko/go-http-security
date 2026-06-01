package security

type Token interface {
	User() User
	SetUser(User)
	UserIdentifier() string
	Roles() []string
}
