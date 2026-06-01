package security

type UserProvider interface {
	LoadUserByIdentifier(id, identifier, roles string, args ...string) User
}
