package security

type User interface {
	Id() string
	Identifier() string
	Roles() []string
}
