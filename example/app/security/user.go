package security

type userIdAware interface {
	Roles() []string
}

type userRolesAware interface {
	Roles() []string
}

type User struct {
	id         string
	identifier string
	roles      []string
}

func (u *User) Id() string {
	return u.id
}

func (u *User) Identifier() string {
	return u.identifier
}

func (u *User) Roles() []string {
	return u.roles
}
