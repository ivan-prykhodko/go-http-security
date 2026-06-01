package security

type NullToken struct{}

func NewNullToken() Token {
	return &NullToken{}
}

func (t *NullToken) User() User {
	return nil
}

func (t *NullToken) SetUser(User) {}

func (t *NullToken) UserIdentifier() string {
	return ""
}

func (t *NullToken) Roles() []string {
	return nil
}
