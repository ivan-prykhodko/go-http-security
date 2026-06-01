package security

type TokenStorage interface {
	Token() Token
	SetToken(t Token)
}

type tokenStorage struct {
	token Token
}

func NewTokenStorage() TokenStorage {
	return &tokenStorage{}
}

func (t *tokenStorage) Token() Token {
	return t.token
}

func (t *tokenStorage) SetToken(token Token) {
	t.token = token
}
