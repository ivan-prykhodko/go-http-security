package security

const UserBadgeName = "UserBadge"

type Badge interface {
	Name() string
}

type UserLoader func(string, []string) (User, error)

type userBadge struct {
	userIdentifier string
	loader         UserLoader
	attributes     []string
	user           User
}

func NewUserBadge(userIdentifier string, loader UserLoader, attributes []string) Badge {
	return &userBadge{
		userIdentifier: userIdentifier,
		loader:         loader,
		attributes:     attributes,
	}
}

func (b *userBadge) Name() string {
	return UserBadgeName
}

func (b *userBadge) UserIdentifier() string {
	return b.userIdentifier
}

func (b *userBadge) Attributes() []string {
	return b.attributes
}

func (b *userBadge) User() (User, error) {
	if b.user != nil {
		return b.user, nil
	}

	user, err := b.loader(b.userIdentifier, b.attributes)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, UserNotFoundError
	}
	b.user = user

	return b.user, nil
}
