package security

type Passport interface {
	User() (User, error)
	Badges() map[string]Badge
	HasBadge(name string) bool
	Badge(name string) Badge
}

type selfValidatingPassport struct {
	user   User
	badges map[string]Badge
}

func NewSelfValidatingPassport(userBadge Badge, badges []Badge) Passport {
	passport := &selfValidatingPassport{
		user:   nil,
		badges: make(map[string]Badge),
	}
	passport.addBadge(userBadge)
	if badges != nil {
		for _, badge := range badges {
			passport.addBadge(badge)
		}
	}
	return passport
}

func (p *selfValidatingPassport) User() (User, error) {
	if p.user != nil {
		return p.user, nil
	}

	var err error
	userBadge, ok := p.badges[UserBadgeName].(*userBadge)
	if !ok {
		return nil, UserBadgeNotFountError
	}
	p.user, err = userBadge.User()
	if err != nil {
		return nil, err
	}

	return p.user, nil
}

func (p *selfValidatingPassport) Badges() map[string]Badge {
	return p.badges
}

func (p *selfValidatingPassport) addBadge(badge Badge) {
	p.badges[badge.Name()] = badge
}

func (p *selfValidatingPassport) HasBadge(name string) bool {
	_, ok := p.badges[name]
	return ok
}

func (p *selfValidatingPassport) Badge(name string) Badge {
	return p.badges[name]
}
