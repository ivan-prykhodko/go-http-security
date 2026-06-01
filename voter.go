package security

type Voters []Voter

type Voter interface {
	Vote(token Token, subject any, attributes []string) AccessState
}

type CacheableVoter interface {
	SupportsAttribute(attribute string) bool
	SupportsType(subject any) bool
}

type AttributeBasedVoter interface {
	Supports(attribute string, subject any) bool
	VoteOnAttribute(attribute string, subject any, token Token) bool
}

type voterRolesExtractor interface {
	extractRoles(token Token) []string
}
