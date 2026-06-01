package security

import "strings"

type roleVoter struct {
	prefix string
	voterRolesExtractor
}

func NewRoleVoter() Voter {
	rv := &roleVoter{
		prefix: "ROLE_",
	}
	rv.voterRolesExtractor = any(rv).(voterRolesExtractor)
	return rv
}

func (v *roleVoter) Vote(token Token, subject any, attributes []string) AccessState {
	result := AccessAbstain
	roles := v.voterRolesExtractor.extractRoles(token)

	for _, attribute := range attributes {
		if !strings.HasPrefix(attribute, v.prefix) {
			continue
		}
		result = AccessDenied
		for _, role := range roles {
			if role == attribute {
				result = AccessGranted
			}
		}
	}

	return result
}

func (v *roleVoter) SupportsAttribute(attribute string) bool {
	return strings.HasPrefix(attribute, v.prefix)
}

func (v *roleVoter) SupportsType(subject any) bool {
	return true
}

func (v *roleVoter) extractRoles(token Token) []string {
	return token.Roles()
}
