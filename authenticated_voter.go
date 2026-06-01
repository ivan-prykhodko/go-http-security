package security

import "slices"

type authenticatedVoter struct {
	atr authenticationTrustResolver
}

func NewAuthenticatedVoter() Voter {
	return &authenticatedVoter{
		atr: authenticationTrustResolver{},
	}
}

func (v *authenticatedVoter) Vote(token Token, subject any, attributes []string) AccessState {
	if len(attributes) == 1 && attributes[0] == PublicAccess {
		return AccessGranted
	}

	result := AccessAbstain
	for _, attribute := range attributes {
		if IsAuthenticatedFully != attribute {
			continue
		}

		result = AccessDenied
		if v.atr.isFullFledged(token) {
			return AccessGranted
		}
	}

	return result
}

func (v *authenticatedVoter) SupportsAttribute(attribute string) bool {
	return slices.Contains([]string{IsAuthenticatedFully, PublicAccess}, attribute)
}

func (v *authenticatedVoter) SupportsType(subject any) bool {
	return true
}

type authenticationTrustResolver struct{}

func (atr authenticationTrustResolver) isFullFledged(token Token) bool {
	return token != nil && token.User() != nil
}
