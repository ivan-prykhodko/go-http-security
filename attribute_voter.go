package security

type AttributeVoter struct {
	AttributeBasedVoter
}

func (v *AttributeVoter) Vote(token Token, subject any, attributes []string) AccessState {
	// abstain vote by default in case none of the attributes are supported
	vote := AccessAbstain
	for _, attribute := range attributes {
		if !v.AttributeBasedVoter.Supports(attribute, subject) {
			continue
		}
		// as soon as at least one attribute is supported, default is to deny access
		vote = AccessDenied
		if v.AttributeBasedVoter.VoteOnAttribute(attribute, subject, token) {
			// grant access as soon as at least one attribute returns a positive response
			return AccessGranted
		}
	}
	return vote
}
