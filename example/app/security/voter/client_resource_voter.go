package voter

import (
	"slices"

	sharedSecurity "github.com/ivan-prykhodko/go-security"
	"github.com/ivan-prykhodko/go-security/example/app/api/resource"
)

type clientResourceVoter struct {
	sharedSecurity.AttributeVoter
	authorizationChecker sharedSecurity.AuthorizationChecker
	resourceName         string
	attributes           []string
}

func NewClientResourceVoter() sharedSecurity.Voter {
	voter := &clientResourceVoter{
		AttributeVoter: sharedSecurity.AttributeVoter{},
		resourceName:   "ClientResource",
		attributes:     []string{"LIST", "CREATE", "VIEW", "EDIT", "DELETE"},
	}
	voter.AttributeBasedVoter = voter
	return voter
}

func (v *clientResourceVoter) Supports(attribute string, subject any) bool {
	if !slices.Contains(v.attributes, attribute) {
		return false
	}
	if _, isResource := subject.(resource.ClientResource); isResource {
		return true
	}
	if subjectString, isString := subject.(string); isString {
		return v.resourceName == subjectString
	}
	return false
}

func (v *clientResourceVoter) VoteOnAttribute(attribute string, subject any, token sharedSecurity.Token) bool {
	permission := v.getPermission(attribute)
	if !v.authorizationChecker.IsGranted(permission, nil, token) {
		return false
	}
	if _, isString := subject.(string); isString {
		return true
	}
	// Some other conditions, checks, and etc if it's necessary
	return true
}

func (v *clientResourceVoter) SetAuthorizationChecker(checker sharedSecurity.AuthorizationChecker) {
	v.authorizationChecker = checker
}

func (v *clientResourceVoter) getPermission(attribute string) string {
	return "ROLE_CLIENT_" + attribute
}
