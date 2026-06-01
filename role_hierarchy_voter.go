package security

type roleHierarchyVoter struct {
	rh RoleHierarchy
	roleVoter
}

func NewRoleHierarchyVoter(rh RoleHierarchy) Voter {
	rhv := &roleHierarchyVoter{
		rh:        rh,
		roleVoter: *NewRoleVoter().(*roleVoter),
	}
	rhv.voterRolesExtractor = any(rhv).(voterRolesExtractor)
	return rhv
}

func (v *roleHierarchyVoter) extractRoles(token Token) []string {
	return v.rh.ReachableRoleNames(token.Roles())
}
