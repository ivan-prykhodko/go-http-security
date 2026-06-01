package security

import (
	"slices"

	islices "github.com/ivan-prykhodko/go-slices"
)

type RoleHierarchy interface {
	ReachableRoleNames(roles []string) []string
}

type roleHierarchy struct {
	hierarchy map[string][]string
	roles     map[string][]string
}

func NewRoleHierarchy(hierarchy map[string][]string) RoleHierarchy {
	return &roleHierarchy{
		hierarchy: hierarchy,
		roles:     buildRoleMap(hierarchy),
	}
}

func (hr *roleHierarchy) ReachableRoleNames(roles []string) []string {
	reachableRoles := slices.Clone(roles)
	for _, role := range roles {
		if _, ok := hr.roles[role]; !ok {
			continue
		}
		for _, r := range hr.roles[role] {
			reachableRoles = append(reachableRoles, r)
		}
	}
	return islices.Unique(reachableRoles)
}

func buildRoleMap(hierarchy map[string][]string) map[string][]string {
	var m = make(map[string][]string, len(hierarchy))

	for mainRole, roles := range hierarchy {
		m[mainRole] = slices.Clone(roles)
		visited := make([]string, 0)
		additionalRoles := slices.Clone(roles)

		i := 0
		for i < len(additionalRoles) {
			role := additionalRoles[i]
			i++
			if _, ok := hierarchy[role]; !ok {
				continue
			}

			visited = append(visited, role)

			for _, roleToAdd := range hierarchy[role] {
				m[mainRole] = append(m[mainRole], roleToAdd)
			}

			for _, additionalRole := range islices.Diff(hierarchy[role], visited) {
				additionalRoles = append(additionalRoles, additionalRole)
			}
		}

		m[mainRole] = islices.Unique(m[mainRole])
	}

	return m
}
