package security

type AccessDecisionStrategy interface {
	Decide(results <-chan AccessState) bool
}

type affirmativeStrategy struct {
	allowIfAllAbstainDecisions bool
}

func NewAffirmativeStrategy(allowIfAllAbstainDecisions bool) AccessDecisionStrategy {
	return &affirmativeStrategy{
		allowIfAllAbstainDecisions: allowIfAllAbstainDecisions,
	}
}

func (s *affirmativeStrategy) Decide(results <-chan AccessState) bool {
	var deny uint
	for result := range results {
		if result.Equal(AccessGranted) {
			return true
		}
		if result.Equal(AccessDenied) {
			deny++
		}
	}
	if deny > 0 {
		return false
	}
	return s.allowIfAllAbstainDecisions
}

type ananimousStrategy struct {
	allowIfAllAbstainDecisions bool
}

func NewAnanimousStrategy(allowIfAllAbstainDecisions bool) AccessDecisionStrategy {
	return &ananimousStrategy{
		allowIfAllAbstainDecisions: allowIfAllAbstainDecisions,
	}
}

func (s *ananimousStrategy) Decide(results <-chan AccessState) bool {
	grant := 0
	for result := range results {
		if result.Equal(AccessDenied) {
			return false
		}
		if result.Equal(AccessGranted) {
			grant++
		}
	}
	// no deny votes
	if grant > 0 {
		return true
	}
	return s.allowIfAllAbstainDecisions
}
