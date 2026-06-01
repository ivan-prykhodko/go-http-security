package security

import (
	"fmt"
	"reflect"
)

type AccessDecisionManager interface {
	Decide(token Token, attributes []string, object any) bool
}

type accessDecisionManager struct {
	voters                Voters
	strategy              AccessDecisionStrategy
	votersCacheAttributes map[string]map[int]bool
	votersCacheObject     map[string]map[int]bool
}

func NewAccessDecisionManager(voters Voters, strategy AccessDecisionStrategy) AccessDecisionManager {
	return &accessDecisionManager{
		voters:                voters,
		strategy:              strategy,
		votersCacheAttributes: make(map[string]map[int]bool),
		votersCacheObject:     make(map[string]map[int]bool),
	}
}

func (dm *accessDecisionManager) Decide(token Token, attributes []string, object any) bool {
	return dm.strategy.Decide(dm.collectResults(token, attributes, object))
}

func (dm *accessDecisionManager) collectResults(token Token, attributes []string, object any) <-chan AccessState {
	var results = make(chan AccessState)
	go func() {
		defer close(results)
		for voter := range dm.getVoters(attributes, object) {
			results <- voter.Vote(token, object, attributes)
		}
	}()
	return results
}

func (dm *accessDecisionManager) getVoters(attributes []string, object any) <-chan Voter {
	var voters = make(chan Voter)
	go func() {
		defer close(voters)
		for vi, voter := range dm.voters {
			cacheableVoter, cacheable := voter.(CacheableVoter)
			if !cacheable {
				voters <- voter
				continue
			}

			supports := true
			for _, attribute := range attributes {
				if _, ok := dm.votersCacheAttributes[attribute][vi]; !ok {
					if _, ok := dm.votersCacheAttributes[attribute]; !ok {
						dm.votersCacheAttributes[attribute] = make(map[int]bool)
					}
					dm.votersCacheAttributes[attribute][vi] = cacheableVoter.SupportsAttribute(attribute)
				} else {
					supports = dm.votersCacheAttributes[attribute][vi]
				}
				if supports {
					break
				}
			}
			if !supports {
				continue
			}
			keyObject := dm.getKeyObject(object)
			if _, ok := dm.votersCacheObject[keyObject][vi]; !ok {
				if _, ok := dm.votersCacheObject[keyObject]; !ok {
					dm.votersCacheObject[keyObject] = make(map[int]bool)
				}
				dm.votersCacheObject[keyObject][vi] = cacheableVoter.SupportsType(object)
			} else {
				supports = dm.votersCacheObject[keyObject][vi]
			}
			if !supports {
				continue
			}
			voters <- voter
		}
	}()
	return voters
}

func (dm *accessDecisionManager) getKeyObject(object any) string {
	if object == nil {
		return "nil"
	}
	r := reflect.TypeOf(object)
	return fmt.Sprintf("%s.%s", r.PkgPath(), r.Name())
}
