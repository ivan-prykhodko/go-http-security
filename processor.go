package security

import (
	"net/http"
)

type Processor interface {
	AuthenticateRequest(r *http.Request) error
}

type processor struct {
	firewallListeners []FirewallListener
	contextManager    contextManager
}

func NewProcessor(config Config) Processor {
	rolesHierarchy := NewRoleHierarchy(config.RolesHierarchy())
	voters := Voters{
		NewAuthenticatedVoter(),
		NewRoleVoter(),
		NewRoleHierarchyVoter(rolesHierarchy),
	}
	voters = append(voters, config.Voters()...)
	adm := NewAccessDecisionManager(
		voters,
		NewAffirmativeStrategy(false), // TODO: use config
	)
	authorizationChecker := NewAuthorizationChecker(adm)
	for _, voter := range voters {
		if authorizationCheckerAwareVoter, ok := voter.(AuthorizationCheckerAware); ok {
			authorizationCheckerAwareVoter.SetAuthorizationChecker(authorizationChecker)
		}
	}

	return &processor{
		firewallListeners: []FirewallListener{
			NewAuthenticatorManagerListener(config.FirewallConfigs()),
			NewAccessControlFirewallListener(
				config.AccessControls(),
				adm,
			),
		},
		contextManager: newContextManager(authorizationChecker),
	}
}

func (p *processor) AuthenticateRequest(r *http.Request) error {
	ctx := p.contextManager.create()

	for _, fl := range p.firewallListeners {
		if err := fl.AuthenticateRequest(r, ctx); err != nil {
			return err
		}
	}

	p.contextManager.save(ctx, r)

	return nil
}
