package config

import (
	sharedSecurity "github.com/ivan-prykhodko/go-security"
	appSecurity "github.com/ivan-prykhodko/go-security/example/app/security"
	"github.com/ivan-prykhodko/go-security/example/app/security/voter"
	"github.com/labstack/echo"
)

func NewHttpSecurityMiddleware() echo.MiddlewareFunc {
	cfg := newHttpSecurityConfig()
	sm := sharedSecurity.NewProcessor(cfg)
	ah := appSecurity.NewAuthenticationHandler(sm)
	return appSecurity.NewSecurityMiddleware(ah)
}

func newHttpSecurityConfig( /** roleHierarchy, voters and etc */ ) sharedSecurity.Config {
	roleHierarchy := map[string][]string{
		"ROLE_CLIENT_GUEST":  {"ROLE_CLIENT_VIEW", "ROLE_CLIENT_LIST"},
		"ROLE_CLIENT_STAFF":  {"ROLE_CLIENT_GUEST", "ROLE_CLIENT_CREATE", "ROLE_CLIENT_EDIT"},
		"ROLE_CLIENT_EDITOR": {"ROLE_CLIENT_STAFF", "ROLE_CLIENT_DELETE"},
	}
	firewallConfigs := sharedSecurity.FirewallConfigs{
		sharedSecurity.NewFirewallConfig(
			"api",
			"^/",
			[]sharedSecurity.Authenticator{
				appSecurity.NewInternalHeaderAuthenticator(&appSecurity.UserProvider{}),
			},
		),
	}
	accessControls := sharedSecurity.AccessControls{
		sharedSecurity.NewAccessControl(
			"^/private/",
			[]string{sharedSecurity.PublicAccess},
			nil,
			nil,
			nil,
			nil,
			[]string{"127.0.0.1"},
		),
		sharedSecurity.NewAccessControl(
			"^/public/",
			[]string{sharedSecurity.PublicAccess},
			nil,
			nil,
			nil,
			nil,
			nil,
		),
		sharedSecurity.NewAccessControl(
			"^/",
			[]string{sharedSecurity.IsAuthenticatedFully},
			nil,
			nil,
			nil,
			nil,
			nil,
		),
	}
	voters := sharedSecurity.Voters{
		voter.NewClientResourceVoter(),
	}
	config := sharedSecurity.NewConfig(roleHierarchy, firewallConfigs, accessControls, voters)

	return config
}
