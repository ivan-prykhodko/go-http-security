package security

import (
	"net/http"
	"regexp"
)

type authenticatorManagerListener struct {
	firewallResolver firewallResolver
}

func NewAuthenticatorManagerListener(firewallConfigs FirewallConfigs) FirewallListener {
	return &authenticatorManagerListener{
		firewallResolver: firewallResolver{firewallConfigs},
	}
}

func (l *authenticatorManagerListener) AuthenticateRequest(r *http.Request, ctx SecurityContext) error {
	firewall, err := l.firewallResolver.Resolve(r)
	if err != nil {
		return err
	}

	ctx.SetFirewallName(firewall.Name())

	for _, authenticator := range firewall.Authenticators() {
		if authenticator.Supports(r) {
			if err = l.executeAuthenticator(authenticator, firewall.Name(), r, ctx); err != nil {
				return err
			}
		}
	}
	if len(firewall.Authenticators()) == 0 {
		ctx.SetToken(NewNullToken())
	}

	return nil
}

func (l *authenticatorManagerListener) executeAuthenticator(authenticator Authenticator, firewallName string, r *http.Request, ctx SecurityContext) error {
	// get the passport from the Authenticator
	passport, err := authenticator.Authenticate(r)
	if err != nil {
		return err
	}

	// TODO: check the passport (e.g. password checking)
	// TODO: check if all badges are resolved

	// create the authentication token
	authenticatedToken, err := authenticator.CreateToken(passport, firewallName)
	if err != nil {
		return err
	}

	// TODO: announce the authentication token
	// TODO: notify about successful authentication

	ctx.SetToken(authenticatedToken)

	return nil
}

type firewallResolver struct {
	firewallConfigs FirewallConfigs
}

func (fr *firewallResolver) Resolve(r *http.Request) (FirewallConfig, error) {
	path := r.URL.Path
	for _, firewallConfig := range fr.firewallConfigs {
		match, err := regexp.MatchString(firewallConfig.Pattern(), path)
		if err != nil {
			return nil, err
		}
		if match {
			return firewallConfig, nil
		}
	}
	return nil, FirewallMissingError
}
