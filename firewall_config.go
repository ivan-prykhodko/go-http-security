package security

type FirewallConfig interface {
	Name() string
	Pattern() string
	Authenticators() []Authenticator
}

type FirewallConfigs []FirewallConfig

type firewallConfig struct {
	name           string
	pattern        string
	authenticators []Authenticator
}

func NewFirewallConfig(name string, pattern string, authenticators []Authenticator) FirewallConfig {
	return &firewallConfig{
		name:           name,
		pattern:        pattern,
		authenticators: authenticators,
	}
}

func (f *firewallConfig) Name() string {
	return f.name
}

func (f *firewallConfig) Pattern() string {
	return f.pattern
}

func (f *firewallConfig) Authenticators() []Authenticator {
	return f.authenticators
}
