package security

type Config interface {
	RolesHierarchy() map[string][]string
	FirewallConfigs() FirewallConfigs
	AccessControls() AccessControls
	Voters() Voters
}

type config struct {
	roleHierarchy   map[string][]string
	firewallConfigs FirewallConfigs
	accessControl   AccessControls
	voters          Voters
}

func NewConfig(roleHierarchy map[string][]string, firewallConfigs FirewallConfigs, accessControl AccessControls, voters Voters) Config {
	return &config{
		roleHierarchy:   roleHierarchy,
		firewallConfigs: firewallConfigs,
		accessControl:   accessControl,
		voters:          voters,
	}
}

func (c *config) RolesHierarchy() map[string][]string {
	return c.roleHierarchy
}

func (c *config) FirewallConfigs() FirewallConfigs {
	return c.firewallConfigs
}

func (c *config) AccessControls() AccessControls {
	return c.accessControl
}

func (c *config) Voters() Voters {
	return c.voters
}
