package security

type AccessControls []AccessControl

type AccessControl interface {
	Path() string
	Roles() []string
	Host() *string
	Port() *int
	Methods() []string
	Scheme() *string
	Ips() []string
}

type accessControl struct {
	path    string
	roles   []string
	host    *string
	port    *int
	methods []string
	scheme  *string
	ips     []string
}

func NewAccessControl(path string, roles []string, host *string, port *int, methods []string, scheme *string, ips []string) AccessControl {
	return &accessControl{
		path:    path,
		roles:   roles,
		host:    host,
		port:    port,
		methods: methods,
		scheme:  scheme,
		ips:     ips,
	}
}

func (a *accessControl) Path() string {
	return a.path
}

func (a *accessControl) Roles() []string {
	return a.roles
}

func (a *accessControl) Host() *string {
	return a.host
}

func (a *accessControl) Port() *int {
	return a.port
}

func (a *accessControl) Methods() []string {
	return a.methods
}

func (a *accessControl) Scheme() *string {
	return a.scheme
}

func (a *accessControl) Ips() []string {
	return a.ips
}
