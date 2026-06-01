package security

import "net/http"

type accessControlListener struct {
	accessMap *accessMap
	adm       AccessDecisionManager
}

func NewAccessControlFirewallListener(accessControls AccessControls, adm AccessDecisionManager) FirewallListener {
	accessMap := newAccessMap()
	for _, accessControl := range accessControls {
		accessMap.Add(
			NewRequestMatcher(
				accessControl.Path(),
				accessControl.Host(),
				accessControl.Port(),
				accessControl.Methods(),
				accessControl.Scheme(),
				accessControl.Ips(),
			),
			accessControl.Roles(),
			accessControl.Scheme(),
		)
	}

	return &accessControlListener{
		accessMap: accessMap,
		adm:       adm,
	}
}

func (l *accessControlListener) AuthenticateRequest(r *http.Request, ctx SecurityContext) error {
	attributes, _ := l.accessMap.Patterns(r)

	rl := len(attributes)
	if rl == 0 || (rl == 1 && attributes[0] == PublicAccess) {
		return nil
	}

	token := ctx.Token()
	if token == nil {
		token = NewNullToken()
		ctx.SetToken(token)
	}

	if !l.adm.Decide(token, attributes, r) {
		return AccessDeniedError
	}

	return nil
}

type accessMapRecord struct {
	rm      RequestMatcher
	roles   []string
	channel *string
}

type accessMap struct {
	records []accessMapRecord
}

func newAccessMap() *accessMap {
	return &accessMap{}
}

func (a *accessMap) Add(rm RequestMatcher, roles []string, channel *string) {
	a.records = append(a.records, accessMapRecord{
		rm:      rm,
		roles:   roles,
		channel: channel,
	})
}

func (a *accessMap) Patterns(r *http.Request) ([]string, *string) {
	for _, record := range a.records {
		if record.rm.Matches(r) {
			return record.roles, record.channel
		}
	}
	return nil, nil
}
