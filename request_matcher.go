package security

import (
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type RequestMatcher interface {
	Matches(r *http.Request) bool
}

type requestMatcher struct {
	path    string
	host    *string
	port    *int
	methods []string
	scheme  *string
	ips     []string
}

func NewRequestMatcher(path string, host *string, port *int, methods []string, scheme *string, ips []string) RequestMatcher {
	for i, method := range methods {
		methods[i] = strings.ToUpper(method)
	}
	if scheme != nil {
		*scheme = strings.ToLower(*scheme)
	}

	return &requestMatcher{
		path:    path,
		host:    host,
		port:    port,
		methods: methods,
		scheme:  scheme,
		ips:     ips,
	}
}

func (m *requestMatcher) Matches(r *http.Request) bool {
	if m.scheme != nil && *m.scheme != r.URL.Scheme {
		return false
	}

	if len(m.methods) != 0 && !slices.Contains(m.methods, r.Method) {
		return false
	}

	match, err := regexp.MatchString(m.path, r.URL.Path)
	if err != nil || !match {
		return false
	}

	if m.host != nil {
		host := r.URL.Hostname()
		match, err := regexp.MatchString(*m.host, host)
		if err != nil || !match {
			return false
		}
	}

	if m.port != nil {
		port, err := strconv.Atoi(r.URL.Port())
		if err != nil || *(m.port) != port {
			return false
		}
	}

	if m.ips != nil {
		clientIp := r.Header.Get("X-Forwarded-For")
		if clientIp != "" {
			clientIp = strings.Split(clientIp, ",")[0]
		}
		if !m.checkIp(clientIp) {
			return false
		}
	}

	return true
}

func (m *requestMatcher) checkIp(requestIp string) bool {
	for _, ip := range m.ips {
		if m.doCheckIp(requestIp, ip) {
			return true
		}
	}
	return false
}

func (m *requestMatcher) doCheckIp(requestIp, ipOrCIDR string) bool {
	ip := net.ParseIP(requestIp)
	if ip == nil {
		return false
	}

	if strings.Contains(ipOrCIDR, "/") {
		_, network, err := net.ParseCIDR(ipOrCIDR)
		if err != nil {
			return false
		}

		return network.Contains(ip)
	}

	target := net.ParseIP(ipOrCIDR)
	if target == nil {
		return false
	}

	return ip.Equal(target)
}
