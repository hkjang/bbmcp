package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// URL handling for OAuth redirects.
//
// Keycloak compares redirect URIs as strings against its registered list, so a
// stray trailing slash, an upper-case host or a default port that is spelled
// out are all enough to produce "Invalid parameter: redirect_uri". Everything
// bbmcp sends to Keycloak goes through these helpers so the value is stable and
// matches what the admin console tells the operator to register.

// NormalizeBaseURL cleans an origin: trims spaces, lower-cases the scheme and
// host, drops a default port and removes any trailing slash.
func NormalizeBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimRight(raw, "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = normalizeHost(u.Scheme, u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// NormalizeRedirectURI cleans a full redirect URI, keeping its path intact.
func NormalizeRedirectURI(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = normalizeHost(u.Scheme, u.Host)
	u.Fragment = ""
	// A bare origin keeps no trailing slash; a real path keeps its shape.
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String()
}

// normalizeHost lower-cases the host and strips the scheme's default port.
func normalizeHost(scheme, host string) string {
	host = strings.ToLower(host)
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return h
	}
	return host
}

// ValidateAbsoluteURL checks an operator-entered URL and explains what is wrong
// in terms they can act on, rather than letting Keycloak reject it later.
func ValidateAbsoluteURL(label, raw string, requireHTTPS bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: 주소 형식이 올바르지 않습니다 (%v)", label, err)
	}
	switch {
	case u.Scheme == "":
		return fmt.Errorf("%s: http:// 또는 https:// 로 시작해야 합니다", label)
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("%s: 지원하지 않는 프로토콜입니다 (%s)", label, u.Scheme)
	case u.Host == "":
		return fmt.Errorf("%s: 호스트가 없습니다", label)
	case strings.ContainsAny(raw, " \t\n"):
		return fmt.Errorf("%s: 공백이 포함되어 있습니다", label)
	case u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%s: 질의 문자열이나 프래그먼트를 포함할 수 없습니다", label)
	}
	if requireHTTPS && u.Scheme != "https" && !IsLoopbackHost(u.Host) {
		return fmt.Errorf("%s: 루프백이 아닌 주소는 https 여야 합니다", label)
	}
	return nil
}

// IsLoopbackHost reports whether a host refers to this machine.
func IsLoopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// RequestBaseURL derives this gateway's public origin from a request, honouring
// the forwarding headers a reverse proxy sets.
//
// Proxy chains append to X-Forwarded-*, so only the first value — the one the
// client actually addressed — is used.
func RequestBaseURL(r *http.Request, trustProxy bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host

	if trustProxy {
		if v := firstForwarded(r.Header.Get("X-Forwarded-Proto")); v != "" {
			scheme = strings.ToLower(v)
		}
		if v := firstForwarded(r.Header.Get("X-Forwarded-Host")); v != "" {
			host = v
			// A proxy that splits host and port sends the port separately.
			if port := firstForwarded(r.Header.Get("X-Forwarded-Port")); port != "" &&
				!strings.Contains(host, ":") {
				if !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
					host = net.JoinHostPort(host, port)
				}
			}
		}
	}
	return NormalizeBaseURL(scheme + "://" + host)
}

func firstForwarded(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[0])
}

// CleanBaseURL validates the operator's raw input and returns the normalised
// form.
//
// Validation runs on what they typed, not on the normalised value: a query
// string or fragment is a mistake worth reporting, while a trailing slash or
// upper-case host is pure formatting and is quietly fixed.
func CleanBaseURL(label, raw string, requireHTTPS bool) (string, error) {
	if err := ValidateAbsoluteURL(label, raw, requireHTTPS); err != nil {
		return "", err
	}
	return NormalizeBaseURL(raw), nil
}

// CleanRedirectURI validates raw input and returns the normalised redirect URI.
func CleanRedirectURI(label, raw string, requireHTTPS bool) (string, error) {
	if err := ValidateAbsoluteURL(label, raw, requireHTTPS); err != nil {
		return "", err
	}
	return NormalizeRedirectURI(raw), nil
}
