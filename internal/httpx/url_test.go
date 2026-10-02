package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://bbmcp.company.local/", "https://bbmcp.company.local"},
		{"  https://bbmcp.company.local  ", "https://bbmcp.company.local"},
		{"HTTPS://BBMCP.Company.Local", "https://bbmcp.company.local"},
		{"https://bbmcp.company.local:443", "https://bbmcp.company.local"},
		{"http://bbmcp.company.local:80", "http://bbmcp.company.local"},
		{"https://bbmcp.company.local:8443", "https://bbmcp.company.local:8443"},
		{"https://sso.local/realms/company/", "https://sso.local/realms/company"},
		{"https://sso.local/realms/company?x=1", "https://sso.local/realms/company"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeBaseURL(c.in); got != c.want {
			t.Errorf("NormalizeBaseURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeRedirectURIKeepsPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://bbmcp.local/auth/oidc/callback", "https://bbmcp.local/auth/oidc/callback"},
		{" https://BBMCP.local:443/auth/oidc/callback ", "https://bbmcp.local/auth/oidc/callback"},
		{"https://bbmcp.local/", "https://bbmcp.local"},
		{"https://bbmcp.local/auth/oidc/callback#x", "https://bbmcp.local/auth/oidc/callback"},
	}
	for _, c := range cases {
		if got := NormalizeRedirectURI(c.in); got != c.want {
			t.Errorf("NormalizeRedirectURI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateAbsoluteURL(t *testing.T) {
	if err := ValidateAbsoluteURL("Issuer", "", false); err != nil {
		t.Errorf("빈 값은 허용해야 합니다: %v", err)
	}
	if err := ValidateAbsoluteURL("Issuer", "https://sso.local/realms/x", false); err != nil {
		t.Errorf("정상 URL 이 거부되었습니다: %v", err)
	}
	for _, bad := range []string{
		"sso.local/realms/x",            // 스킴 없음
		"ftp://sso.local",               // 지원하지 않는 스킴
		"https://",                      // 호스트 없음
		"https://sso.local/realms?x=1",  // 질의 문자열
		"https://sso.local/realms#frag", // 프래그먼트
	} {
		if err := ValidateAbsoluteURL("Issuer", bad, false); err == nil {
			t.Errorf("잘못된 URL 이 통과했습니다: %q", bad)
		}
	}
	if err := ValidateAbsoluteURL("Redirect", "http://bbmcp.company.local/cb", true); err == nil {
		t.Error("https 요구 시 평문 http 가 통과했습니다")
	}
	if err := ValidateAbsoluteURL("Redirect", "http://127.0.0.1:1234/cb", true); err != nil {
		t.Errorf("루프백은 https 요구에서 예외여야 합니다: %v", err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, host := range []string{"localhost", "localhost:5173", "127.0.0.1", "127.0.0.1:41234", "[::1]:8080"} {
		if !IsLoopbackHost(host) {
			t.Errorf("%q 를 루프백으로 인식하지 못했습니다", host)
		}
	}
	for _, host := range []string{"bbmcp.company.local", "10.0.0.5:8080"} {
		if IsLoopbackHost(host) {
			t.Errorf("%q 를 루프백으로 잘못 인식했습니다", host)
		}
	}
}

func TestRequestBaseURLHonoursProxyHeadersOnlyWhenTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://internal:8080/api", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "bbmcp.company.local")

	if got := RequestBaseURL(req, true); got != "https://bbmcp.company.local" {
		t.Errorf("프록시 신뢰 시 = %q", got)
	}
	// Without trust, a forged header must not change the origin bbmcp builds
	// redirect URIs from.
	if got := RequestBaseURL(req, false); got != "http://internal:8080" {
		t.Errorf("프록시 미신뢰 시 = %q", got)
	}
}

func TestRequestBaseURLUsesFirstForwardedValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://internal/api", nil)
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("X-Forwarded-Host", "bbmcp.company.local, inner.local")
	if got := RequestBaseURL(req, true); got != "https://bbmcp.company.local" {
		t.Errorf("프록시 체인에서 = %q", got)
	}
}

func TestRequestBaseURLJoinsForwardedPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://internal/api", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "bbmcp.company.local")
	req.Header.Set("X-Forwarded-Port", "8443")
	if got := RequestBaseURL(req, true); got != "https://bbmcp.company.local:8443" {
		t.Errorf("포워딩 포트 반영 = %q", got)
	}

	// A default port must not appear, or the string stops matching Keycloak's
	// registered redirect URI.
	req.Header.Set("X-Forwarded-Port", "443")
	if got := RequestBaseURL(req, true); got != "https://bbmcp.company.local" {
		t.Errorf("기본 포트가 남았습니다: %q", got)
	}
}
