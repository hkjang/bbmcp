package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hkjang/bbmcp/internal/settings"
)

// registrationEndpoint answers the way the Keycloak versions bbmcp was tested
// against answered the check's request.
func registrationEndpoint(t *testing.T, status int, body map[string]any, deleted *bool) string {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if r.Header.Get("Authorization") == "Bearer rat" && deleted != nil {
				*deleted = true
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["token_endpoint_auth_method"] != "none" {
			t.Errorf("token_endpoint_auth_method = %v, MCP 클라이언트처럼 none 이어야 합니다", req["token_endpoint_auth_method"])
		}
		if body != nil && body["registration_client_uri"] == "self" {
			body["registration_client_uri"] = srv.URL + "/client/1"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestCheckKeycloakRegistrationReadsEachKeycloakAnswer(t *testing.T) {
	ctx := context.Background()
	kc := settings.Keycloak{}
	cases := []struct {
		name    string
		status  int
		body    map[string]any
		accepts bool
		reason  bool
		problem bool
	}{
		// Keycloak 10.0.2: does not know "none" and fails while converting.
		{"keycloak10", 400, map[string]any{"error": "invalid_client_metadata", "error_description": "Client metadata invalid"}, false, true, false},
		// Keycloak 26.4 with the default Trusted Hosts policy.
		{"keycloak26-trusted-hosts", 403, map[string]any{"error": "insufficient_scope", "error_description": "Policy 'Trusted Hosts' rejected request to client-registration service. Details: Host not trusted."}, false, true, false},
		// Keycloak 26.4 with the policy relaxed: reaches URL validation, rolled back.
		{"keycloak26-open", 400, map[string]any{"error": "invalid_client_metadata", "error_description": "Terms of service URL is not a valid URL"}, true, false, false},
		{"unexpected", 500, map[string]any{"error": "server_error"}, false, false, true},
	}
	for _, c := range cases {
		got := checkKeycloakRegistration(ctx, kc, registrationEndpoint(t, c.status, c.body, nil))
		if got.AcceptsPublicClients != c.accepts || (got.Reason != "") != c.reason || (got.Problem != "") != c.problem {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

// A Keycloak that creates the client despite the bad URL gets it deleted.
func TestCheckKeycloakRegistrationRemovesAClientItCreated(t *testing.T) {
	deleted := false
	endpoint := registrationEndpoint(t, 201, map[string]any{
		"client_id": "x", "registration_client_uri": "self", "registration_access_token": "rat",
	}, &deleted)
	got := checkKeycloakRegistration(context.Background(), settings.Keycloak{}, endpoint)
	if !got.AcceptsPublicClients || !deleted {
		t.Fatalf("accepts=%t deleted=%t", got.AcceptsPublicClients, deleted)
	}
}

func TestCheckKeycloakRegistrationWithoutEndpoint(t *testing.T) {
	got := checkKeycloakRegistration(context.Background(), settings.Keycloak{}, "")
	if got.AcceptsPublicClients || got.Reason == "" {
		t.Fatalf("%+v", got)
	}
}
