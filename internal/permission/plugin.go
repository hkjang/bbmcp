package permission

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/bbmcp/internal/settings"
)

// PluginClient talks to the companion bbmcp permission plugin installed in
// Bitbucket, which answers from Bitbucket's own PermissionService.
type PluginClient struct {
	store *settings.Store

	mu   sync.Mutex
	key  string
	http *http.Client
}

// NewPluginClient builds the client.
func NewPluginClient(store *settings.Store) *PluginClient {
	return &PluginClient{store: store}
}

// Reset drops the cached HTTP client.
func (p *PluginClient) Reset() {
	p.mu.Lock()
	p.http, p.key = nil, ""
	p.mu.Unlock()
}

func (p *PluginClient) client(cfg settings.Permission) *http.Client {
	key := fmt.Sprintf("%s|%d", cfg.PluginBaseURL, cfg.TimeoutSec)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == key && p.http != nil {
		return p.http
	}
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	p.http = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	p.key = key
	return p.http
}

type pluginPermissions struct {
	Username    string `json:"username"`
	Project     string `json:"project"`
	Repository  string `json:"repository"`
	Permissions struct {
		Read  bool `json:"read"`
		Write bool `json:"write"`
		Admin bool `json:"admin"`
	} `json:"permissions"`
	Effective string `json:"effective"`
}

// Repository asks the plugin for repository-level effective permission.
func (p *PluginClient) Repository(ctx context.Context, username, projectKey, slug string) (Decision, error) {
	path := fmt.Sprintf("/rest/mcp-permission/1.0/users/%s/repositories/%s/%s",
		url.PathEscape(username), url.PathEscape(projectKey), url.PathEscape(slug))
	var out pluginPermissions
	if err := p.get(ctx, path, &out); err != nil {
		return Decision{}, err
	}
	return decide(username, projectKey, slug, levelFromFlags(out), "plugin", out.Effective), nil
}

// Project asks the plugin for project-level effective permission.
func (p *PluginClient) Project(ctx context.Context, username, projectKey string) (Decision, error) {
	path := fmt.Sprintf("/rest/mcp-permission/1.0/users/%s/projects/%s",
		url.PathEscape(username), url.PathEscape(projectKey))
	var out pluginPermissions
	if err := p.get(ctx, path, &out); err != nil {
		return Decision{}, err
	}
	return decide(username, projectKey, "", levelFromFlags(out), "plugin", out.Effective), nil
}

// Health pings the plugin.
func (p *PluginClient) Health(ctx context.Context) error {
	var out map[string]any
	return p.get(ctx, "/rest/mcp-permission/1.0/health", &out)
}

func levelFromFlags(out pluginPermissions) Level {
	switch {
	case out.Permissions.Admin:
		return Admin
	case out.Permissions.Write:
		return Write
	case out.Permissions.Read:
		return Read
	default:
		return None
	}
}

// get performs a signed GET against the plugin.
func (p *PluginClient) get(ctx context.Context, path string, out any) error {
	cfg, err := p.store.Permission(ctx)
	if err != nil {
		return err
	}
	base := strings.TrimRight(cfg.PluginBaseURL, "/")
	if base == "" {
		return errors.New("권한 플러그인 URL이 설정되지 않았습니다")
	}
	secret, err := p.store.Reveal(cfg.PluginSecretEnc)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "\n" + path))
		req.Header.Set("X-BBMCP-Timestamp", ts)
		req.Header.Set("X-BBMCP-Signature", hex.EncodeToString(mac.Sum(nil)))
		req.Header.Set("X-BBMCP-Token", secret)
	}

	resp, err := p.client(cfg).Do(req)
	if err != nil {
		return fmt.Errorf("권한 플러그인 호출 실패: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("권한 플러그인 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

// PluginHealth is exposed on the resolver so the admin console can probe the
// plugin without reaching into the client.
func (r *Resolver) PluginHealth(ctx context.Context) error { return r.plugin.Health(ctx) }
