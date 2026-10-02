package permission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/settings"
)

// ErrUnavailable means effective permission could not be determined. With
// fail-closed enabled (the default) callers must deny the request.
var ErrUnavailable = errors.New("유효 권한을 확인할 수 없습니다")

// Resolver resolves effective Bitbucket permissions for a user.
//
// Preferred mode is the companion Bitbucket plugin, which asks Bitbucket's own
// PermissionService and therefore agrees with Bitbucket exactly. The REST mode
// is a fallback that combines global, project, repository and group grants.
type Resolver struct {
	store    *settings.Store
	provider *bitbucket.Provider
	plugin   *PluginClient

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	dec Decision
	exp time.Time
}

// NewResolver builds the resolver.
func NewResolver(store *settings.Store, provider *bitbucket.Provider) *Resolver {
	return &Resolver{
		store:    store,
		provider: provider,
		plugin:   NewPluginClient(store),
		cache:    map[string]cacheEntry{},
	}
}

// Reset clears the cache and plugin client after a settings change.
func (r *Resolver) Reset() {
	r.mu.Lock()
	r.cache = map[string]cacheEntry{}
	r.mu.Unlock()
	r.plugin.Reset()
}

func (r *Resolver) cached(key string) (Decision, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[key]
	if !ok || time.Now().After(e.exp) {
		delete(r.cache, key)
		return Decision{}, false
	}
	return e.dec, true
}

func (r *Resolver) store_(key string, dec Decision, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	r.mu.Lock()
	r.cache[key] = cacheEntry{dec: dec, exp: time.Now().Add(ttl)}
	r.mu.Unlock()
}

// Repository resolves the effective permission of username on one repository.
func (r *Resolver) Repository(ctx context.Context, username, projectKey, slug string) (Decision, error) {
	cfg, err := r.store.Permission(ctx)
	if err != nil {
		return Decision{}, err
	}
	key := "repo|" + strings.ToLower(username+"|"+projectKey+"|"+slug)
	if dec, ok := r.cached(key); ok {
		return dec, nil
	}

	var dec Decision
	if cfg.Mode == "plugin" {
		dec, err = r.plugin.Repository(ctx, username, projectKey, slug)
	} else {
		dec, err = r.restRepository(ctx, username, projectKey, slug)
	}
	if err != nil {
		if cfg.FailClosed {
			return Decision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return decide(username, projectKey, slug, None, "unavailable", err.Error()), nil
	}
	r.store_(key, dec, time.Duration(cfg.CacheTTLSec)*time.Second)
	return dec, nil
}

// Project resolves the effective permission of username on one project.
func (r *Resolver) Project(ctx context.Context, username, projectKey string) (Decision, error) {
	cfg, err := r.store.Permission(ctx)
	if err != nil {
		return Decision{}, err
	}
	key := "proj|" + strings.ToLower(username+"|"+projectKey)
	if dec, ok := r.cached(key); ok {
		return dec, nil
	}

	var dec Decision
	if cfg.Mode == "plugin" {
		dec, err = r.plugin.Project(ctx, username, projectKey)
	} else {
		dec, err = r.restProject(ctx, username, projectKey)
	}
	if err != nil {
		if cfg.FailClosed {
			return Decision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return decide(username, projectKey, "", None, "unavailable", err.Error()), nil
	}
	r.store_(key, dec, time.Duration(cfg.CacheTTLSec)*time.Second)
	return dec, nil
}

// restProject computes project permission from global, direct and group grants.
func (r *Resolver) restProject(ctx context.Context, username, projectKey string) (Decision, error) {
	adapter, cred, err := r.serviceCall(ctx)
	if err != nil {
		return Decision{}, err
	}

	level, source := None, "rest"
	if g, err := adapter.GlobalPermission(ctx, cred, username); err == nil {
		if l := fromBitbucket(g); l > level {
			level, source = l, "rest:global"
		}
		if strings.EqualFold(g, "ADMIN") || strings.EqualFold(g, "SYS_ADMIN") {
			return decide(username, projectKey, "", Admin, "rest:global", "전역 관리자"), nil
		}
	}
	if p, err := adapter.ProjectPermissionForUser(ctx, cred, projectKey, username); err == nil {
		if l := fromBitbucket(p); l > level {
			level, source = l, "rest:project"
		}
	} else if !isForbidden(err) {
		return Decision{}, err
	}
	if l, src, err := r.groupLevel(ctx, adapter, cred, username, projectKey, ""); err == nil && l > level {
		level, source = l, src
	}

	// A public project grants read to any licensed user.
	if level == None {
		if proj, err := adapter.Project(ctx, cred, projectKey); err == nil && proj.Public {
			return decide(username, projectKey, "", Read, "rest:public", "공개 프로젝트"), nil
		}
	}
	return decide(username, projectKey, "", level, source, ""), nil
}

// restRepository computes repository permission, inheriting from the project.
func (r *Resolver) restRepository(ctx context.Context, username, projectKey, slug string) (Decision, error) {
	projDec, err := r.restProject(ctx, username, projectKey)
	if err != nil {
		return Decision{}, err
	}
	if projDec.Level == Admin {
		return decide(username, projectKey, slug, Admin, projDec.Source, "프로젝트 권한 상속"), nil
	}

	adapter, cred, err := r.serviceCall(ctx)
	if err != nil {
		return Decision{}, err
	}
	level, source := projDec.Level, projDec.Source
	if p, err := adapter.RepoPermissionForUser(ctx, cred, projectKey, slug, username); err == nil {
		if l := fromBitbucket(p); l > level {
			level, source = l, "rest:repo"
		}
	} else if !isForbidden(err) {
		return Decision{}, err
	}
	if l, src, err := r.groupLevel(ctx, adapter, cred, username, projectKey, slug); err == nil && l > level {
		level, source = l, src
	}
	if level == None {
		if repo, err := adapter.Repository(ctx, cred, projectKey, slug); err == nil && repo.Public {
			return decide(username, projectKey, slug, Read, "rest:public", "공개 저장소"), nil
		}
	}
	return decide(username, projectKey, slug, level, source, ""), nil
}

// groupLevel folds in grants the user receives through group membership.
func (r *Resolver) groupLevel(ctx context.Context, adapter bitbucket.Adapter, cred bitbucket.Credential, username, projectKey, slug string) (Level, string, error) {
	groups, err := adapter.UserGroups(ctx, cred, username)
	if err != nil {
		return None, "", err
	}
	if len(groups) == 0 {
		return None, "", nil
	}
	member := map[string]bool{}
	for _, g := range groups {
		member[strings.ToLower(g)] = true
	}

	best, source := None, ""
	if perms, err := adapter.ProjectGroupPermissions(ctx, cred, projectKey); err == nil {
		for g, p := range perms {
			if member[g] {
				if l := fromBitbucket(p); l > best {
					best, source = l, "rest:project-group:"+g
				}
			}
		}
	}
	if slug != "" {
		if perms, err := adapter.RepoGroupPermissions(ctx, cred, projectKey, slug); err == nil {
			for g, p := range perms {
				if member[g] {
					if l := fromBitbucket(p); l > best {
						best, source = l, "rest:repo-group:"+g
					}
				}
			}
		}
	}
	return best, source, nil
}

// BranchWritable reports whether the user may write to a specific branch,
// taking branch restrictions into account on top of repository write.
func (r *Resolver) BranchWritable(ctx context.Context, username, projectKey, slug, branch string) (bool, string, error) {
	dec, err := r.Repository(ctx, username, projectKey, slug)
	if err != nil {
		return false, "", err
	}
	if !dec.Write {
		return false, "저장소 쓰기 권한이 없습니다", nil
	}
	if dec.Admin {
		return true, "저장소 관리자", nil
	}

	adapter, cred, err := r.serviceCall(ctx)
	if err != nil {
		return false, "", err
	}
	raw, err := adapter.BranchRestrictions(ctx, cred, projectKey, slug)
	if err != nil {
		cfg, _ := r.store.Permission(ctx)
		if cfg.FailClosed {
			return false, "브랜치 제한을 확인할 수 없습니다", fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return true, "브랜치 제한 확인 생략", nil
	}
	groups, _ := adapter.UserGroups(ctx, cred, username)
	allowed, reason := evaluateRestrictions(raw, username, groups, branch)
	return allowed, reason, nil
}

func (r *Resolver) serviceCall(ctx context.Context) (bitbucket.Adapter, bitbucket.Credential, error) {
	adapter, _, err := r.provider.Adapter(ctx)
	if err != nil {
		return nil, bitbucket.Credential{}, err
	}
	cred, err := r.provider.ServiceCredential(ctx)
	if err != nil {
		return nil, bitbucket.Credential{}, err
	}
	return adapter, cred, nil
}

func isForbidden(err error) bool {
	var apiErr *bitbucket.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == 401 || apiErr.Status == 403 || apiErr.Status == 404
	}
	return false
}
