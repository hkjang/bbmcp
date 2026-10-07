// Command server runs the bbmcp gateway: a Bitbucket Server MCP gateway with
// Keycloak SSO, an admin console and personal key management.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hkjang/bbmcp/internal/aiproxy"
	"github.com/hkjang/bbmcp/internal/api"
	"github.com/hkjang/bbmcp/internal/apikey"
	"github.com/hkjang/bbmcp/internal/approval"
	"github.com/hkjang/bbmcp/internal/audit"
	"github.com/hkjang/bbmcp/internal/auth"
	"github.com/hkjang/bbmcp/internal/bitbucket"
	"github.com/hkjang/bbmcp/internal/config"
	"github.com/hkjang/bbmcp/internal/crypto"
	"github.com/hkjang/bbmcp/internal/database"
	"github.com/hkjang/bbmcp/internal/identity"
	"github.com/hkjang/bbmcp/internal/permission"
	"github.com/hkjang/bbmcp/internal/policy"
	"github.com/hkjang/bbmcp/internal/settings"
	"github.com/hkjang/bbmcp/internal/tools"
	"github.com/hkjang/bbmcp/internal/version"
	"github.com/hkjang/bbmcp/internal/webui"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("서비스를 시작할 수 없습니다", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	slog.Info("bbmcp 시작", "version", version.Version, "commit", version.Commit,
		"buildDate", version.BuildDate, "addr", cfg.Addr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	slog.Info("데이터베이스 마이그레이션 완료")

	sealer, err := crypto.NewSealer(cfg.EncryptionKey)
	if err != nil {
		return err
	}

	store := settings.NewStore(db.Pool, sealer)
	auditLog := audit.New(db.Pool)
	users := auth.NewUsers(db.Pool)
	sessions := auth.NewSessions(db.Pool, sealer)
	keys := apikey.NewService(db.Pool, sealer, store)
	provider := bitbucket.NewProvider(store, db.Pool)
	resolver := permission.NewResolver(store, provider)
	mapper := identity.NewMapper(db.Pool, provider)
	policies := policy.NewEngine(db.Pool)
	approvals := approval.NewEngine(db.Pool)
	registry := tools.NewRegistry(db.Pool)
	oidc := auth.NewOIDC(store)
	ai := aiproxy.New(store)

	if err := users.EnsureBootstrapAdmin(ctx, cfg.BootstrapAdmin, cfg.BootstrapAdminPasswd); err != nil {
		return err
	}
	if err := keys.SeedRoles(ctx); err != nil {
		return err
	}
	if err := registry.Sync(ctx); err != nil {
		return err
	}
	if changed, err := store.MigrateMCPRegistration(ctx, "system:migration"); err != nil {
		slog.Warn("MCP 동적 등록 대행 설정을 점검하지 못했습니다", "error", err)
	} else if changed {
		const msg = "MCP 동적 등록 대행을 한 번 다시 켰습니다. 꺼짐은 'MCP 클라이언트를 Keycloak 동적 등록으로 보냄'을 뜻하는데(v0.2.6 부터), " +
			"이 값은 v0.2.9 이전에 저장되어 어느 뜻으로 고른 것인지 알 수 없습니다. Keycloak 13 이하는 MCP 클라이언트 등록을 invalid_client_metadata 로 거부합니다. " +
			"이제 클라이언트에는 bbmcp 가 인가 서버로 알려지므로, Keycloak 이 로그인 응답에 iss 를 붙이면 MCP 클라이언트의 'Exclude Issuer From Authentication Response' 를 켜십시오(MCP OAuth 점검이 알려 줍니다). " +
			"의도한 설정이면 관리 콘솔에서 다시 끄십시오."
		slog.Warn(msg)
		auditLog.Write(ctx, audit.Entry{
			Category: audit.CatAdmin,
			Action:   "settings.migrate",
			Success:  true,
			Message:  msg,
			Detail:   map[string]any{"setting": "keycloak.mcpAllowDynamicRegistration", "from": false, "to": true},
		})
	}
	slog.Info("초기화 완료", "bootstrapAdmin", cfg.BootstrapAdmin)

	authSvc := &auth.Service{
		Users: users, Sessions: sessions, OIDC: oidc, Mapper: mapper,
		Keys: keys, Store: store, Audit: auditLog, Sealer: sealer,
	}
	executor := tools.NewExecutor(tools.Deps{
		Registry: registry, Provider: provider, Resolver: resolver, Policy: policies,
		Approvals: approvals, Audit: auditLog, Store: store,
	})

	server := api.New(api.Deps{
		Pool: db.Pool, Store: store, Auth: authSvc, Users: users, Sessions: sessions,
		Keys: keys, Mapper: mapper, Provider: provider, Resolver: resolver,
		Policy: policies, Approvals: approvals, Registry: registry, Executor: executor,
		Audit: auditLog, AI: ai, Static: webui.Handler(),
	})

	go housekeeping(ctx, sessions, approvals, auditLog, store)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           server.Router(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("HTTP 수신 대기", "addr", cfg.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("종료 신호 수신, 정리 중")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// housekeeping performs the periodic maintenance an air-gapped deployment has
// nobody to run by hand: expiring sessions and approvals, trimming the audit log.
func housekeeping(ctx context.Context, sessions *auth.Sessions, approvals *approval.Engine,
	auditLog *audit.Logger, store *settings.Store) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sessions.Cleanup(ctx); err != nil {
				slog.Warn("세션 정리 실패", "error", err)
			}
			if err := approvals.ExpireStale(ctx); err != nil {
				slog.Warn("승인 만료 처리 실패", "error", err)
			}
			if sec, err := store.Security(ctx); err == nil {
				if err := auditLog.Purge(ctx, sec.AuditRetainDays); err != nil {
					slog.Warn("감사 로그 정리 실패", "error", err)
				}
			}
		}
	}
}
