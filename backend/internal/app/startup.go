package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	auditapp "github.com/chenyme/grok2api/backend/internal/application/audit"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/repository"
	httpserver "github.com/chenyme/grok2api/backend/internal/transport/http"
)

type startupAccountRepository interface {
	ListEnabledBatch(context.Context, accountdomain.Provider, int) ([]accountdomain.Credential, error)
	CountActiveCooldowns(context.Context, time.Time) (int64, error)
}

const (
	startupRecoveryBudget     = 20 * time.Second
	startupCriticalWindow     = 2 * time.Minute
	startupCriticalLimit      = 100
	statsigWarmupInterval     = 15 * time.Minute
	statsigWarmupAccountLimit = 3
	modelCatalogStaleAfter    = 24 * time.Hour
	modelCatalogCatchupEvery  = 6 * time.Hour
)

type startupReport struct {
	StartedAt                time.Time
	CompletedAt              *time.Time
	Credentials              accountapp.CredentialStartupReport
	CooldownsRestored        int
	QuotaRecoveriesRestored  int
	DueWebQuotasQueued       int
	StatsigKeysWarmed        int
	StaleWebQuotasFound      int
	StaleWebQuotasSynced     int
	StaleModelCatalogsFound  int
	StaleModelCatalogsSynced int
	ErrorCount               int
}

type startupState struct {
	mu        sync.RWMutex
	phase     string
	updatedAt time.Time
	report    startupReport
	statsig   httpserver.ReadinessComponent
}

func newStartupState(restoredQuotaRecoveries int) *startupState {
	now := time.Now().UTC()
	return &startupState{
		phase:     "booting",
		updatedAt: now,
		report: startupReport{
			StartedAt:               now,
			QuotaRecoveriesRestored: restoredQuotaRecoveries,
		},
		statsig: httpserver.ReadinessComponent{State: "cold"},
	}
}

func (s *startupState) setPhase(phase string) {
	s.mu.Lock()
	s.phase = phase
	s.updatedAt = time.Now().UTC()
	if phase == "running" {
		completed := s.updatedAt
		s.report.CompletedAt = &completed
	}
	s.mu.Unlock()
}

func (s *startupState) updateReport(update func(*startupReport)) {
	s.mu.Lock()
	update(&s.report)
	s.updatedAt = time.Now().UTC()
	s.mu.Unlock()
}

func (s *startupState) recordError(err error) {
	if err == nil {
		return
	}
	s.updateReport(func(report *startupReport) {
		report.ErrorCount++
	})
}

func (s *startupState) setStatsig(state, detail string, warmed int) {
	s.mu.Lock()
	s.statsig = httpserver.ReadinessComponent{State: state, Detail: detail}
	if warmed > 0 {
		s.report.StatsigKeysWarmed = warmed
	}
	s.updatedAt = time.Now().UTC()
	s.mu.Unlock()
}

func (s *startupState) snapshot() (string, time.Time, startupReport, httpserver.ReadinessComponent) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phase, s.updatedAt, s.report, s.statsig
}

func (s *startupState) acceptsTraffic() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phase == "running"
}

func readinessSnapshot(
	ctx context.Context,
	state *startupState,
	runtimeHealth func(context.Context) error,
	mediaHealth func(context.Context) error,
	models repository.ModelRepository,
	accounts repository.AccountRepository,
	providers *provider.Registry,
	ledger *auditapp.Service,
) httpserver.ReadinessSnapshot {
	phase, updatedAt, report, statsig := state.snapshot()
	snapshot := httpserver.ReadinessSnapshot{
		Ready: false, State: phase, UpdatedAt: updatedAt, Startup: newReadinessStartupReport(report),
		Components: map[string]httpserver.ReadinessComponent{
			"runtime_store":  {State: "unknown"},
			"billing_ledger": {State: "unknown"},
			"media_store":    {State: "unknown"},
			"grok_build":     {State: "unknown"},
			"grok_web":       {State: "unknown"},
			"statsig":        statsig,
		},
	}
	if phase != "running" {
		return snapshot
	}
	ledgerDegraded := false
	healthCtx, cancel := context.WithTimeout(ctx, time.Second)
	err := runtimeHealth(healthCtx)
	cancel()
	if err != nil {
		snapshot.State = "not_ready"
		snapshot.Components["runtime_store"] = httpserver.ReadinessComponent{State: "unavailable", Detail: "运行态存储不可用"}
		return snapshot
	}
	snapshot.Components["runtime_store"] = httpserver.ReadinessComponent{State: "ready"}
	if ledger != nil {
		ledgerState := ledger.LedgerSnapshot()
		if ledgerState.Ready {
			snapshot.Components["billing_ledger"] = httpserver.ReadinessComponent{State: "ready"}
		} else {
			detail := fmt.Sprintf("审计账本不可用；连续失败 %d 次，丢失 %d 条，队列 %d/%d", ledgerState.ConsecutiveFailures, ledgerState.Dropped, ledgerState.QueueDepth, ledgerState.QueueCapacity)
			snapshot.Components["billing_ledger"] = httpserver.ReadinessComponent{State: "degraded", Detail: detail}
			if ledgerState.Irrecoverable || ledgerState.Mode == auditapp.LedgerModeEnforce {
				snapshot.State = "not_ready"
				return snapshot
			}
			ledgerDegraded = true
		}
	}
	healthCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	err = mediaHealth(healthCtx)
	cancel()
	if err != nil {
		snapshot.State = "not_ready"
		// 固定文案，不泄露 S3/COS 错误原文（startup.media_readiness_no_leak）
		snapshot.Components["media_store"] = httpserver.ReadinessComponent{State: "unavailable", Detail: "媒体存储不可用"}
		return snapshot
	}
	snapshot.Components["media_store"] = httpserver.ReadinessComponent{State: "ready"}

	routes, err := models.ListConfiguredEnabled(ctx)
	if err != nil {
		snapshot.State = "not_ready"
		snapshot.Components["model_routes"] = httpserver.ReadinessComponent{State: "unavailable", Detail: "模型路由读取失败"}
		return snapshot
	}
	if len(routes) == 0 {
		snapshot.State = "not_ready"
		snapshot.Components["model_routes"] = httpserver.ReadinessComponent{State: "unavailable", Detail: "没有启用的模型路由"}
		return snapshot
	}
	snapshot.Components["model_routes"] = httpserver.ReadinessComponent{State: "ready", Detail: fmt.Sprintf("%d 条已启用路由", len(routes))}

	required := make(map[accountdomain.Provider]bool, 3)
	usable := make(map[accountdomain.Provider]bool, 3)
	providerErrors := make(map[accountdomain.Provider]bool, 3)
	for _, route := range routes {
		required[route.Provider] = true
		if route.SupportedAccounts == 0 || usable[route.Provider] || providerErrors[route.Provider] {
			continue
		}
		available, activeErr := accounts.HasActive(ctx, route.Provider, route.UpstreamModel, providers.QuotaMode(route.Provider, route.UpstreamModel))
		if activeErr != nil {
			providerErrors[route.Provider] = true
			continue
		}
		usable[route.Provider] = available
	}

	readyProviders := 0
	unavailableProviders := 0
	for _, providerValue := range accountdomain.Providers() {
		name := string(providerValue)
		if !required[providerValue] {
			snapshot.Components[name] = httpserver.ReadinessComponent{State: "disabled"}
			continue
		}
		if usable[providerValue] {
			readyProviders++
			snapshot.Components[name] = httpserver.ReadinessComponent{State: "ready"}
			continue
		}
		unavailableProviders++
		detail := "当前没有可用于已启用路由的账号"
		if providerErrors[providerValue] {
			detail = "账号候选状态读取失败"
		}
		snapshot.Components[name] = httpserver.ReadinessComponent{State: "unavailable", Detail: detail}
	}
	if required[accountdomain.ProviderWeb] && usable[accountdomain.ProviderWeb] && statsig.State != "warm" {
		component := snapshot.Components[string(accountdomain.ProviderWeb)]
		if statsig.State == "warming" || statsig.State == "cold" {
			component.State = "warming"
		} else {
			component.State = "degraded"
		}
		component.Detail = "Statsig 尚未完成预热；请求仍可按需刷新"
		snapshot.Components[string(accountdomain.ProviderWeb)] = component
		unavailableProviders++
	}
	if readyProviders == 0 {
		snapshot.State = "not_ready"
		return snapshot
	}
	snapshot.Ready = true
	if unavailableProviders > 0 || ledgerDegraded {
		snapshot.State = "degraded"
	} else {
		snapshot.State = "ready"
	}
	return snapshot
}

// newReadinessStartupReport 只公开稳定统计，不把启动错误原文暴露到无鉴权就绪端点。
func newReadinessStartupReport(report startupReport) *httpserver.ReadinessStartupReport {
	return &httpserver.ReadinessStartupReport{
		StartedAt:   report.StartedAt,
		CompletedAt: report.CompletedAt,
		Credentials: httpserver.ReadinessCredentialReport{
			SchedulesBackfilled: report.Credentials.SchedulesBackfilled,
			CriticalFound:       report.Credentials.CriticalFound,
			Refreshed:           report.Credentials.Refreshed,
			Failed:              report.Credentials.Failed,
		},
		CooldownsRestored:        report.CooldownsRestored,
		QuotaRecoveriesRestored:  report.QuotaRecoveriesRestored,
		DueWebQuotasQueued:       report.DueWebQuotasQueued,
		StatsigKeysWarmed:        report.StatsigKeysWarmed,
		StaleWebQuotasFound:      report.StaleWebQuotasFound,
		StaleWebQuotasSynced:     report.StaleWebQuotasSynced,
		StaleModelCatalogsFound:  report.StaleModelCatalogsFound,
		StaleModelCatalogsSynced: report.StaleModelCatalogsSynced,
		ErrorCount:               report.ErrorCount,
	}
}

func (a *Application) reconcileStartup(ctx context.Context) {
	a.startup.setPhase("reconciling")
	recoveryCtx, cancel := context.WithTimeout(ctx, startupRecoveryBudget)
	defer cancel()

	if _, err := a.clientKeys.CleanupExpiredBilling(recoveryCtx, 1000); err != nil {
		a.logger.Warn("billing_reservation_cleanup_failed", "error", err)
		a.startup.recordError(err)
	}
	if err := a.gateway.RecoverVideoJobs(recoveryCtx); err != nil {
		a.logger.Warn("video_job_recovery_failed", "error", err)
		a.startup.recordError(err)
	}
	if _, err := a.accountRepo.PruneExpiredModelQuotaBlocks(recoveryCtx, time.Now().UTC(), 1000); err != nil {
		a.logger.Warn("model_cooldown_cleanup_failed", "error", err)
		a.startup.recordError(err)
	}
	cooldowns, err := a.startupAccounts.CountActiveCooldowns(recoveryCtx, time.Now().UTC())
	if err != nil {
		a.startup.recordError(err)
	} else {
		a.startup.updateReport(func(report *startupReport) { report.CooldownsRestored = int(cooldowns) })
	}
	report, err := a.accounts.RecoverCriticalCredentials(recoveryCtx, startupCriticalWindow, startupCriticalLimit)
	a.startup.updateReport(func(startup *startupReport) { startup.Credentials = report })
	if err != nil && ctx.Err() == nil {
		a.logger.Warn("credential_startup_recovery_incomplete", "error", err, "found", report.CriticalFound, "refreshed", report.Refreshed, "failed", report.Failed)
		a.startup.recordError(err)
	}
	a.startup.setPhase("running")
	a.logger.Info("startup_reconciliation_completed", "credentials_backfilled", report.SchedulesBackfilled, "critical_found", report.CriticalFound, "credentials_refreshed", report.Refreshed, "credentials_failed", report.Failed)
}

func (a *Application) runStatsigWarmup(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		a.startup.setStatsig("warming", "正在预热 Statsig meta", 0)
		values, err := a.startupAccounts.ListEnabledBatch(ctx, accountdomain.ProviderWeb, statsigWarmupAccountLimit)
		if err == nil && len(values) == 0 {
			a.startup.setStatsig("disabled", "没有启用的 Grok Web 账号", 0)
		} else if err == nil {
			warmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			var warmed int
			warmed, err = warmStatsigFromAccounts(warmCtx, values, a.web.WarmStatsig)
			cancel()
			if err == nil {
				a.startup.setStatsig("warm", "Statsig meta 已预热", warmed)
			}
		}
		if err != nil && ctx.Err() == nil {
			a.logger.Warn("web_statsig_warmup_failed", "error", err)
			a.startup.setStatsig("unavailable", "预热失败，将由请求按需重试", 0)
		}
		resetTimer(timer, statsigWarmupInterval)
	}
}

func warmStatsigFromAccounts(ctx context.Context, values []accountdomain.Credential, warm func(context.Context, accountdomain.Credential) (int, error)) (int, error) {
	limit := min(len(values), statsigWarmupAccountLimit)
	var lastErr error
	for index := range limit {
		warmed, err := warm(ctx, values[index])
		if err == nil {
			return warmed, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
	}
	return 0, lastErr
}

func (a *Application) runModelCatalogCatchup(ctx context.Context) {
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		ids, err := a.modelRepo.ListStaleAccountSyncIDs(ctx, time.Now().UTC().Add(-modelCatalogStaleAfter), 100)
		if err == nil && len(ids) > 0 {
			runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			var succeeded int
			succeeded, _, err = a.models.SyncAccounts(runCtx, ids)
			cancel()
			a.startup.updateReport(func(report *startupReport) {
				report.StaleModelCatalogsFound = len(ids)
				report.StaleModelCatalogsSynced = succeeded
			})
		}
		if err != nil && ctx.Err() == nil {
			a.logger.Warn("model_catalog_stale_catchup_failed", "error", err)
		}
		resetTimer(timer, modelCatalogCatchupEvery)
	}
}
