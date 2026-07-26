package relational

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
)

func TestConsoleQuotaParticipatesInRoutingAndSummary(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "console.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repository := NewAccountRepository(database)
	credential, _, err := repository.UpsertByIdentity(ctx, account.Credential{
		Provider: account.ProviderConsole, AuthType: account.AuthTypeSSO, Name: "console", SourceKey: "console:test",
		EncryptedAccessToken: "encrypted", Enabled: true, AuthStatus: account.AuthStatusActive, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	resetAt := now.Add(time.Hour)
	if err := repository.SaveQuotaWindows(ctx, credential.ID, "", now, []account.QuotaWindow{{
		AccountID: credential.ID, Mode: "console", Remaining: 20, Total: 20, WindowSeconds: 3600,
		ResetAt: &resetAt, Source: account.QuotaSourceDefault, UpdatedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}
	var profileCount int64
	if err := database.db.WithContext(ctx).Model(&webAccountProfileModel{}).Where("account_id = ?", credential.ID).Count(&profileCount).Error; err != nil {
		t.Fatal(err)
	}
	if profileCount != 0 {
		t.Fatalf("console created %d web profiles", profileCount)
	}
	candidates, err := repository.ListRoutingCandidates(ctx, account.ProviderConsole, 0, "grok-4.3", "console")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].QuotaWindow == nil || candidates[0].QuotaWindow.Remaining != 20 {
		t.Fatalf("candidates = %#v", candidates)
	}
	summary, err := repository.Summarize(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary) != 1 || summary[0].Available != 1 || summary[0].WaitingReset != 0 {
		t.Fatalf("summary before exhaustion = %#v", summary)
	}
	if err := repository.ExhaustQuotaWindow(ctx, credential.ID, "console", &resetAt, now); err != nil {
		t.Fatal(err)
	}
	summary, err = repository.Summarize(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary) != 1 || summary[0].Available != 0 || summary[0].WaitingReset != 1 {
		t.Fatalf("summary after exhaustion = %#v", summary)
	}
}

func TestMigrateConsoleLegacyQuotaWindowPreservesActiveState(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "console-quota-migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repository := NewAccountRepository(database)
	credential, _, err := repository.UpsertByIdentity(ctx, account.Credential{
		Provider: account.ProviderConsole, AuthType: account.AuthTypeSSO, Name: "legacy-console", SourceKey: "console:legacy",
		EncryptedAccessToken: "encrypted", Enabled: true, AuthStatus: account.AuthStatusActive, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	resetAt := now.Add(30 * time.Minute)
	if err := repository.SaveQuotaWindows(ctx, credential.ID, "", now, []account.QuotaWindow{
		{AccountID: credential.ID, Mode: "console", Remaining: 7, Total: 20, WindowSeconds: 3600, ResetAt: &resetAt, SyncedAt: &now, Source: account.QuotaSourceDefault, UpdatedAt: now},
		{AccountID: credential.ID, Mode: "console:model-a", Remaining: 3, Total: 20, WindowSeconds: 3600, ResetAt: &resetAt, SyncedAt: &now, Source: account.QuotaSourceDefault, UpdatedAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	migrated, err := repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console", []string{"console:model-a", "console:model-b", "console:model-b"}, 1000)
	if err != nil || migrated != 1 {
		t.Fatalf("migration = %d, err = %v", migrated, err)
	}
	windows, err := repository.GetQuotaWindows(ctx, []uint64{credential.ID})
	if err != nil {
		t.Fatal(err)
	}
	byMode := make(map[string]account.QuotaWindow, len(windows[credential.ID]))
	for _, window := range windows[credential.ID] {
		byMode[window.Mode] = window
	}
	if len(byMode) != 2 || byMode["console:model-a"].Remaining != 3 || byMode["console:model-b"].Remaining != 7 {
		t.Fatalf("migrated windows = %#v", byMode)
	}
	if migrated, err = repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console", []string{"console:model-a", "console:model-b"}, 1000); err != nil || migrated != 0 {
		t.Fatalf("idempotent migration = %d, err = %v", migrated, err)
	}
	if migrated, err = repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console:model-a", []string{"console:model-b"}, 1000); err != nil || migrated != 1 {
		t.Fatalf("alias migration = %d, err = %v", migrated, err)
	}
	windows, err = repository.GetQuotaWindows(ctx, []uint64{credential.ID})
	if err != nil || len(windows[credential.ID]) != 1 || windows[credential.ID][0].Mode != "console:model-b" || windows[credential.ID][0].Remaining != 3 {
		t.Fatalf("alias migration preserved wrong window = %#v, err = %v", windows, err)
	}

	// A less restrictive alias must not overwrite the canonical limit.
	if err := repository.SaveQuotaWindows(ctx, credential.ID, "", now, []account.QuotaWindow{
		{AccountID: credential.ID, Mode: "console:model-a", Remaining: 9, Total: 20, WindowSeconds: 3600, ResetAt: &resetAt, SyncedAt: &now, Source: account.QuotaSourceDefault, UpdatedAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	if migrated, err = repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console:model-a", []string{"console:model-b"}, 1000); err != nil || migrated != 1 {
		t.Fatalf("less restrictive alias migration = %d, err = %v", migrated, err)
	}
	windows, err = repository.GetQuotaWindows(ctx, []uint64{credential.ID})
	if err != nil || len(windows[credential.ID]) != 1 || windows[credential.ID][0].Remaining != 3 {
		t.Fatalf("canonical limit was overwritten = %#v, err = %v", windows, err)
	}

	// An exhausted alias must keep the real bucket blocked through its reset.
	laterReset := now.Add(2 * time.Hour)
	if err := repository.SaveQuotaWindows(ctx, credential.ID, "", now, []account.QuotaWindow{
		{AccountID: credential.ID, Mode: "console:model-a", Remaining: 0, Total: 20, UsagePercent: 100, WindowSeconds: 3600, ResetAt: &laterReset, SyncedAt: &now, Source: account.QuotaSourceUpstream, UpdatedAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	if migrated, err = repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console:model-a", []string{"console:model-b"}, 1000); err != nil || migrated != 1 {
		t.Fatalf("exhausted alias migration = %d, err = %v", migrated, err)
	}
	windows, err = repository.GetQuotaWindows(ctx, []uint64{credential.ID})
	merged := windows[credential.ID]
	if err != nil || len(merged) != 1 || merged[0].Remaining != 0 || merged[0].ResetAt == nil || !merged[0].ResetAt.Equal(laterReset) || merged[0].Source != account.QuotaSourceUpstream {
		t.Fatalf("exhausted alias state was lost = %#v, err = %v", windows, err)
	}
}

func TestMigrateQuotaModeHonorsBatchLimit(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "console-quota-batch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repository := NewAccountRepository(database)
	now := time.Now().UTC()
	for index := range 3 {
		credential, _, err := repository.UpsertByIdentity(ctx, account.Credential{
			Provider: account.ProviderConsole, AuthType: account.AuthTypeSSO,
			Name: fmt.Sprintf("console-%d", index), SourceKey: fmt.Sprintf("console:batch:%d", index),
			EncryptedAccessToken: "encrypted", Enabled: true, AuthStatus: account.AuthStatusActive, MaxConcurrent: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.SaveQuotaWindows(ctx, credential.ID, "", now, []account.QuotaWindow{{
			AccountID: credential.ID, Mode: "console", Remaining: 20, Total: 20,
			WindowSeconds: 3600, Source: account.QuotaSourceDefault, UpdatedAt: now,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	migrated, err := repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console", []string{"console:model"}, 2)
	if err != nil || migrated != 2 {
		t.Fatalf("first migration = %d, err = %v", migrated, err)
	}
	var legacy int64
	if err := database.db.WithContext(ctx).Model(&quotaWindowModel{}).Where("mode = ?", "console").Count(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if legacy != 1 {
		t.Fatalf("legacy windows after bounded migration = %d, want 1", legacy)
	}
	if migrated, err = repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console", []string{"console:model"}, 2); err != nil || migrated != 1 {
		t.Fatalf("second migration = %d, err = %v", migrated, err)
	}
}
