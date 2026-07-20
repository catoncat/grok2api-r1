package relational

import (
	"context"
	"errors"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"gorm.io/gorm"
)

func TestCleanupAccountStatusBatchRevalidatesStatusAndDeletesEligibleAccount(t *testing.T) {
	ctx := context.Background()
	database := openTestDatabase(t)
	accounts := NewAccountRepository(database)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	createDisabled := func(source string) accountdomain.Credential {
		t.Helper()
		value, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
			Provider: accountdomain.ProviderBuild, Name: source, SourceKey: source,
			EncryptedAccessToken: testEncryptedToken, AuthStatus: accountdomain.AuthStatusActive,
		})
		if err != nil {
			t.Fatal(err)
		}
		value.Enabled = false
		value, err = accounts.Update(ctx, value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}

	changed := createDisabled("status-changed")
	eligible := createDisabled("eligible")
	preview, err := accounts.CleanupAccountStatusBatch(ctx, accountdomain.ProviderBuild, "disabled", now, 2, true)
	if err != nil || preview.Matched != 2 || preview.Eligible != 2 || preview.Protected != 0 || preview.Skipped != 0 || len(preview.DeletedIDs) != 0 {
		t.Fatalf("preview = %#v, err = %v", preview, err)
	}
	changed.Enabled = true
	if _, err := accounts.Update(ctx, changed); err != nil {
		t.Fatal(err)
	}

	result, err := accounts.CleanupAccountStatusBatch(ctx, accountdomain.ProviderBuild, "disabled", now, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 1 || result.Protected != 0 || result.Eligible != 1 || result.Skipped != 0 || len(result.DeletedIDs) != 1 || result.DeletedIDs[0] != eligible.ID {
		t.Fatalf("execution = %#v", result)
	}
	if _, err := accounts.Get(ctx, changed.ID); err != nil {
		t.Fatalf("status-changed account was deleted: %v", err)
	}
	if _, err := accounts.Get(ctx, eligible.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("eligible account should be deleted, err = %v", err)
	}
}

func TestCleanupAccountStatusBatchReportsStatusChangeDuringExecution(t *testing.T) {
	ctx := context.Background()
	database := openTestDatabase(t)
	accounts := NewAccountRepository(database)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	value, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "status-race", SourceKey: "status-race",
		EncryptedAccessToken: testEncryptedToken, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	value.Enabled = false
	value, err = accounts.Update(ctx, value)
	if err != nil {
		t.Fatal(err)
	}

	const callbackName = "test:cleanup-status-change"
	if err := database.db.Callback().Delete().Before("gorm:delete").Register(callbackName, func(tx *gorm.DB) {
		if err := tx.Session(&gorm.Session{NewDB: true, SkipHooks: true}).Model(&accountModel{}).
			Where("id = ?", value.ID).Update("enabled", true).Error; err != nil {
			tx.AddError(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.db.Callback().Delete().Remove(callbackName) })

	result, err := accounts.CleanupAccountStatusBatch(ctx, accountdomain.ProviderBuild, "disabled", now, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 1 || result.Protected != 0 || result.Eligible != 1 || result.Skipped != 1 || len(result.DeletedIDs) != 0 {
		t.Fatalf("execution = %#v", result)
	}
	stored, err := accounts.Get(ctx, value.ID)
	if err != nil || !stored.Enabled {
		t.Fatalf("status-changed account = %#v, err = %v", stored, err)
	}
}

func TestCleanupAccountStatusBatchRechecksVerifiedBinding(t *testing.T) {
	ctx := context.Background()
	database := openTestDatabase(t)
	accounts := NewAccountRepository(database)
	models := NewModelRepository(database)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	value, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "protected-later", SourceKey: "protected-later",
		EncryptedAccessToken: testEncryptedToken, Enabled: false, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	value.Enabled = false
	if _, err := accounts.Update(ctx, value); err != nil {
		t.Fatal(err)
	}
	preview, err := accounts.CleanupAccountStatusBatch(ctx, accountdomain.ProviderBuild, "disabled", now, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Matched != 1 || preview.Protected != 0 || preview.Eligible != 1 || preview.Skipped != 0 || len(preview.DeletedIDs) != 0 {
		t.Fatalf("preview = %#v", preview)
	}
	if _, err := models.Create(ctx, modeldomain.Route{
		PublicID: "verified-race", Provider: accountdomain.ProviderBuild, UpstreamModel: "grok-4.5",
		Capability: modeldomain.CapabilityResponses, Enabled: true,
	}, []uint64{value.ID}); err != nil {
		t.Fatal(err)
	}

	result, err := accounts.CleanupAccountStatusBatch(ctx, accountdomain.ProviderBuild, "disabled", now, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 1 || result.Protected != 1 || result.Eligible != 0 || result.Skipped != 0 || len(result.DeletedIDs) != 0 {
		t.Fatalf("execution = %#v", result)
	}
	if _, err := accounts.Get(ctx, value.ID); err != nil {
		t.Fatalf("verified account was deleted: %v", err)
	}
}
