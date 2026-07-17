package relational

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
)

func TestPostgresRepositoriesIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not configured")
	}
	ctx := context.Background()
	database, err := OpenPostgres(ctx, dsn, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repository := NewAccountRepository(database)
	created, wasCreated, err := repository.UpsertByIdentity(ctx, account.Credential{
		Provider: account.ProviderConsole, AuthType: account.AuthTypeSSO, Name: "postgres", SourceKey: "postgres-integration-" + time.Now().UTC().Format("150405.000000"),
		EncryptedAccessToken: "encrypted", AuthStatus: account.AuthStatusActive,
	})
	if err != nil || !wasCreated || created.ID == 0 {
		t.Fatalf("account = %#v, created = %v, err = %v", created, wasCreated, err)
	}
	loaded, err := repository.Get(ctx, created.ID)
	if err != nil || loaded.SourceKey != created.SourceKey {
		t.Fatalf("loaded = %#v, err = %v", loaded, err)
	}
	now := time.Now().UTC()
	resetAt := now.Add(time.Hour)
	if err := repository.SaveQuotaWindows(ctx, created.ID, "", now, []account.QuotaWindow{
		{AccountID: created.ID, Mode: "console:alias", Remaining: 0, Total: 20, UsagePercent: 100, WindowSeconds: 3600, ResetAt: &resetAt, SyncedAt: &now, Source: account.QuotaSourceUpstream, UpdatedAt: now},
		{AccountID: created.ID, Mode: "console:canonical", Remaining: 20, Total: 20, WindowSeconds: 3600, ResetAt: &resetAt, SyncedAt: &now, Source: account.QuotaSourceDefault, UpdatedAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	if migrated, err := repository.MigrateQuotaMode(ctx, account.ProviderConsole, "console:alias", []string{"console:canonical"}); err != nil || migrated != 1 {
		t.Fatalf("quota migration = %d, err = %v", migrated, err)
	}
	windows, err := repository.GetQuotaWindows(ctx, []uint64{created.ID})
	if err != nil || len(windows[created.ID]) != 1 || windows[created.ID][0].Mode != "console:canonical" || windows[created.ID][0].Remaining != 0 {
		t.Fatalf("quota windows = %#v, err = %v", windows, err)
	}
	if err := repository.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
}
