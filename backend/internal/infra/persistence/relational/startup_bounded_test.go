package relational

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

func TestStartupAccountQueriesStayBounded(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "startup-bounded.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repository := NewAccountRepository(database)
	now := time.Now().UTC()

	for index := range 6 {
		_, _, err := repository.UpsertByIdentity(ctx, accountdomain.Credential{
			Provider: accountdomain.ProviderWeb, Name: fmt.Sprintf("warm-%d", index), SourceKey: fmt.Sprintf("warm-%d", index),
			EncryptedAccessToken: "access", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
			Priority: 100 - index, MaxConcurrent: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	values, err := repository.ListEnabledBatch(ctx, accountdomain.ProviderWeb, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 3 || values[0].Name != "warm-0" || values[2].Name != "warm-2" {
		t.Fatalf("bounded warmup accounts = %#v", values)
	}
	empty, err := repository.ListEnabledBatch(ctx, accountdomain.ProviderWeb, 0)
	if err != nil || len(empty) != 0 {
		t.Fatalf("zero-limit warmup accounts = %#v, err=%v", empty, err)
	}

	future := now.Add(time.Hour)
	expired := now.Add(-time.Minute)
	fixtures := []accountdomain.Credential{
		{Provider: accountdomain.ProviderBuild, Name: "cooling", SourceKey: "cooling", Enabled: true, AuthStatus: accountdomain.AuthStatusActive, CooldownUntil: &future},
		{Provider: accountdomain.ProviderConsole, Name: "expired", SourceKey: "expired", Enabled: true, AuthStatus: accountdomain.AuthStatusActive, CooldownUntil: &expired},
		{Provider: accountdomain.ProviderBuild, Name: "disabled", SourceKey: "disabled", Enabled: false, AuthStatus: accountdomain.AuthStatusActive, CooldownUntil: &future},
		{Provider: accountdomain.ProviderWeb, Name: "reauth", SourceKey: "reauth", Enabled: true, AuthStatus: accountdomain.AuthStatusReauthRequired, CooldownUntil: &future},
	}
	for index := range fixtures {
		fixtures[index].EncryptedAccessToken = "access"
		fixtures[index].MaxConcurrent = 1
		created, _, err := repository.UpsertByIdentity(ctx, fixtures[index])
		if err != nil {
			t.Fatal(err)
		}
		if fixtures[index].Name == "disabled" {
			if err := database.db.WithContext(ctx).Model(&accountModel{}).Where("id = ?", created.ID).Update("enabled", false).Error; err != nil {
				t.Fatal(err)
			}
		}
	}

	cooldowns, err := repository.CountActiveCooldowns(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if cooldowns != 1 {
		t.Fatalf("active cooldown count = %d, want 1", cooldowns)
	}
}
