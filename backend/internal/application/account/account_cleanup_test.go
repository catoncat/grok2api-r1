package account

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/runtime/memory"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestCleanupAccountsDefaultsToSafeStatusSelection(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "account-cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := relational.NewAccountRepository(database)
	models := relational.NewModelRepository(database)
	service := NewService(accounts, nil, nil, memory.NewStickyStore(), nil, nil, nil)
	service.now = func() time.Time { return now }

	create := func(name string, providerValue accountdomain.Provider, mutate func(*accountdomain.Credential)) accountdomain.Credential {
		t.Helper()
		value, _, createErr := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
			Provider: providerValue, Name: name, SourceKey: "cleanup-" + name,
			EncryptedAccessToken: "encrypted", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if mutate != nil {
			mutate(&value)
			value, createErr = accounts.Update(ctx, value)
			if createErr != nil {
				t.Fatal(createErr)
			}
		}
		return value
	}

	disabled := create("disabled", accountdomain.ProviderBuild, func(value *accountdomain.Credential) { value.Enabled = false })
	reauth := create("reauth", accountdomain.ProviderBuild, func(value *accountdomain.Credential) { value.AuthStatus = accountdomain.AuthStatusReauthRequired })
	cooling := create("cooling", accountdomain.ProviderBuild, func(value *accountdomain.Credential) {
		until := now.Add(time.Hour)
		value.CooldownUntil = &until
	})
	expired := create("expired", accountdomain.ProviderBuild, func(value *accountdomain.Credential) {
		until := now.Add(-time.Hour)
		value.CooldownUntil = &until
	})
	active := create("active", accountdomain.ProviderBuild, nil)
	wrongProvider := create("web-disabled", accountdomain.ProviderWeb, func(value *accountdomain.Credential) { value.Enabled = false })
	protected := create("protected", accountdomain.ProviderBuild, func(value *accountdomain.Credential) { value.Enabled = false })
	if _, err := models.Create(ctx, modeldomain.Route{
		PublicID: "verified-cleanup", Provider: accountdomain.ProviderBuild, UpstreamModel: "grok-4.5",
		Capability: modeldomain.CapabilityResponses, Enabled: true,
	}, []uint64{protected.ID}); err != nil {
		t.Fatal(err)
	}

	preview, err := service.CleanupAccounts(ctx, accountdomain.ProviderBuild, []CleanupStatus{
		CleanupStatusDisabled, CleanupStatusReauthRequired, CleanupStatusCooldown, CleanupStatusDisabled,
	}, 20, true)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.DryRun || preview.Matched != 4 || preview.Protected != 1 || preview.Eligible != 3 || preview.Skipped != 0 || preview.Deleted != 0 {
		t.Fatalf("preview = %#v", preview)
	}
	for _, value := range []accountdomain.Credential{disabled, reauth, cooling, expired, active, protected} {
		if _, err := accounts.Get(ctx, value.ID); err != nil {
			t.Fatalf("preview deleted account %d: %v", value.ID, err)
		}
	}
	if _, err := accounts.Get(ctx, wrongProvider.ID); err != nil {
		t.Fatalf("preview affected wrong provider: %v", err)
	}

	executed, err := service.CleanupAccounts(ctx, accountdomain.ProviderBuild, []CleanupStatus{
		CleanupStatusDisabled, CleanupStatusReauthRequired, CleanupStatusCooldown,
	}, 20, false)
	if err != nil {
		t.Fatal(err)
	}
	if executed.DryRun || executed.Matched != 4 || executed.Protected != 1 || executed.Eligible != 3 || executed.Skipped != 0 || executed.Deleted != 3 {
		t.Fatalf("executed = %#v", executed)
	}
	for _, value := range []accountdomain.Credential{disabled, reauth, cooling} {
		if _, err := accounts.Get(ctx, value.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("account %d should be deleted, err = %v", value.ID, err)
		}
	}
	for _, value := range []accountdomain.Credential{expired, active, protected, wrongProvider} {
		if _, err := accounts.Get(ctx, value.ID); err != nil {
			t.Fatalf("account %d should remain: %v", value.ID, err)
		}
	}
}

func TestCleanupAccountsRejectsUnboundedOrInvalidRequests(t *testing.T) {
	service := NewService(nil, nil, nil, nil, nil, nil, nil)
	ctx := context.Background()
	cases := []struct {
		name     string
		provider accountdomain.Provider
		statuses []CleanupStatus
		limit    int
	}{
		{name: "empty status", provider: accountdomain.ProviderBuild, statuses: nil, limit: 1},
		{name: "invalid status", provider: accountdomain.ProviderBuild, statuses: []CleanupStatus{"active"}, limit: 1},
		{name: "zero limit", provider: accountdomain.ProviderBuild, statuses: []CleanupStatus{CleanupStatusDisabled}, limit: 0},
		{name: "too large", provider: accountdomain.ProviderBuild, statuses: []CleanupStatus{CleanupStatusDisabled}, limit: 501},
		{name: "invalid provider", provider: "unknown", statuses: []CleanupStatus{CleanupStatusDisabled}, limit: 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := service.CleanupAccounts(ctx, test.provider, test.statuses, test.limit, true); err == nil {
				t.Fatal("invalid cleanup request unexpectedly succeeded")
			}
		})
	}
}
