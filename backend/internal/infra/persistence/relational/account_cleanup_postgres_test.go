package relational

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"gorm.io/gorm"
)

func TestPostgresCleanupSerializesVerifiedBindingInsert(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not configured")
	}
	ctx := context.Background()
	base, err := OpenPostgres(ctx, dsn, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	schema := fmt.Sprintf("cleanup_lock_%d", time.Now().UTC().UnixNano())
	if err := base.db.Exec(`CREATE SCHEMA "` + schema + `"`).Error; err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := base.db.Exec(`DROP SCHEMA IF EXISTS "` + schema + `" CASCADE`).Error; err != nil {
			t.Errorf("drop schema: %v", err)
		}
	}()

	database, err := OpenPostgres(ctx, postgresDSNWithSearchPath(dsn, schema), 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountRepository(database)
	models := NewModelRepository(database)
	value, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "cleanup-lock", SourceKey: "cleanup-lock",
		EncryptedAccessToken: "encrypted", AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	value.Enabled = false
	if _, err := accounts.Update(ctx, value); err != nil {
		t.Fatal(err)
	}
	if _, err := models.Create(ctx, modeldomain.Route{
		PublicID: "cleanup-lock", Provider: accountdomain.ProviderBuild, UpstreamModel: "grok-4.5",
		Capability: modeldomain.CapabilityResponses, Enabled: true,
	}, nil); err != nil {
		t.Fatal(err)
	}

	locked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	releaseCleanup := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCleanup()
	const callbackName = "test:postgres-cleanup-locked"
	if err := database.db.Callback().Query().After("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if strings.Contains(tx.Statement.SQL.String(), "FOR UPDATE") {
			once.Do(func() {
				close(locked)
				<-release
			})
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.db.Callback().Query().Remove(callbackName) }()

	type cleanupOutcome struct {
		value repository.AccountCleanupBatch
		err   error
	}
	cleanupDone := make(chan cleanupOutcome, 1)
	go func() {
		result, cleanupErr := accounts.CleanupAccountStatusBatch(ctx, accountdomain.ProviderBuild, "disabled", time.Now().UTC(), 1, false)
		cleanupDone <- cleanupOutcome{value: result, err: cleanupErr}
	}()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		releaseCleanup()
		t.Fatal("cleanup did not acquire PostgreSQL FOR UPDATE lock")
	}

	bindingDone := make(chan error, 1)
	go func() {
		bindingDone <- models.AddAccountBinding(ctx, accountdomain.ProviderBuild, "grok-4.5", value.ID)
	}()
	select {
	case err := <-bindingDone:
		releaseCleanup()
		t.Fatalf("binding insert did not wait for cleanup row lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	releaseCleanup()

	outcome := <-cleanupDone
	if outcome.err != nil || outcome.value.Matched != 1 || outcome.value.Eligible != 1 || len(outcome.value.DeletedIDs) != 1 {
		t.Fatalf("cleanup = %#v, err = %v", outcome.value, outcome.err)
	}
	if err := <-bindingDone; err == nil {
		t.Fatal("binding insert succeeded after cleanup deleted its parent account")
	}
	if _, err := accounts.Get(ctx, value.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cleanup account should be deleted, err = %v", err)
	}
}

func postgresDSNWithSearchPath(dsn, schema string) string {
	parsed, err := url.Parse(dsn)
	if err == nil && parsed.Scheme != "" {
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return strings.TrimSpace(dsn) + " search_path=" + schema
}
