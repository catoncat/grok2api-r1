package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	modelapp "github.com/chenyme/grok2api/backend/internal/application/model"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/runtime/memory"
)

type closeTrackingBody struct {
	io.Reader
	closed *atomic.Bool
}

func (b *closeTrackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

type buildVerificationAdapter struct {
	mu         sync.Mutex
	status     int
	body       string
	retryAfter string
	err        error
	closed     atomic.Bool
	requests   []provider.ResponseResourceRequest
}

func (a *buildVerificationAdapter) Provider() accountdomain.Provider {
	return accountdomain.ProviderBuild
}

func (a *buildVerificationAdapter) ForwardResponse(_ context.Context, request provider.ResponseResourceRequest) (*provider.Response, error) {
	a.mu.Lock()
	a.requests = append(a.requests, request)
	a.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	header := make(http.Header)
	if a.retryAfter != "" {
		header.Set("Retry-After", a.retryAfter)
	}
	return &provider.Response{
		StatusCode: a.status,
		Header:     header,
		Body:       &closeTrackingBody{Reader: strings.NewReader(a.body), closed: &a.closed},
	}, nil
}

type buildVerificationFixture struct {
	ctx      context.Context
	service  *Service
	models   *relational.ModelRepository
	accounts *relational.AccountRepository
	target   accountdomain.Credential
	keeper   accountdomain.Credential
	route    modeldomain.Route
}

func newBuildVerificationFixture(t *testing.T, adapter provider.Adapter, bindTarget bool) buildVerificationFixture {
	t.Helper()
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "build-verification.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := relational.NewAccountRepository(database)
	models := relational.NewModelRepository(database)
	audits := relational.NewAuditRepository(database)
	createAccount := func(source string) accountdomain.Credential {
		value, _, createErr := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
			Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
			Name: source, SourceKey: source, EncryptedAccessToken: "encrypted",
			Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return value
	}
	keeper := createAccount("keeper")
	target := createAccount("target")
	bound := []uint64{keeper.ID}
	if bindTarget {
		bound = append(bound, target.ID)
	}
	route, err := models.Create(ctx, modeldomain.Route{
		PublicID: "verified-build", Provider: accountdomain.ProviderBuild, UpstreamModel: "grok-4.5",
		Capability: modeldomain.CapabilityResponses, Enabled: true,
	}, bound)
	if err != nil {
		t.Fatal(err)
	}
	registry := provider.NewRegistry(adapter)
	accountService := accountapp.NewService(accounts, audits, nil, memory.NewStickyStore(), registry, testCipher(t), nil)
	modelService := modelapp.NewService(models, accounts, accountService, registry)
	selector := NewSelector(accounts, memory.NewConcurrencyLimiter(), memory.NewStickyStore(), registry, time.Hour, time.Second, time.Minute)
	service := NewService(modelService, nil, accountService, nil, registry, selector, nil, 1)
	return buildVerificationFixture{ctx: ctx, service: service, models: models, accounts: accounts, target: target, keeper: keeper, route: route}
}

func TestVerifyBuildModelBindsOnlyExactHTTP200(t *testing.T) {
	adapter := &buildVerificationAdapter{status: http.StatusOK, body: `{"id":"resp_verified","status":"completed"}`}
	fixture := newBuildVerificationFixture(t, adapter, false)

	for range 2 {
		if err := fixture.service.VerifyBuildModel(fixture.ctx, fixture.target.ID, "grok-4.5"); err != nil {
			t.Fatal(err)
		}
	}
	updated, err := fixture.models.Get(fixture.ctx, fixture.route.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.BoundAccountIDs) != 2 || updated.BoundAccountIDs[0] != fixture.keeper.ID || updated.BoundAccountIDs[1] != fixture.target.ID {
		t.Fatalf("bindings = %#v", updated.BoundAccountIDs)
	}
	adapter.mu.Lock()
	requests := append([]provider.ResponseResourceRequest(nil), adapter.requests...)
	adapter.mu.Unlock()
	if len(requests) != 2 || requests[0].Credential.ID != fixture.target.ID || requests[0].Method != http.MethodPost || requests[0].Path != "/responses" || requests[0].Model != "grok-4.5" || requests[0].Streaming || !requests[0].NormalizeBody || requests[0].Operation != "responses" {
		t.Fatalf("probe requests = %#v", requests)
	}
	if body := string(requests[0].Body); !strings.Contains(body, `"model":"grok-4.5"`) || !strings.Contains(body, `"store":false`) {
		t.Fatalf("probe body = %s", body)
	}
	if !adapter.closed.Load() {
		t.Fatal("probe response body was not closed")
	}

	nonExact := &buildVerificationAdapter{status: http.StatusCreated, body: `{}`}
	nonExactFixture := newBuildVerificationFixture(t, nonExact, false)
	if err := nonExactFixture.service.VerifyBuildModel(nonExactFixture.ctx, nonExactFixture.target.ID, "grok-4.5"); err == nil {
		t.Fatal("expected non-200 response to fail verification")
	}
	nonExactRoute, err := nonExactFixture.models.Get(nonExactFixture.ctx, nonExactFixture.route.ID)
	if err != nil || len(nonExactRoute.BoundAccountIDs) != 1 || nonExactRoute.BoundAccountIDs[0] != nonExactFixture.keeper.ID {
		t.Fatalf("non-200 bindings = %#v, err = %v", nonExactRoute.BoundAccountIDs, err)
	}
}

func TestVerifyBuildModelClassifiesFailuresWithoutChangingBindings(t *testing.T) {
	permissionBody := `{"error":{"code":"permission_denied","message":"Access to the chat endpoint is denied. Please ensure you're using the correct credentials."}}`
	quotaBody := `{"error":{"message":"You have used all the included free usage for model grok-4.5"}}`
	for _, test := range []struct {
		name         string
		status       int
		body         string
		retryAfter   string
		transport    error
		wantReason   string
		wantCooldown bool
	}{
		{name: "permission denied", status: http.StatusForbidden, body: permissionBody, wantReason: "model_permission_denied"},
		{name: "unknown forbidden", status: http.StatusForbidden, body: `{"error":{"message":"policy denied"}}`},
		{name: "forbidden model quota", status: http.StatusForbidden, body: quotaBody, wantReason: "model_quota_depleted"},
		{name: "rate limited model quota", status: http.StatusTooManyRequests, body: quotaBody, retryAfter: "120", wantReason: "model_quota_depleted", wantCooldown: true},
		{name: "generic rate limit", status: http.StatusTooManyRequests, body: `{"error":{"message":"rate limited"}}`},
		{name: "upstream failure", status: http.StatusBadGateway, body: `{"error":"unavailable"}`},
		{name: "transport failure", transport: errors.New("network unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := &buildVerificationAdapter{status: test.status, body: test.body, retryAfter: test.retryAfter, err: test.transport}
			fixture := newBuildVerificationFixture(t, adapter, true)
			if err := fixture.service.VerifyBuildModel(fixture.ctx, fixture.target.ID, "grok-4.5"); err == nil {
				t.Fatal("expected verification failure")
			}
			updated, err := fixture.models.Get(fixture.ctx, fixture.route.ID)
			if err != nil || len(updated.BoundAccountIDs) != 2 || updated.BoundAccountIDs[0] != fixture.keeper.ID || updated.BoundAccountIDs[1] != fixture.target.ID {
				t.Fatalf("bindings = %#v, err = %v", updated.BoundAccountIDs, err)
			}
			candidates, err := fixture.accounts.ListRoutingCandidates(fixture.ctx, accountdomain.ProviderBuild, fixture.route.ID, "grok-4.5", "")
			if err != nil {
				t.Fatal(err)
			}
			var block *accountdomain.ModelQuotaBlock
			for _, candidate := range candidates {
				if candidate.Credential.ID == fixture.target.ID {
					block = candidate.ModelQuotaBlock
				}
			}
			var reason string
			if block != nil {
				reason = block.Reason
			}
			if reason != test.wantReason {
				t.Fatalf("block reason = %q, want %q", reason, test.wantReason)
			}
			if test.wantCooldown {
				remaining := time.Until(block.CooldownUntil)
				if remaining < 90*time.Second || remaining > 130*time.Second {
					t.Fatalf("block cooldown = %v", remaining)
				}
			}
			if test.transport == nil && !adapter.closed.Load() {
				t.Fatal("failure response body was not closed")
			}
		})
	}
}

type blockingBuildVerificationAdapter struct {
	active  atomic.Int64
	maximum atomic.Int64
	calls   atomic.Int64
	started chan struct{}
	release chan struct{}
}

func (a *blockingBuildVerificationAdapter) Provider() accountdomain.Provider {
	return accountdomain.ProviderBuild
}

func (a *blockingBuildVerificationAdapter) ForwardResponse(ctx context.Context, _ provider.ResponseResourceRequest) (*provider.Response, error) {
	active := a.active.Add(1)
	defer a.active.Add(-1)
	a.calls.Add(1)
	for {
		maximum := a.maximum.Load()
		if active <= maximum || a.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	a.started <- struct{}{}
	select {
	case <-a.release:
		return &provider.Response{StatusCode: http.StatusBadGateway, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"unavailable"}`))}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestVerifyBuildModelLimitsConcurrentProbes(t *testing.T) {
	adapter := &blockingBuildVerificationAdapter{started: make(chan struct{}, 8), release: make(chan struct{})}
	fixture := newBuildVerificationFixture(t, adapter, false)
	accountIDs := []uint64{fixture.target.ID}
	for index := 0; index < 7; index++ {
		value, _, err := fixture.accounts.UpsertByIdentity(fixture.ctx, accountdomain.Credential{
			Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
			Name: "extra", SourceKey: "extra-" + string(rune('a'+index)), EncryptedAccessToken: "encrypted",
			Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
		})
		if err != nil {
			t.Fatal(err)
		}
		accountIDs = append(accountIDs, value.ID)
	}
	var workers sync.WaitGroup
	workers.Add(len(accountIDs))
	for _, accountID := range accountIDs {
		go func() {
			defer workers.Done()
			_ = fixture.service.VerifyBuildModel(context.Background(), accountID, "grok-4.5")
		}()
	}
	for range 4 {
		select {
		case <-adapter.started:
		case <-time.After(time.Second):
			t.Fatal("four probes did not start")
		}
	}
	select {
	case <-adapter.started:
		t.Fatal("more than four probes started concurrently")
	case <-time.After(100 * time.Millisecond):
	}
	close(adapter.release)
	workers.Wait()
	if adapter.calls.Load() != int64(len(accountIDs)) || adapter.maximum.Load() != 4 {
		t.Fatalf("calls=%d max=%d", adapter.calls.Load(), adapter.maximum.Load())
	}
}
