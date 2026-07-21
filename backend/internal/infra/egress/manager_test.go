package egress

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	domain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestDirectFallbackRebuildsClientAfterAntiBotRejection(t *testing.T) {
	manager := &Manager{clients: map[clientCacheKey]cachedClient{{nodeID: 0, scope: domain.ScopeWeb, fingerprint: "web"}: {}}}
	manager.Feedback(context.Background(), 0, http.StatusForbidden, nil)
	if len(manager.clients) != 0 {
		t.Fatal("direct fallback client was not invalidated after anti-bot rejection")
	}
}

func TestClientCacheEvictsIdleEntriesAndEnforcesCapacity(t *testing.T) {
	now := time.Now()
	idleClient := &scriptedRequestClient{}
	freshClient := &scriptedRequestClient{}
	idleKey := clientCacheKey{nodeID: 1, scope: domain.ScopeWeb, fingerprint: "idle"}
	freshKey := clientCacheKey{nodeID: 1, scope: domain.ScopeWeb, fingerprint: "fresh"}
	manager := &Manager{clients: map[clientCacheKey]cachedClient{
		idleKey:  {client: idleClient, lastUsed: now.Add(-clientCacheIdleTTL)},
		freshKey: {client: freshClient, lastUsed: now},
	}}
	manager.cleanupClientCacheLocked(now)
	if _, exists := manager.clients[idleKey]; exists || idleClient.closedIdle != 1 {
		t.Fatalf("idle client exists=%v closed=%d", exists, idleClient.closedIdle)
	}
	if _, exists := manager.clients[freshKey]; !exists || freshClient.closedIdle != 0 {
		t.Fatalf("fresh client exists=%v closed=%d", exists, freshClient.closedIdle)
	}

	oldestClient := &scriptedRequestClient{}
	oldestKey := clientCacheKey{nodeID: 2, scope: domain.ScopeBuild, fingerprint: "oldest"}
	manager.clients = make(map[clientCacheKey]cachedClient, maxCachedClients)
	manager.clients[oldestKey] = cachedClient{client: oldestClient, lastUsed: now.Add(-time.Hour)}
	for index := 1; index < maxCachedClients; index++ {
		key := clientCacheKey{nodeID: uint64(index + 2), scope: domain.ScopeBuild, fingerprint: "cached"}
		manager.clients[key] = cachedClient{lastUsed: now}
	}
	manager.ensureClientCacheCapacityLocked()
	if len(manager.clients) != maxCachedClients-1 || oldestClient.closedIdle != 1 {
		t.Fatalf("cache size=%d oldest closed=%d", len(manager.clients), oldestClient.closedIdle)
	}
}

func TestDirectBuildAndWebClientsDoNotEvictEachOther(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{}, cipher)
	buildFirst, err := manager.Acquire(context.Background(), domain.ScopeBuild, "")
	if err != nil {
		t.Fatal(err)
	}
	defer buildFirst.Release()
	web, err := manager.Acquire(context.Background(), domain.ScopeWeb, "")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Release()
	buildSecond, err := manager.Acquire(context.Background(), domain.ScopeBuild, "")
	if err != nil {
		t.Fatal(err)
	}
	defer buildSecond.Release()

	if buildFirst.client != buildSecond.client {
		t.Fatal("Web direct traffic evicted the reusable Build connection pool")
	}
	if buildFirst.client == web.client || len(manager.clients) != 2 {
		t.Fatalf("direct clients were not isolated: build=%T web=%T cached=%d", buildFirst.client, web.client, len(manager.clients))
	}
	manager.FeedbackForScope(context.Background(), domain.ScopeWeb, 0, http.StatusForbidden, nil)
	buildAfterWebFailure, err := manager.Acquire(context.Background(), domain.ScopeBuild, "")
	if err != nil {
		t.Fatal(err)
	}
	defer buildAfterWebFailure.Release()
	if buildAfterWebFailure.client != buildFirst.client || len(manager.clients) != 1 {
		t.Fatalf("Web failure evicted Build direct client: reused=%v cached=%d", buildAfterWebFailure.client == buildFirst.client, len(manager.clients))
	}
}

func TestBrowserRequestLeavesHeaderOrderingToTLSProfile(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://grok.com/rest/app-chat/conversations/new", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", DefaultUserAgent)
	request.Header.Set("Accept", "*/*")
	converted, err := toFHTTPRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(converted.Header[fhttp.HeaderOrderKey]) != 0 || len(converted.Header[fhttp.PHeaderOrderKey]) != 0 {
		t.Fatalf("manual header order=%#v pseudo=%#v", converted.Header[fhttp.HeaderOrderKey], converted.Header[fhttp.PHeaderOrderKey])
	}
}

func TestConfiguredCoolingAppNodesNeverFallBackToDirect(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Minute)
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{{
		ID: 1, Name: "proxy", Scope: domain.ScopeWeb, Enabled: true, CooldownUntil: &until,
	}}}, cipher)
	if _, err := manager.Acquire(context.Background(), domain.ScopeWeb, "account"); err == nil {
		t.Fatal("cooling configured node unexpectedly fell back to direct")
	}
}

func TestAcquireIfConfiguredDoesNotChangeBuildDirectTransport(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{}, cipher)
	ctx, trace := WithTrace(context.Background())
	lease, configured, err := manager.AcquireIfConfigured(ctx, domain.ScopeBuild, "")
	if err != nil || configured || lease != nil {
		t.Fatalf("lease=%#v configured=%v err=%v", lease, configured, err)
	}
	selection, ok := trace.Selection(domain.ScopeBuild)
	if !ok || selection.NodeID != 0 || selection.NodeName != "direct" || selection.Proxied {
		t.Fatalf("direct selection = %#v, ok=%v", selection, ok)
	}
}

func TestTraceRecordsConfiguredProxyWithoutCredentials(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	encryptedProxy, err := cipher.Encrypt("socks5h://secret:password@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{{
		ID: 42, Name: "primary-proxy", Scope: domain.ScopeBuild, Enabled: true, Health: 1, EncryptedProxyURL: encryptedProxy,
	}}}, cipher)
	ctx, trace := WithTrace(context.Background())
	lease, configured, err := manager.AcquireIfConfigured(ctx, domain.ScopeBuild, "")
	if err != nil || !configured || lease == nil {
		t.Fatalf("lease=%#v configured=%v err=%v", lease, configured, err)
	}
	defer lease.Release()
	selection, ok := trace.Selection(domain.ScopeBuild)
	if !ok || selection.NodeID != 42 || selection.NodeName != "primary-proxy" || !selection.Proxied {
		t.Fatalf("proxy selection = %#v, ok=%v", selection, ok)
	}
}

func TestConfiguredBuildNodeDoesNotOverrideProviderUserAgent(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	encryptedProxy, err := cipher.Encrypt("socks5h://warp:1080")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{{
		ID: 1, Name: "build", Scope: domain.ScopeBuild, Enabled: true, Health: 1, UserAgent: "legacy-build-agent", EncryptedProxyURL: encryptedProxy,
	}}}, cipher)
	lease, configured, err := manager.AcquireIfConfigured(context.Background(), domain.ScopeBuild, "")
	if err != nil {
		t.Fatal(err)
	}
	if !configured || lease == nil {
		t.Fatal("configured build node did not produce a lease")
	}
	defer lease.Release()
	if lease.UserAgent != "" {
		t.Fatalf("build lease userAgent = %q", lease.UserAgent)
	}
	if _, ok := lease.client.(*http.Client); !ok || lease.browser != nil || lease.Scope != domain.ScopeBuild {
		t.Fatalf("build lease client=%T browser=%p scope=%q", lease.client, lease.browser, lease.Scope)
	}
	if _, _, err := lease.DialWebSocket(context.Background(), "wss://example.com", nil, time.Second); err == nil {
		t.Fatal("build lease unexpectedly exposed browser WebSocket")
	}
}

func TestConfiguredWebNodeKeepsChromeBrowserTransport(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{{
		ID: 1, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1,
	}}}, cipher)
	lease, err := manager.Acquire(context.Background(), domain.ScopeWeb, "account")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, ok := lease.client.(*browserClient); !ok || lease.browser == nil || lease.Scope != domain.ScopeWeb {
		t.Fatalf("web lease client=%T browser=%p scope=%q", lease.client, lease.browser, lease.Scope)
	}
}

func TestAcquireCredentialRendersResinAccountAndOverridesNodeCookie(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := cipher.Encrypt("socks5h://Default.{account}:token@resin:2260")
	if err != nil {
		t.Fatal(err)
	}
	nodeCookie, err := cipher.Encrypt("cf_clearance=node")
	if err != nil {
		t.Fatal(err)
	}
	accountCookie, err := cipher.Encrypt("cf_clearance=account")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{{
		ID: 1, Name: "resin", Scope: domain.ScopeWeb, Enabled: true, Health: 1,
		EncryptedProxyURL: proxyURL, EncryptedCloudflareCookie: nodeCookie,
	}}}, cipher)
	first, err := manager.AcquireCredential(context.Background(), domain.ScopeWeb, accountdomain.Credential{
		ID: 42, Provider: accountdomain.ProviderWeb, EncryptedCloudflareCookie: accountCookie,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	if first.ProxyURL != "socks5h://Default.grok_web_42:token@resin:2260" {
		t.Fatalf("first proxy URL = %q", first.ProxyURL)
	}
	if first.CFCookies != "cf_clearance=account" || !first.sticky {
		t.Fatalf("first lease cookie=%q sticky=%v", first.CFCookies, first.sticky)
	}
	second, err := manager.AcquireCredential(context.Background(), domain.ScopeWeb, accountdomain.Credential{
		ID: 43, Provider: accountdomain.ProviderWeb,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	if second.ProxyURL != "socks5h://Default.grok_web_43:token@resin:2260" {
		t.Fatalf("second proxy URL = %q", second.ProxyURL)
	}
	if second.CFCookies != "cf_clearance=node" {
		t.Fatalf("second lease cookie = %q", second.CFCookies)
	}
	if first.client == second.client {
		t.Fatal("different Resin accounts unexpectedly shared one connection pool")
	}
	if len(manager.clients) != 2 {
		t.Fatalf("cached Resin account pools = %d, want 2", len(manager.clients))
	}
}

func TestLinkedProvidersSharePersistedResinIdentity(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := cipher.Encrypt("socks5h://Default.{account}:token@resin:2260")
	if err != nil {
		t.Fatal(err)
	}
	firstToken, _ := cipher.Encrypt("first-sso")
	rotatedToken, _ := cipher.Encrypt("rotated-sso")
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{
		{ID: 1, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1, EncryptedProxyURL: proxyURL},
		{ID: 2, Name: "build", Scope: domain.ScopeBuild, Enabled: true, Health: 1, EncryptedProxyURL: proxyURL},
	}}, cipher)
	const identity = "sso_persisted_identity"
	web, err := manager.AcquireCredential(context.Background(), domain.ScopeWeb, accountdomain.Credential{
		ID: 11, Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO,
		EncryptedAccessToken: firstToken, EgressIdentity: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer web.Release()
	console, err := manager.AcquireCredential(context.Background(), domain.ScopeConsole, accountdomain.Credential{
		ID: 22, Provider: accountdomain.ProviderConsole, AuthType: accountdomain.AuthTypeSSO,
		EncryptedAccessToken: rotatedToken, EgressIdentity: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer console.Release()
	buildCtx := WithCredential(context.Background(), accountdomain.Credential{ID: 33, Provider: accountdomain.ProviderBuild, EgressIdentity: identity})
	build, configured, err := manager.AcquireIfConfigured(buildCtx, domain.ScopeBuild, AccountFromContext(buildCtx))
	if err != nil || !configured {
		t.Fatalf("build configured=%v err=%v", configured, err)
	}
	defer build.Release()
	for name, proxy := range map[string]string{"web": web.ProxyURL, "console": console.ProxyURL, "build": build.ProxyURL} {
		if !strings.Contains(proxy, "Default."+identity+":") {
			t.Fatalf("%s proxy = %q", name, proxy)
		}
	}
}

func TestConsoleFallsBackToWebAndSharesSSOResinIdentity(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := cipher.Encrypt("socks5h://Default.{account}:token@resin:2260")
	if err != nil {
		t.Fatal(err)
	}
	token := "shared-web-console-sso"
	encryptedToken, err := cipher.Encrypt(token)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{{
		ID: 7, Name: "shared-web", Scope: domain.ScopeWeb, Enabled: true, Health: 1,
		EncryptedProxyURL: proxyURL,
	}}}, cipher)
	web, err := manager.AcquireCredential(context.Background(), domain.ScopeWeb, accountdomain.Credential{
		ID: 11, Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO,
		EncryptedAccessToken: encryptedToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer web.Release()
	console, err := manager.AcquireCredential(context.Background(), domain.ScopeConsole, accountdomain.Credential{
		ID: 22, Provider: accountdomain.ProviderConsole, AuthType: accountdomain.AuthTypeSSO,
		EncryptedAccessToken: encryptedToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer console.Release()
	wantAccount := "sso_" + security.HashToken(token)[:32]
	if web.NodeID != 7 || console.NodeID != 7 {
		t.Fatalf("nodes web=%d console=%d, want shared Web node", web.NodeID, console.NodeID)
	}
	if !strings.Contains(web.ProxyURL, "Default."+wantAccount+":") || web.ProxyURL != console.ProxyURL {
		t.Fatalf("proxy identities web=%q console=%q", web.ProxyURL, console.ProxyURL)
	}
}

func TestBuildForbiddenDoesNotPoisonEgressNode(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repository := &mutableEgressRepository{node: domain.Node{ID: 1, Name: "build", Scope: domain.ScopeBuild, Enabled: true, Health: 1}}
	manager := NewManager(repository, cipher)
	lease, _, err := manager.AcquireIfConfigured(context.Background(), domain.ScopeBuild, "")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	manager.FeedbackForScope(context.Background(), domain.ScopeBuild, 1, http.StatusForbidden, nil)
	if repository.updates != 0 || repository.node.Health != 1 || repository.node.LastError != "" {
		t.Fatalf("build 403 poisoned node: updates=%d node=%#v", repository.updates, repository.node)
	}
	if !managerHasClientForNode(manager, 1) {
		t.Fatal("build client was invalidated by an ambiguous 403")
	}
}

func TestStickyProxyForbiddenDoesNotCooldownSharedNode(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := cipher.Encrypt("socks5h://Default.{account}:token@resin:2260")
	if err != nil {
		t.Fatal(err)
	}
	repository := &mutableEgressRepository{node: domain.Node{ID: 1, Name: "resin", Scope: domain.ScopeWeb, Enabled: true, Health: 1, EncryptedProxyURL: proxy}}
	manager := NewManager(repository, cipher)
	lease, err := manager.AcquireCredential(context.Background(), domain.ScopeWeb, accountdomain.Credential{ID: 42, Provider: accountdomain.ProviderWeb})
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	manager.Feedback(context.Background(), 1, http.StatusForbidden, nil)
	if repository.updates != 0 || repository.node.Health != 1 || repository.node.LastError != "" {
		t.Fatalf("sticky proxy 403 changed shared node: updates=%d node=%#v", repository.updates, repository.node)
	}
}

func TestWebAssetCredentialFallsBackToWebWithSameResinIdentity(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := cipher.Encrypt("socks5h://Default.{account}:token@resin:2260")
	if err != nil {
		t.Fatal(err)
	}
	accountCookie, err := cipher.Encrypt("cf_clearance=account")
	if err != nil {
		t.Fatal(err)
	}
	token := "shared-web-asset-sso"
	encryptedToken, err := cipher.Encrypt(token)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{
		{ID: 2, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1, EncryptedProxyURL: proxyURL},
	}}, cipher)
	credential := accountdomain.Credential{
		ID: 42, Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO,
		EncryptedAccessToken: encryptedToken, EncryptedCloudflareCookie: accountCookie,
	}
	webLease, err := manager.AcquireCredential(context.Background(), domain.ScopeWeb, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer webLease.Release()
	lease, err := manager.AcquireCredential(context.Background(), domain.ScopeWebAsset, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if lease.NodeID != 2 {
		t.Fatalf("node = %d, want web fallback node 2", lease.NodeID)
	}
	wantAccount := "sso_" + security.HashToken(token)[:32]
	if lease.ProxyURL != webLease.ProxyURL || !strings.Contains(lease.ProxyURL, "Default."+wantAccount+":") {
		t.Fatalf("proxy identities web=%q asset=%q", webLease.ProxyURL, lease.ProxyURL)
	}
	if lease.CFCookies != "cf_clearance=account" {
		t.Fatalf("asset lease cookie = %q", lease.CFCookies)
	}
	if lease.client != webLease.client {
		t.Fatal("Web Asset credential fallback did not reuse the matching Web browser session")
	}
}

func TestEgressNodeSnapshotAvoidsRepeatedRepositoryReads(t *testing.T) {
	repository := &countingEgressRepository{egressRepositoryTestStub: egressRepositoryTestStub{nodes: []domain.Node{{ID: 1, Scope: domain.ScopeWeb, Enabled: true}}}}
	manager := NewManager(repository, nil)
	now := time.Now().UTC()
	for range 2 {
		values, err := manager.listNodes(context.Background(), domain.ScopeWeb, now)
		if err != nil || len(values) != 1 {
			t.Fatalf("nodes=%#v err=%v", values, err)
		}
	}
	if repository.calls != 1 {
		t.Fatalf("repository reads = %d, want 1", repository.calls)
	}
}

func TestAffinitySelectionKeepsRecoverableNodesInMixedFleet(t *testing.T) {
	manager := NewManager(nil, nil)
	nodes := make([]domain.Node, 15)
	for index := range nodes {
		nodes[index] = domain.Node{ID: uint64(index + 1), Health: 1}
	}
	for index := 0; index < 8; index++ {
		nodes[index].Health = 0.7
	}
	counts := make(map[uint64]int)
	for accountID := 1; accountID <= 10000; accountID++ {
		selected, ok := manager.selectNode(nodes, fmt.Sprintf("%d", accountID))
		if !ok {
			t.Fatal("ready fleet returned no node")
		}
		if selected.Health < affinityHealthFloor {
			t.Fatalf("selected node below fleet floor %d", selected.ID)
		}
		counts[selected.ID]++
	}
	if len(counts) != len(nodes) {
		t.Fatalf("selected ready nodes=%d, want %d", len(counts), len(nodes))
	}
}

func TestAffinitySelectionExcludesNodesBelowFleetFloor(t *testing.T) {
	manager := NewManager(nil, nil)
	nodes := make([]domain.Node, 15)
	for index := range nodes {
		nodes[index] = domain.Node{ID: uint64(index + 1), Health: 1}
	}
	for index := 0; index < 8; index++ {
		nodes[index].Health = affinityHealthFloor - 0.01
	}
	counts := make(map[uint64]int)
	for accountID := 1; accountID <= 10000; accountID++ {
		selected, ok := manager.selectNode(nodes, fmt.Sprintf("%d", accountID))
		if !ok {
			t.Fatal("ready fleet returned no node")
		}
		if selected.Health < affinityHealthFloor {
			t.Fatalf("selected node below fleet floor %d", selected.ID)
		}
		counts[selected.ID]++
	}
	if len(counts) != 7 {
		t.Fatalf("selected ready nodes=%d, want 7", len(counts))
	}
}

func TestAffinitySelectionIncludesFleetFloorBoundary(t *testing.T) {
	manager := NewManager(nil, nil)
	nodes := []domain.Node{
		{ID: 1, Health: 1},
		{ID: 2, Health: affinityHealthFloor},
	}
	seen := make(map[uint64]bool)
	for accountID := 1; accountID <= 1000; accountID++ {
		selected, ok := manager.selectNode(nodes, fmt.Sprintf("%d", accountID))
		if !ok {
			t.Fatal("fleet-floor boundary returned no node")
		}
		seen[selected.ID] = true
	}
	if !seen[2] {
		t.Fatal("node at the fleet health floor never re-entered affinity selection")
	}
}

func TestAffinitySelectionExcludesConfirmedAntiBotBeforeFleetSync(t *testing.T) {
	manager := NewManager(nil, nil)
	nodes := []domain.Node{
		{ID: 1, Health: 1},
		{ID: 2, Health: 0.7, LastError: "anti-bot rejection"},
	}
	for accountID := 1; accountID <= 1000; accountID++ {
		selected, ok := manager.selectNode(nodes, fmt.Sprintf("%d", accountID))
		if !ok {
			t.Fatal("safe node was not selected")
		}
		if selected.ID != 1 {
			t.Fatalf("selected confirmed anti-bot node %d", selected.ID)
		}
	}
}

func TestAffinitySelectionDoesNotCollapseWhenEveryNodeIsBelowFleetFloor(t *testing.T) {
	manager := NewManager(nil, nil)
	nodes := make([]domain.Node, 15)
	for index := range nodes {
		nodes[index] = domain.Node{ID: uint64(index + 1), Health: affinityHealthFloor - 0.01}
	}
	counts := make(map[uint64]int)
	for accountID := 1; accountID <= 10000; accountID++ {
		selected, ok := manager.selectNode(nodes, fmt.Sprintf("%d", accountID))
		if !ok {
			t.Fatal("degraded but safe fleet returned no node")
		}
		counts[selected.ID]++
	}
	if len(counts) != len(nodes) {
		t.Fatalf("selected fallback nodes=%d, want %d", len(counts), len(nodes))
	}
}

func TestAffinitySelectionFailsClosedWhenEveryNodeIsConfirmedAntiBot(t *testing.T) {
	manager := NewManager(nil, nil)
	nodes := []domain.Node{
		{ID: 1, Health: 1, LastError: "anti-bot rejection"},
		{ID: 2, Health: 0.7, LastError: "upstream anti-bot challenge"},
	}
	if selected, ok := manager.selectNode(nodes, "account"); ok {
		t.Fatalf("selected confirmed anti-bot node %d", selected.ID)
	}
}

func TestAcquireFailsClosedWhenEveryNodeIsConfirmedAntiBot(t *testing.T) {
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{
		{ID: 1, Scope: domain.ScopeWeb, Enabled: true, Health: 1, LastError: "anti-bot rejection"},
		{ID: 2, Scope: domain.ScopeWeb, Enabled: true, Health: 0.7, LastError: "upstream anti-bot challenge"},
	}}, nil)
	lease, err := manager.Acquire(context.Background(), domain.ScopeWeb, "account")
	if lease != nil {
		lease.Release()
		t.Fatal("acquired confirmed anti-bot node")
	}
	if err == nil || !strings.Contains(err.Error(), "当前没有可用") {
		t.Fatalf("Acquire error = %v", err)
	}
}

func TestAffinitySelectionOnlyRemapsAssignmentsFromRemovedNode(t *testing.T) {
	manager := NewManager(nil, nil)
	nodes := make([]domain.Node, 15)
	for index := range nodes {
		nodes[index] = domain.Node{ID: uint64(index + 1), Health: 1}
	}
	remaining := append([]domain.Node(nil), nodes[:14]...)
	for accountID := 1; accountID <= 10000; accountID++ {
		affinity := fmt.Sprintf("%d", accountID)
		before, beforeOK := manager.selectNode(nodes, affinity)
		after, afterOK := manager.selectNode(remaining, affinity)
		if !beforeOK || !afterOK {
			t.Fatal("healthy fleet returned no node")
		}
		if before.ID != 15 && after.ID != before.ID {
			t.Fatalf("account %d moved from node %d to node %d", accountID, before.ID, after.ID)
		}
	}
}

func TestConsoleFallbackFeedbackDoesNotCoolWebResinNode(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := cipher.Encrypt("socks5h://Default.{account}:token@resin:2260")
	if err != nil {
		t.Fatal(err)
	}
	repository := &mutableEgressRepository{node: domain.Node{
		ID: 7, Name: "shared-web", Scope: domain.ScopeWeb, Enabled: true, Health: 1,
		EncryptedProxyURL: proxyURL,
	}}
	manager := NewManager(repository, cipher)
	web, err := manager.AcquireCredential(context.Background(), domain.ScopeWeb, accountdomain.Credential{ID: 11, Provider: accountdomain.ProviderWeb})
	if err != nil {
		t.Fatal(err)
	}
	defer web.Release()
	console, err := manager.AcquireCredential(context.Background(), domain.ScopeConsole, accountdomain.Credential{ID: 22, Provider: accountdomain.ProviderConsole})
	if err != nil {
		t.Fatal(err)
	}
	defer console.Release()

	manager.FeedbackForLease(context.Background(), console, http.StatusBadGateway, errors.New("console transport failed"))

	if repository.updates != 0 || repository.node.Health != 1 || repository.node.CooldownUntil != nil {
		t.Fatalf("Web Resin node was mutated by Console feedback: updates=%d node=%#v", repository.updates, repository.node)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	webClientPresent := false
	consoleClientPresent := false
	for key := range manager.clients {
		webClientPresent = webClientPresent || (key.nodeID == 7 && key.scope == domain.ScopeWeb)
		consoleClientPresent = consoleClientPresent || (key.nodeID == 7 && key.scope == domain.ScopeConsole)
	}
	if !webClientPresent {
		t.Fatal("Web Resin client was invalidated by Console feedback")
	}
	if consoleClientPresent {
		t.Fatal("failed Console fallback client was not invalidated")
	}
}

func TestConsoleDoesNotFallBackToStaticWebNode(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{{
		ID: 7, Name: "static-web", Scope: domain.ScopeWeb, Enabled: true, Health: 1,
	}}}, cipher)
	lease, err := manager.AcquireCredential(context.Background(), domain.ScopeConsole, accountdomain.Credential{
		ID: 22, Provider: accountdomain.ProviderConsole,
	})
	if err == nil || lease != nil {
		t.Fatalf("static Web node was reused for Console: lease=%#v err=%v", lease, err)
	}
}

func TestBuildOAuthPending400DoesNotCoolEgressNode(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repository := &mutableEgressRepository{node: domain.Node{ID: 1, Name: "build", Scope: domain.ScopeBuild, Enabled: true, Health: 1}}
	manager := NewManager(repository, cipher)
	lease, _, err := manager.AcquireIfConfigured(context.Background(), domain.ScopeBuild, "")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	manager.FeedbackForScope(context.Background(), domain.ScopeBuild, 1, http.StatusBadRequest, nil)
	if repository.updates != 0 || repository.node.Health != 1 || repository.node.LastError != "" || repository.node.CooldownUntil != nil {
		t.Fatalf("build OAuth pending 400 changed node: updates=%d node=%#v", repository.updates, repository.node)
	}
	if !managerHasClientForNode(manager, 1) {
		t.Fatal("build client was invalidated by OAuth pending 400")
	}
}

func TestWebForbiddenRequiresConfirmationBeforePoisoningNode(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repository := &mutableEgressRepository{node: domain.Node{ID: 1, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1}}
	manager := NewManager(repository, cipher)
	lease, err := manager.Acquire(context.Background(), domain.ScopeWeb, "account")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	manager.Feedback(context.Background(), 1, http.StatusForbidden, nil)
	if repository.updates != 1 || repository.node.Health != 1 || repository.node.FailureCount != 1 || repository.node.LastError != "web rejection unconfirmed" {
		t.Fatalf("first web 403 feedback = updates=%d node=%#v", repository.updates, repository.node)
	}
	if managerHasClientForNode(manager, 1) {
		t.Fatal("web browser session was not invalidated after 403")
	}
	manager.Feedback(context.Background(), 1, http.StatusForbidden, nil)
	if repository.updates != 2 || repository.node.Health >= 1 || repository.node.FailureCount != 2 || repository.node.LastError != "anti-bot rejection" {
		t.Fatalf("confirmed web 403 feedback = updates=%d node=%#v", repository.updates, repository.node)
	}
}

func TestWebSuccessClearsUnconfirmedRejection(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repository := &mutableEgressRepository{node: domain.Node{ID: 1, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1}}
	manager := NewManager(repository, cipher)
	manager.Feedback(context.Background(), 1, http.StatusForbidden, nil)
	manager.Feedback(context.Background(), 1, http.StatusOK, nil)
	manager.Feedback(context.Background(), 1, http.StatusForbidden, nil)
	if repository.node.Health != 1 || repository.node.FailureCount != 1 || repository.node.LastError != "web rejection unconfirmed" {
		t.Fatalf("web feedback after recovery = %#v", repository.node)
	}
}

func TestConcurrentWebForbiddenFeedbackConfirmsNode(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	repository := &mutableEgressRepository{node: domain.Node{ID: 1, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1}}
	manager := NewManager(repository, cipher)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			manager.Feedback(context.Background(), 1, http.StatusForbidden, nil)
		}()
	}
	close(start)
	wait.Wait()
	if repository.updates != 2 || repository.node.FailureCount != 2 || repository.node.LastError != "anti-bot rejection" {
		t.Fatalf("concurrent web feedback = updates=%d node=%#v", repository.updates, repository.node)
	}
}

func TestWebAssetFallsBackToWeb(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{
		{ID: 2, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1},
	}}, cipher)
	webLease, err := manager.Acquire(context.Background(), domain.ScopeWeb, "account")
	if err != nil {
		t.Fatal(err)
	}
	defer webLease.Release()
	lease, err := manager.Acquire(context.Background(), domain.ScopeWebAsset, "account")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if lease.NodeID != 2 {
		t.Fatalf("node = %d, want web fallback node 2", lease.NodeID)
	}
	if lease.client != webLease.client {
		t.Fatal("Web Asset fallback did not reuse the matching Web browser session")
	}
}

func TestWebAssetFallsBackWhenAssetNodesAreConfirmedAntiBot(t *testing.T) {
	cipher, err := security.NewCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(egressRepositoryTestStub{nodes: []domain.Node{
		{ID: 1, Name: "asset", Scope: domain.ScopeWebAsset, Enabled: true, Health: 1, LastError: "anti-bot rejection"},
		{ID: 2, Name: "web", Scope: domain.ScopeWeb, Enabled: true, Health: 1},
	}}, cipher)
	lease, err := manager.Acquire(context.Background(), domain.ScopeWebAsset, "account")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if lease.NodeID != 2 {
		t.Fatalf("node = %d, want safe web fallback node 2", lease.NodeID)
	}
}

type egressRepositoryTestStub struct{ nodes []domain.Node }

func managerHasClientForNode(manager *Manager, nodeID uint64) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for key := range manager.clients {
		if key.nodeID == nodeID {
			return true
		}
	}
	return false
}

type countingEgressRepository struct {
	egressRepositoryTestStub
	calls int
}

type mutableEgressRepository struct {
	node    domain.Node
	updates int
}

func (r *mutableEgressRepository) ListEgressNodes(_ context.Context, scope domain.Scope, _ repository.SortQuery) ([]domain.Node, error) {
	if scope != "" && r.node.Scope != scope {
		return nil, nil
	}
	return []domain.Node{r.node}, nil
}

func (r *mutableEgressRepository) GetEgressNode(_ context.Context, id uint64) (domain.Node, error) {
	if r.node.ID != id {
		return domain.Node{}, errors.New("not found")
	}
	return r.node, nil
}

func (r *mutableEgressRepository) CreateEgressNode(_ context.Context, value domain.Node) (domain.Node, error) {
	r.node = value
	return value, nil
}

func (r *mutableEgressRepository) UpdateEgressNode(_ context.Context, value domain.Node) (domain.Node, error) {
	r.node = value
	r.updates++
	return value, nil
}

func (r *mutableEgressRepository) DeleteEgressNode(_ context.Context, id uint64) error {
	if r.node.ID != id {
		return errors.New("not found")
	}
	r.node = domain.Node{}
	return nil
}

func (r *countingEgressRepository) ListEgressNodes(ctx context.Context, scope domain.Scope, sort repository.SortQuery) ([]domain.Node, error) {
	r.calls++
	return r.egressRepositoryTestStub.ListEgressNodes(ctx, scope, sort)
}

func (s egressRepositoryTestStub) ListEgressNodes(_ context.Context, scope domain.Scope, _ repository.SortQuery) ([]domain.Node, error) {
	values := make([]domain.Node, 0, len(s.nodes))
	for _, node := range s.nodes {
		if scope == "" || node.Scope == scope {
			values = append(values, node)
		}
	}
	return values, nil
}
func (egressRepositoryTestStub) GetEgressNode(context.Context, uint64) (domain.Node, error) {
	return domain.Node{}, errors.New("not found")
}
func (egressRepositoryTestStub) CreateEgressNode(context.Context, domain.Node) (domain.Node, error) {
	return domain.Node{}, errors.New("unsupported")
}
func (egressRepositoryTestStub) UpdateEgressNode(context.Context, domain.Node) (domain.Node, error) {
	return domain.Node{}, errors.New("unsupported")
}
func (egressRepositoryTestStub) DeleteEgressNode(context.Context, uint64) error {
	return errors.New("unsupported")
}
