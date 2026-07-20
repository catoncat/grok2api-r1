package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestChatRetriesStatsigMetaForbiddenOnDifferentEgress(t *testing.T) {
	adapter, credential, repository, firstNodeID, fetchNodes := newStatsigEgressRetryFixture(t, func(firstNodeID uint64, lease *infraegress.Lease) (string, error) {
		if lease.NodeID == firstNodeID {
			return "", &statsigMetaHTTPError{statusCode: http.StatusForbidden}
		}
		return "meta", nil
	})

	response, err := adapter.ForwardResponse(context.Background(), provider.ResponseResourceRequest{
		Credential: credential,
		Method:     http.MethodPost,
		Path:       "/responses",
		Body:       []byte(`{"model":"grok-chat-fast","messages":[{"role":"user","content":"hello"}],"stream":false}`),
		Model:      "grok-chat-fast",
		Operation:  "chat",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"content":"ok"`) {
		t.Fatalf("status=%d body=%s err=%v", response.StatusCode, body, err)
	}
	if len(*fetchNodes) != 2 || (*fetchNodes)[0] != firstNodeID || (*fetchNodes)[1] == firstNodeID {
		t.Fatalf("Statsig fetch nodes = %v, first=%d", *fetchNodes, firstNodeID)
	}
	failedNode, updates := repository.snapshot(firstNodeID)
	if updates != 1 || failedNode.FailureCount != 1 || failedNode.LastError != "web rejection unconfirmed" {
		t.Fatalf("failed node=%#v updates=%d", failedNode, updates)
	}
}

func TestChatDoesNotRotateEgressForGenericSigningFailure(t *testing.T) {
	adapter, credential, repository, firstNodeID, fetchNodes := newStatsigEgressRetryFixture(t, func(_ uint64, _ *infraegress.Lease) (string, error) {
		return "", errors.New("signer unavailable")
	})

	response, err := adapter.ForwardResponse(context.Background(), provider.ResponseResourceRequest{
		Credential: credential,
		Method:     http.MethodPost,
		Path:       "/responses",
		Body:       []byte(`{"model":"grok-chat-fast","messages":[{"role":"user","content":"hello"}],"stream":false}`),
		Model:      "grok-chat-fast",
		Operation:  "chat",
	})
	if response != nil || !errors.Is(err, provider.ErrRequestSigning) {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if len(*fetchNodes) != 1 || (*fetchNodes)[0] != firstNodeID {
		t.Fatalf("Statsig fetch nodes = %v, first=%d", *fetchNodes, firstNodeID)
	}
	_, updates := repository.snapshot(firstNodeID)
	if updates != 0 {
		t.Fatalf("generic signing failure updated Egress %d times", updates)
	}
}

func TestChatStopsAfterTwoStatsigMetaForbiddenNodes(t *testing.T) {
	adapter, credential, repository, firstNodeID, fetchNodes := newStatsigEgressRetryFixture(t, func(_ uint64, _ *infraegress.Lease) (string, error) {
		return "", &statsigMetaHTTPError{statusCode: http.StatusForbidden}
	})

	response, err := adapter.ForwardResponse(context.Background(), provider.ResponseResourceRequest{
		Credential: credential,
		Method:     http.MethodPost,
		Path:       "/responses",
		Body:       []byte(`{"model":"grok-chat-fast","messages":[{"role":"user","content":"hello"}],"stream":false}`),
		Model:      "grok-chat-fast",
		Operation:  "chat",
	})
	if response != nil || !errors.Is(err, provider.ErrRequestSigning) || !isStatsigMetaForbidden(err) {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if len(*fetchNodes) != 2 || (*fetchNodes)[0] != firstNodeID || (*fetchNodes)[1] == firstNodeID {
		t.Fatalf("Statsig fetch nodes = %v, first=%d", *fetchNodes, firstNodeID)
	}
	_, updates := repository.snapshot(firstNodeID)
	if updates != 1 {
		t.Fatalf("first forbidden node updated %d times", updates)
	}
}

func TestFetchStatsigMetaContentPreservesIndexForbiddenCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	empty, err := cipher.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}
	repository := newMultiTrackingEgressRepository([]egressdomain.Node{{
		ID: 201, Name: "web", Scope: egressdomain.ScopeWeb, Enabled: true, Health: 1,
		EncryptedProxyURL: empty, EncryptedCloudflareCookie: empty,
	}})
	lease, err := infraegress.NewManager(repository, cipher).Acquire(context.Background(), egressdomain.ScopeWeb, "meta")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	_, err = fetchStatsigMetaContent(context.Background(), server.URL, "token", lease)
	if !isStatsigMetaForbidden(err) {
		t.Fatalf("error=%v, want typed index 403", err)
	}
}

type statsigMetaFetcher func(firstNodeID uint64, lease *infraegress.Lease) (string, error)

func newStatsigEgressRetryFixture(t *testing.T, fetch statsigMetaFetcher) (*Adapter, account.Credential, *multiTrackingEgressRepository, uint64, *[]uint64) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/rest/app-chat/conversations/new" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: {\"result\":{\"conversation\":{\"conversationId\":\"conv_1\"}}}\n")
		_, _ = io.WriteString(writer, "data: {\"result\":{\"response\":{\"token\":\"ok\",\"isThinking\":false,\"messageTag\":\"final\"}}}\n")
		_, _ = io.WriteString(writer, "data: [DONE]\n")
	}))
	t.Cleanup(upstream.Close)

	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	emptyProxy, err := cipher.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}
	emptyCookie, err := cipher.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}
	encryptedToken, err := cipher.Encrypt("test-sso")
	if err != nil {
		t.Fatal(err)
	}
	repository := newMultiTrackingEgressRepository([]egressdomain.Node{
		{ID: 101, Name: "web-a", Scope: egressdomain.ScopeWeb, Enabled: true, Health: 1, UserAgent: "test-agent", EncryptedProxyURL: emptyProxy, EncryptedCloudflareCookie: emptyCookie},
		{ID: 102, Name: "web-b", Scope: egressdomain.ScopeWeb, Enabled: true, Health: 1, UserAgent: "test-agent", EncryptedProxyURL: emptyProxy, EncryptedCloudflareCookie: emptyCookie},
	})
	manager := infraegress.NewManager(repository, cipher)
	credential := account.Credential{ID: 42, Provider: account.ProviderWeb, AuthType: account.AuthTypeSSO, EncryptedAccessToken: encryptedToken}
	firstLease, err := manager.AcquireCredential(context.Background(), egressdomain.ScopeWeb, credential)
	if err != nil {
		t.Fatal(err)
	}
	firstNodeID := firstLease.NodeID
	firstLease.Release()

	adapter := NewAdapter(Config{BaseURL: upstream.URL, StatsigMode: "url", StatsigSignerURL: "https://signer.example/sign"}, manager, cipher, nil, nil)
	adapter.statsig.fetchLocal = func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error) {
		return statsigLocalChallenge{}, errStatsigLocalCold
	}
	fetchNodes := make([]uint64, 0, 2)
	adapter.statsig.fetchMeta = func(_ context.Context, _ string, _ string, lease *infraegress.Lease) (string, error) {
		fetchNodes = append(fetchNodes, lease.NodeID)
		return fetch(firstNodeID, lease)
	}
	adapter.statsig.validateEndpoint = func(context.Context, string) error { return nil }
	var signatures int
	adapter.statsig.client = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		signatures++
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(signatures)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	return adapter, credential, repository, firstNodeID, &fetchNodes
}

type multiTrackingEgressRepository struct {
	mu      sync.Mutex
	nodes   map[uint64]egressdomain.Node
	updates map[uint64]int
}

func newMultiTrackingEgressRepository(nodes []egressdomain.Node) *multiTrackingEgressRepository {
	value := &multiTrackingEgressRepository{nodes: make(map[uint64]egressdomain.Node, len(nodes)), updates: make(map[uint64]int)}
	for _, node := range nodes {
		value.nodes[node.ID] = node
	}
	return value
}

func (r *multiTrackingEgressRepository) ListEgressNodes(_ context.Context, scope egressdomain.Scope, _ repository.SortQuery) ([]egressdomain.Node, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	values := make([]egressdomain.Node, 0, len(r.nodes))
	for _, node := range r.nodes {
		if node.Scope == scope {
			values = append(values, node)
		}
	}
	return values, nil
}

func (r *multiTrackingEgressRepository) GetEgressNode(_ context.Context, id uint64) (egressdomain.Node, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.nodes[id]
	if !ok {
		return egressdomain.Node{}, errors.New("not found")
	}
	return value, nil
}

func (r *multiTrackingEgressRepository) CreateEgressNode(context.Context, egressdomain.Node) (egressdomain.Node, error) {
	return egressdomain.Node{}, errors.New("unsupported")
}

func (r *multiTrackingEgressRepository) UpdateEgressNode(_ context.Context, node egressdomain.Node) (egressdomain.Node, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodes[node.ID] = node
	r.updates[node.ID]++
	return node, nil
}

func (r *multiTrackingEgressRepository) DeleteEgressNode(context.Context, uint64) error {
	return errors.New("unsupported")
}

func (r *multiTrackingEgressRepository) snapshot(id uint64) (egressdomain.Node, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nodes[id], r.updates[id]
}
