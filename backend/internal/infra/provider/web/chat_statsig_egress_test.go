package web

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

// 注：r1.5/r1.6 的 REST chat + Statsig meta 403 换节点合同，在上游 Web Gateway
// 协议落地后不再走 openChat 主路径（Gateway 不再在 open 时拉 Statsig）。
// 仍保留：
// 1) index 403 的类型化错误（供残余 Statsig/meta 调用与 ForwardResponse 分支使用）
// 2) multi-node egress 跟踪仓库（协议测试复用）
// Gateway 层 anti-bot 换账号见 application/gateway 的
// TestGatewayAntiBotRejectionSwitchesAccountWithoutCooldown。

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
