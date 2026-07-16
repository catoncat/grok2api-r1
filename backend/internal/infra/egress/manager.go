package egress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	application "github.com/chenyme/grok2api/backend/internal/application/egress"
	domain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"golang.org/x/sync/singleflight"
)

const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
const (
	nodeSnapshotTTL     = time.Second
	affinityHealthFloor = 0.5
)

type Lease struct {
	NodeID    uint64
	NodeName  string
	Scope     domain.Scope
	ProxyURL  string
	UserAgent string
	CFCookies string
	client    requestClient
	browser   *browserClient
	release   func()
}

type requestClient interface {
	Do(*http.Request) (*http.Response, error)
	CloseIdleConnections()
}

func (l *Lease) Do(request *http.Request) (*http.Response, error) {
	if l == nil || l.client == nil {
		return nil, errors.New("出口客户端未初始化")
	}
	return l.client.Do(request)
}
func (l *Lease) Release() {
	if l != nil && l.release != nil {
		l.release()
		l.release = nil
	}
}

type Manager struct {
	repository repository.EgressRepository
	cipher     *security.Cipher
	feedbackMu sync.Mutex
	mu         sync.Mutex
	clients    map[clientCacheKey]cachedClient
	inflight   map[uint64]int
	nodes      map[domain.Scope]cachedNodeSnapshot
	nodeLoads  singleflight.Group
}

type cachedClient struct {
	client  requestClient
	browser *browserClient
}

type clientCacheKey struct {
	nodeID      uint64
	scope       domain.Scope
	fingerprint string
}

type cachedNodeSnapshot struct {
	values    []domain.Node
	expiresAt time.Time
}

func NewManager(repository repository.EgressRepository, cipher *security.Cipher) *Manager {
	return &Manager{repository: repository, cipher: cipher, clients: make(map[clientCacheKey]cachedClient), inflight: make(map[uint64]int), nodes: make(map[domain.Scope]cachedNodeSnapshot)}
}

func (m *Manager) Acquire(ctx context.Context, scope domain.Scope, affinity string) (*Lease, error) {
	lease, _, err := m.acquire(ctx, scope, affinity, true)
	return lease, err
}

func (m *Manager) AcquireIfConfigured(ctx context.Context, scope domain.Scope, affinity string) (*Lease, bool, error) {
	return m.acquire(ctx, scope, affinity, false)
}

func (m *Manager) acquire(ctx context.Context, scope domain.Scope, affinity string, allowDirect bool) (*Lease, bool, error) {
	now := time.Now().UTC()
	configured := false
	var available []domain.Node
	for _, candidateScope := range fallbackScopes(scope) {
		nodes, err := m.listNodes(ctx, candidateScope, now)
		if err != nil {
			return nil, false, err
		}
		configured = configured || len(nodes) > 0
		candidateAvailable := make([]domain.Node, 0, len(nodes))
		for _, node := range nodes {
			if node.Enabled && (node.CooldownUntil == nil || !now.Before(*node.CooldownUntil)) {
				candidateAvailable = append(candidateAvailable, node)
			}
		}
		if len(candidateAvailable) > 0 {
			available = candidateAvailable
			break
		}
	}
	if len(available) == 0 {
		if configured {
			return nil, false, fmt.Errorf("当前没有可用的 %s 出口节点", scope)
		}
		if !allowDirect {
			recordSelection(ctx, Selection{NodeName: "direct", Scope: scope})
			return nil, false, nil
		}
		available = []domain.Node{{ID: 0, Name: "direct", Scope: scope, Enabled: true, Health: 1}}
	}
	sort.SliceStable(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	selected, ok := m.selectNode(available, affinity)
	if !ok {
		return nil, false, fmt.Errorf("当前没有可用的 %s 出口节点", scope)
	}
	proxyURL, err := m.cipher.Decrypt(selected.EncryptedProxyURL)
	if err != nil {
		return nil, false, err
	}
	proxyURL, err = application.NormalizeProxyURL(proxyURL)
	if err != nil {
		return nil, false, err
	}
	cookies := ""
	if scope != domain.ScopeBuild {
		cookies, err = m.cipher.Decrypt(selected.EncryptedCloudflareCookie)
		if err != nil {
			return nil, false, err
		}
		cookies = application.SanitizeCloudflareCookies(cookies)
	}
	userAgent := ""
	if scope != domain.ScopeBuild {
		userAgent = strings.TrimSpace(selected.UserAgent)
	}
	if scope != domain.ScopeBuild && userAgent == "" {
		userAgent = DefaultUserAgent
	}
	client, err := m.clientFor(selected.ID, scope, proxyURL, userAgent, cookies)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	m.inflight[selected.ID]++
	m.mu.Unlock()
	recordSelection(ctx, Selection{NodeID: selected.ID, NodeName: selected.Name, Scope: scope, Proxied: proxyURL != ""})
	var once sync.Once
	return &Lease{NodeID: selected.ID, NodeName: selected.Name, Scope: scope, ProxyURL: proxyURL, UserAgent: userAgent, CFCookies: cookies, client: client.client, browser: client.browser, release: func() {
		once.Do(func() {
			m.mu.Lock()
			m.inflight[selected.ID]--
			if m.inflight[selected.ID] <= 0 {
				delete(m.inflight, selected.ID)
			}
			m.mu.Unlock()
		})
	}}, true, nil
}

func (m *Manager) listNodes(ctx context.Context, scope domain.Scope, now time.Time) ([]domain.Node, error) {
	m.mu.Lock()
	if snapshot, ok := m.nodes[scope]; ok && now.Before(snapshot.expiresAt) {
		values := append([]domain.Node(nil), snapshot.values...)
		m.mu.Unlock()
		return values, nil
	}
	m.mu.Unlock()
	loaded, err, _ := m.nodeLoads.Do(string(scope), func() (any, error) {
		checkTime := time.Now().UTC()
		m.mu.Lock()
		if snapshot, ok := m.nodes[scope]; ok && checkTime.Before(snapshot.expiresAt) {
			values := append([]domain.Node(nil), snapshot.values...)
			m.mu.Unlock()
			return values, nil
		}
		m.mu.Unlock()
		values, err := m.repository.ListEgressNodes(ctx, scope, repository.SortQuery{})
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		m.nodes[scope] = cachedNodeSnapshot{values: append([]domain.Node(nil), values...), expiresAt: checkTime.Add(nodeSnapshotTTL)}
		m.mu.Unlock()
		return values, nil
	})
	if err != nil {
		return nil, err
	}
	return append([]domain.Node(nil), loaded.([]domain.Node)...), nil
}

func (m *Manager) invalidateNodes(scope domain.Scope) {
	m.mu.Lock()
	delete(m.nodes, scope)
	m.mu.Unlock()
}

func fallbackScopes(scope domain.Scope) []domain.Scope {
	if scope == domain.ScopeWebAsset {
		return []domain.Scope{domain.ScopeWebAsset, domain.ScopeWeb}
	}
	return []domain.Scope{scope}
}

func (m *Manager) selectNode(nodes []domain.Node, affinity string) (domain.Node, bool) {
	safe := make([]domain.Node, 0, len(nodes))
	for _, node := range nodes {
		if !strings.Contains(strings.ToLower(node.LastError), "anti-bot") {
			safe = append(safe, node)
		}
	}
	if len(safe) == 0 {
		return domain.Node{}, false
	}
	if affinity != "" {
		candidates := make([]domain.Node, 0, len(safe))
		for _, node := range safe {
			if node.Health >= affinityHealthFloor {
				candidates = append(candidates, node)
			}
		}
		if len(candidates) == 0 {
			candidates = safe
		}
		return rendezvousNode(candidates, affinity), true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	best := safe[0]
	for _, node := range safe[1:] {
		if m.inflight[node.ID] < m.inflight[best.ID] || (m.inflight[node.ID] == m.inflight[best.ID] && node.Health > best.Health) {
			best = node
		}
	}
	return best, true
}

func rendezvousNode(nodes []domain.Node, affinity string) domain.Node {
	selected := nodes[0]
	best := rendezvousScore(affinity, selected.ID)
	for _, node := range nodes[1:] {
		score := rendezvousScore(affinity, node.ID)
		if bytes.Compare(score[:], best[:]) > 0 {
			selected = node
			best = score
		}
	}
	return selected
}

func rendezvousScore(affinity string, nodeID uint64) [sha256.Size]byte {
	var encodedNodeID [8]byte
	binary.BigEndian.PutUint64(encodedNodeID[:], nodeID)
	hash := sha256.New()
	_, _ = hash.Write([]byte(affinity))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encodedNodeID[:])
	var score [sha256.Size]byte
	copy(score[:], hash.Sum(nil))
	return score
}

func (m *Manager) clientFor(id uint64, scope domain.Scope, proxyURL, userAgent, cookies string) (cachedClient, error) {
	clientKind := "browser"
	if scope == domain.ScopeBuild {
		clientKind = "build"
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(clientKind+"\x00"+proxyURL+"\x00"+userAgent+"\x00"+cookies)))
	cacheScope := scope
	if cacheScope == domain.ScopeWebAsset {
		cacheScope = domain.ScopeWeb
	}
	key := clientCacheKey{nodeID: id, scope: cacheScope, fingerprint: fingerprint}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.clients[key]; ok {
		return cached, nil
	}
	var value cachedClient
	if scope == domain.ScopeBuild {
		client, err := newBuildClient(proxyURL)
		if err != nil {
			return cachedClient{}, err
		}
		value.client = client
	} else {
		client, err := newBrowserClient(proxyURL)
		if err != nil {
			return cachedClient{}, err
		}
		value.client = client
		value.browser = client
	}
	// 持久化节点只属于一个 Scope；同节点出现新指纹说明配置已更新，旧连接池应淘汰。
	// 直连节点统一使用 ID 0，不同 Provider 的传输必须并存，避免 Build 与 Web 互相重建客户端。
	if id != 0 {
		for previousKey, previous := range m.clients {
			if previousKey.nodeID != id {
				continue
			}
			if previous.client != nil {
				previous.client.CloseIdleConnections()
			}
			delete(m.clients, previousKey)
		}
	}
	m.clients[key] = value
	return value, nil
}

func (m *Manager) Feedback(ctx context.Context, nodeID uint64, status int, transportErr error) {
	m.FeedbackForScope(ctx, domain.ScopeWeb, nodeID, status, transportErr)
}

func (m *Manager) FeedbackForScope(ctx context.Context, scope domain.Scope, nodeID uint64, status int, transportErr error) {
	if nodeID == 0 {
		if transportErr != nil || status >= 500 || (scope != domain.ScopeBuild && status == http.StatusForbidden) {
			m.mu.Lock()
			m.invalidateClientForScopeLocked(0, scope)
			m.mu.Unlock()
		}
		return
	}
	m.feedbackMu.Lock()
	defer m.feedbackMu.Unlock()
	value, err := m.repository.GetEgressNode(ctx, nodeID)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	before := value.Health
	kind := "noop"
	switch {
	case transportErr == nil && status >= 200 && status < 400:
		value.Health = min(1, value.Health+0.1)
		value.FailureCount = 0
		value.CooldownUntil = nil
		value.LastError = ""
		kind = "success"
	case status == http.StatusUnauthorized || status == http.StatusTooManyRequests:
		return
	case scope == domain.ScopeBuild && status == http.StatusForbidden:
		// Build 403 可能是账号权限、额度、Token 或出口策略，响应体由网关层
		// 分类；仅凭状态码不能把标准 CLI 出口误判为 Web anti-bot。
		return
	case status == http.StatusForbidden:
		confirmed := value.FailureCount > 0 && value.LastError == "web rejection unconfirmed"
		if confirmed {
			value.FailureCount++
			value.Health = max(0.05, value.Health*0.7)
			value.LastError = "anti-bot rejection"
			kind = "anti_bot"
		} else {
			value.FailureCount = 1
			value.LastError = "web rejection unconfirmed"
			kind = "anti_bot_suspect"
		}
		value.CooldownUntil = nil
		m.mu.Lock()
		m.invalidateClientLocked(nodeID)
		m.mu.Unlock()
	default:
		value.FailureCount++
		value.Health = max(0.05, value.Health*0.7)
		cooldown := min(10*time.Minute, 30*time.Second*time.Duration(1<<min(value.FailureCount-1, 4)))
		until := now.Add(cooldown)
		value.CooldownUntil = &until
		if transportErr != nil {
			value.LastError = "transport error"
			kind = "transport"
		} else {
			value.LastError = fmt.Sprintf("upstream status %d", status)
			kind = "status"
		}
		m.mu.Lock()
		m.invalidateClientLocked(nodeID)
		m.mu.Unlock()
	}
	crossed := before >= 0.5 && value.Health < 0.5
	// Log failures and threshold crossings; skip routine success heals to keep volume low.
	if kind != "success" || crossed {
		slog.Default().Info("egress_feedback",
			"node_id", nodeID,
			"scope", string(scope),
			"kind", kind,
			"status", status,
			"health_before", before,
			"health_after", value.Health,
			"failure_count", value.FailureCount,
			"crossed_threshold", crossed,
			"last_error", value.LastError,
		)
	}
	if _, err := m.repository.UpdateEgressNode(ctx, value); err == nil {
		m.invalidateNodes(value.Scope)
	}
}

func (m *Manager) invalidateClientLocked(nodeID uint64) {
	for key, cached := range m.clients {
		if key.nodeID != nodeID {
			continue
		}
		if cached.client != nil {
			cached.client.CloseIdleConnections()
		}
		delete(m.clients, key)
	}
}

func (m *Manager) invalidateClientForScopeLocked(nodeID uint64, scope domain.Scope) {
	if scope == domain.ScopeWebAsset {
		scope = domain.ScopeWeb
	}
	for key, cached := range m.clients {
		if key.nodeID != nodeID || key.scope != scope {
			continue
		}
		if cached.client != nil {
			cached.client.CloseIdleConnections()
		}
		delete(m.clients, key)
	}
}

func BuildSSOCookie(token, cloudflareCookies string) string {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "sso=") {
		token = strings.TrimSpace(token[len("sso="):])
	}
	if value, _, found := strings.Cut(token, ";"); found {
		token = strings.TrimSpace(value)
	}
	token = strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(token)
	cookies := "sso=" + token + "; sso-rw=" + token
	if sanitized := application.SanitizeCloudflareCookies(cloudflareCookies); sanitized != "" {
		cookies += "; " + sanitized
	}
	return cookies
}
