package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	domainegress "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/pkg/signerurl"
	"golang.org/x/net/html"
	"golang.org/x/sync/singleflight"
)

const (
	defaultStatsigSignerURL = "https://grok.wodf.de/sign"
	statsigCacheTTL         = time.Hour
	statsigMetaMaxEntries   = 4096
	statsigSignAttempts     = 3
	statsigMetaAttempts     = 2
	statsigInvalidateWindow = 30 * time.Second
	statsigMetaBodyLimit    = 4 << 20
	statsigResponseLimit    = 4 << 10
	statsigLocalMaxEntries  = 16
	statsigRecentMaxEntries = 64 << 10
)

type statsigCacheEntry struct {
	value     string
	expiresAt time.Time
}

type statsigMetaResult struct {
	value      string
	source     string
	generation uint64
}

type statsigSignatureEntry struct {
	value  string
	seenAt time.Time
}

type statsigSigner struct {
	client           *http.Client
	fetchMeta        func(context.Context, string, string, *infraegress.Lease) (string, error)
	validateEndpoint func(context.Context, string) error
	now              func() time.Time
	mu               sync.Mutex
	entries          map[string]statsigCacheEntry
	recentSignatures map[string]time.Time
	recentOrder      []statsigSignatureEntry
	invalidations    map[string]time.Time
	generation       uint64
	refreshes        singleflight.Group
	localRefreshes   singleflight.Group
	locals           map[string]statsigLocalChallenge
	fetchLocal       func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error)
}

var errStatsigMetaInvalidated = errors.New("Statsig meta refresh invalidated")
var errStatsigLocalCold = errors.New("local Statsig is not warmed")

func newStatsigSigner() *statsigSigner {
	return &statsigSigner{
		client: &http.Client{
			Timeout:       12 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		fetchMeta:        fetchStatsigMetaContent,
		validateEndpoint: validateStatsigSignerEndpoint,
		now:              time.Now,
		entries:          make(map[string]statsigCacheEntry),
		recentSignatures: make(map[string]time.Time),
		invalidations:    make(map[string]time.Time),
		locals:           make(map[string]statsigLocalChallenge),
		fetchLocal:       fetchStatsigLocalChallenge,
	}
}

func (s *statsigSigner) Sign(ctx context.Context, baseURL, signerURL, token string, lease *infraegress.Lease, method, target string, forceRemoteArgs ...bool) (string, string, error) {
	forceRemote := len(forceRemoteArgs) > 0 && forceRemoteArgs[0]
	path, err := statsigSignaturePath(target)
	if err != nil {
		return "", "", err
	}
	if !forceRemote {
		if value, localErr := s.localSign(ctx, baseURL, method, path); localErr == nil {
			return value, "local", nil
		}
	}
	for metaAttempt := 0; metaAttempt < statsigMetaAttempts; metaAttempt++ {
		meta, metaErr := s.meta(ctx, baseURL, token, lease)
		if metaErr != nil {
			return "", "", metaErr
		}
		for signAttempt := 0; signAttempt < statsigSignAttempts; signAttempt++ {
			value, signErr := s.requestSignature(ctx, signerURL, method, path, meta.value)
			if signErr != nil {
				return "", "", fmt.Errorf("Statsig 签名失败: %w", signErr)
			}
			claimed, current := s.claimSignature(value, s.now().UTC(), meta.generation)
			if !current {
				break
			}
			if claimed {
				return value, meta.source, nil
			}
		}
		if s.isGenerationCurrent(meta.generation) {
			return "", "", fmt.Errorf("Statsig 签名服务连续返回重复值")
		}
	}
	return "", "", errStatsigMetaInvalidated
}

// Warm 在后台构建本地 signer；失败时仍预热远端 meta 作为业务兜底。
func (s *statsigSigner) Warm(ctx context.Context, baseURL, token string, lease *infraegress.Lease) (int, error) {
	if err := s.warmLocal(ctx, baseURL, token, lease); err == nil {
		return 1, nil
	}
	_, err := s.meta(ctx, baseURL, token, lease)
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (s *statsigSigner) meta(ctx context.Context, baseURL, token string, lease *infraegress.Lease) (statsigMetaResult, error) {
	key := statsigMetaKey(baseURL)
	for attempt := 0; attempt < statsigMetaAttempts; attempt++ {
		if value, ok := s.cached(key, s.now().UTC()); ok {
			return value, nil
		}
		value, err, _ := s.refreshes.Do(key, func() (any, error) {
			now := s.now().UTC()
			if cached, ok := s.cached(key, now); ok {
				return cached, nil
			}
			generation := s.currentGeneration()
			fresh, refreshErr := s.fetchMeta(ctx, baseURL, token, lease)
			if refreshErr != nil {
				return statsigMetaResult{}, refreshErr
			}
			if !s.storeIfGeneration(key, fresh, now.Add(statsigCacheTTL), now, generation) {
				return statsigMetaResult{}, errStatsigMetaInvalidated
			}
			return statsigMetaResult{value: fresh, source: "meta_refresh", generation: generation}, nil
		})
		if errors.Is(err, errStatsigMetaInvalidated) {
			continue
		}
		if err != nil {
			return statsigMetaResult{}, err
		}
		return value.(statsigMetaResult), nil
	}
	return statsigMetaResult{}, errStatsigMetaInvalidated
}

func (s *statsigSigner) Invalidate(baseURL string) {
	key := statsigMetaKey(baseURL)
	now := s.now().UTC()
	s.mu.Lock()
	if last, ok := s.invalidations[key]; ok && now.Before(last.Add(statsigInvalidateWindow)) {
		s.mu.Unlock()
		return
	}
	delete(s.entries, key)
	clear(s.locals)
	s.invalidations[key] = now
	s.generation++
	s.mu.Unlock()
}

func (s *statsigSigner) Clear() {
	s.mu.Lock()
	clear(s.entries)
	clear(s.invalidations)
	clear(s.locals)
	s.generation++
	s.mu.Unlock()
}

func (s *statsigSigner) cached(key string, now time.Time) (statsigMetaResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok || entry.value == "" || !now.Before(entry.expiresAt) {
		return statsigMetaResult{}, false
	}
	return statsigMetaResult{value: entry.value, source: "meta_cache", generation: s.generation}, true
}

func (s *statsigSigner) currentGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

func (s *statsigSigner) isGenerationCurrent(generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return generation == s.generation
}

func (s *statsigSigner) claimSignature(value string, now time.Time, generation uint64) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return false, false
	}
	for len(s.recentOrder) > 0 && !now.Before(s.recentOrder[0].seenAt.Add(statsigCacheTTL)) {
		entry := s.recentOrder[0]
		s.recentOrder = s.recentOrder[1:]
		if seenAt, ok := s.recentSignatures[entry.value]; ok && seenAt.Equal(entry.seenAt) {
			delete(s.recentSignatures, entry.value)
		}
	}
	if _, exists := s.recentSignatures[value]; exists {
		return false, true
	}
	if len(s.recentSignatures) >= statsigRecentMaxEntries {
		return false, true
	}
	s.recentSignatures[value] = now
	s.recentOrder = append(s.recentOrder, statsigSignatureEntry{value: value, seenAt: now})
	return true, true
}

func (s *statsigSigner) storeIfGeneration(key, value string, expiresAt, now time.Time, generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return false
	}
	for existingKey, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			delete(s.entries, existingKey)
		}
	}
	if len(s.entries) >= statsigMetaMaxEntries {
		oldestKey := ""
		var oldestExpiry time.Time
		for existingKey, entry := range s.entries {
			if oldestKey == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestKey, oldestExpiry = existingKey, entry.expiresAt
			}
		}
		delete(s.entries, oldestKey)
	}
	s.entries[key] = statsigCacheEntry{value: value, expiresAt: expiresAt}
	return true
}

func (s *statsigSigner) cachedLocal(key string, now time.Time) (statsigLocalChallenge, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.locals[key]
	if !ok || !now.Before(entry.expiresAt) {
		delete(s.locals, key)
		return statsigLocalChallenge{}, s.generation, false
	}
	return entry, s.generation, true
}

func (s *statsigSigner) storeLocalIfGeneration(key string, value statsigLocalChallenge, now time.Time, generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return false
	}
	for existingKey, entry := range s.locals {
		if !now.Before(entry.expiresAt) {
			delete(s.locals, existingKey)
		}
	}
	if len(s.locals) >= statsigLocalMaxEntries {
		oldestKey := ""
		var oldestExpiry time.Time
		for existingKey, entry := range s.locals {
			if oldestKey == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestKey, oldestExpiry = existingKey, entry.expiresAt
			}
		}
		delete(s.locals, oldestKey)
	}
	s.locals[key] = value
	return true
}

func (s *statsigSigner) dropLocalIfGeneration(key string, generation uint64) {
	s.mu.Lock()
	if generation == s.generation {
		delete(s.locals, key)
	}
	s.mu.Unlock()
}

func statsigMetaKey(baseURL string) string {
	return strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

func statsigSignaturePath(target string) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("解析 Statsig 目标地址: %w", err)
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return path, nil
}

func (s *statsigSigner) requestSignature(ctx context.Context, endpoint, method, path, metaContent string) (string, error) {
	if err := s.validateEndpoint(ctx, endpoint); err != nil {
		return "", err
	}
	payload, _ := json.Marshal(map[string]any{
		"method": strings.ToUpper(strings.TrimSpace(method)),
		"path":   path,
		"environment": map[string]string{
			"metaContent": metaContent,
		},
	})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, statsigResponseLimit+1))
	if err != nil {
		return "", err
	}
	if len(body) > statsigResponseLimit {
		return "", fmt.Errorf("签名响应超过安全上限")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("签名服务返回 %d", response.StatusCode)
	}
	var value struct {
		StatsigID string `json:"x-statsig-id"`
	}
	if json.Unmarshal(body, &value) != nil || !validStatsigID(value.StatsigID) {
		return "", fmt.Errorf("签名服务响应无效")
	}
	return value.StatsigID, nil
}

func validateStatsigSignerEndpoint(ctx context.Context, endpoint string) error {
	_ = ctx
	return signerurl.Validate(endpoint)
}

func fetchStatsigMetaContent(ctx context.Context, baseURL, token string, lease *infraegress.Lease) (string, error) {
	if lease == nil {
		return "", fmt.Errorf("Statsig 获取缺少出口租约")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/index", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Pragma", "no-cache")
	request.Header.Set("Sec-Fetch-Dest", "document")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Upgrade-Insecure-Requests", "1")
	request.Header.Set("User-Agent", lease.UserAgent)
	request.Header.Set("Cookie", infraegress.BuildSSOCookie(token, lease.CFCookies))
	response, err := lease.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Grok index 返回 %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, statsigMetaBodyLimit+1))
	if err != nil {
		return "", err
	}
	if len(body) > statsigMetaBodyLimit {
		return "", fmt.Errorf("Grok index 超过安全上限")
	}
	content, err := extractStatsigMetaContent(body)
	if err != nil {
		return "", err
	}
	return content, nil
}

func extractStatsigMetaContent(body []byte) (string, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return "", fmt.Errorf("Grok index 缺少 grok-site-verification")
			}
			return "", tokenizer.Err()
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttrs := tokenizer.TagName()
			if !strings.EqualFold(string(name), "meta") || !hasAttrs {
				continue
			}
			metaName := ""
			content := ""
			for {
				key, value, more := tokenizer.TagAttr()
				switch strings.ToLower(string(key)) {
				case "name":
					metaName = normalizeStatsigMetaName(string(value))
				case "content":
					content = strings.TrimSpace(string(value))
				}
				if !more {
					break
				}
			}
			if metaName == "grok-site-verification" && content != "" {
				return content, nil
			}
		}
	}
}

func normalizeStatsigMetaName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer("‐", "-", "‑", "-", "‒", "-", "–", "-", "—", "-", "―", "-").Replace(value)
}

func validStatsigID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	return err == nil && len(decoded) == 70
}

func (a *Adapter) applySignedStatsig(ctx context.Context, request *http.Request, token string, lease *infraegress.Lease, forceRemote bool) error {
	if request == nil {
		return fmt.Errorf("%w: request is nil", provider.ErrRequestSigning)
	}
	cfg := a.config()
	request.Header.Del("x-statsig-id")
	if cfg.StatsigMode == "manual" {
		if value := strings.TrimSpace(cfg.StatsigManualValue); validStatsigID(value) {
			request.Header.Set("x-statsig-id", value)
			return nil
		}
		return fmt.Errorf("%w: manual Statsig value is invalid", provider.ErrRequestSigning)
	}
	if a.statsig == nil {
		return fmt.Errorf("%w: Statsig signer is unavailable", provider.ErrRequestSigning)
	}
	value, source, err := a.statsig.Sign(ctx, cfg.BaseURL, cfg.StatsigSignerURL, token, lease, request.Method, request.URL.String(), forceRemote)
	if err == nil {
		request.Header.Set("x-statsig-id", value)
		if source == "meta_refresh" {
			a.log().Info("web_statsig_meta_refreshed", "method", request.Method, "path", request.URL.EscapedPath())
		}
		return nil
	}
	a.log().Warn("web_statsig_fetch_failed", "method", request.Method, "path", request.URL.EscapedPath(), "error", err)
	return fmt.Errorf("%w: %v", provider.ErrRequestSigning, err)
}

// WarmStatsig 只使用一个 Web 账号和一个出口租约预热共享 meta，不会逐账号访问上游。
func (a *Adapter) WarmStatsig(ctx context.Context, credential account.Credential) (int, error) {
	cfg := a.config()
	if cfg.StatsigMode == "manual" {
		if !validStatsigID(strings.TrimSpace(cfg.StatsigManualValue)) {
			return 0, fmt.Errorf("手动 Statsig 配置无效")
		}
		return 0, nil
	}
	if a.statsig == nil {
		return 0, fmt.Errorf("Statsig 签名器未初始化")
	}
	token, err := a.cipher.Decrypt(credential.EncryptedAccessToken)
	if err != nil {
		return 0, err
	}
	lease, err := a.egress.Acquire(ctx, domainegress.ScopeWeb, fmt.Sprintf("%d", credential.ID))
	if err != nil {
		return 0, err
	}
	defer lease.Release()
	return a.statsig.Warm(ctx, cfg.BaseURL, token, lease)
}

func (a *Adapter) invalidateSignedStatsig(method, target string) bool {
	cfg := a.config()
	if cfg.StatsigMode == "url" && a.statsig != nil {
		a.statsig.Invalidate(cfg.BaseURL)
		if parsed, err := url.Parse(target); err == nil {
			a.log().Info("web_statsig_invalidated", "method", method, "path", parsed.EscapedPath())
		}
		return true
	}
	return false
}
