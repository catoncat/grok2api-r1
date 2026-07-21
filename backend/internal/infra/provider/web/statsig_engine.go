package web

// Derived from image2api (MIT, commit a65f52b7).  The implementation is kept
// build-agnostic: discovery verifies runtime behaviour rather than build IDs.

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/dop251/goja"
	"golang.org/x/sync/singleflight"
)

//go:embed statsig_shim.js
var statsigShim string

const (
	statsigChunkLimit        = 256
	statsigChunkBytes        = 2 << 20
	statsigTotalBytes        = 32 << 20
	statsigWorkers           = 8
	statsigRuntimeMax        = 4
	statsigCurvesBytes       = 64 << 10
	statsigCurveGroupsMax    = 64
	statsigCurvesPerGroupMax = 64
	statsigLocalSignAttempts = 16
	statsigLocalRetryDelay   = time.Millisecond
	statsigDiscoveryTimeout  = 20 * time.Second
	statsigSignerSourceBytes = 256 << 10
	statsigJSBytesMax        = 1 << 20
	statsigBuildTTL          = statsigCacheTTL
	statsigBuildMaxEntries   = 16
)

var (
	statsigChunkPath    = regexp.MustCompile(`(?:/_next/)?static/chunks/[A-Za-z0-9_.~/-]+\.js`)
	statsigSourceMap    = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=\S*`)
	statsigBuildMu      sync.Mutex
	statsigBuilds       = make(map[string]statsigBuildEntry)
	statsigBuildRefresh singleflight.Group
)

type statsigLocalChallenge struct {
	seed      string
	curves    string
	engine    *statsigEngine
	expiresAt time.Time
}

type statsigEngine struct {
	source  string
	pool    chan *statsigRuntime
	mu      sync.Mutex
	created int
}

type statsigBuildEntry struct {
	engine    *statsigEngine
	expiresAt time.Time
	lastUsed  time.Time
}

type statsigRuntime struct {
	rt   *goja.Runtime
	sign goja.Callable
}

type statsigDiscoveryLimits struct {
	ChunkLimit int
	ChunkBytes int
	TotalBytes int
	Workers    int
	Timeout    time.Duration
}

var defaultStatsigDiscoveryLimits = statsigDiscoveryLimits{
	ChunkLimit: statsigChunkLimit,
	ChunkBytes: statsigChunkBytes,
	TotalBytes: statsigTotalBytes,
	Workers:    statsigWorkers,
	Timeout:    statsigDiscoveryTimeout,
}

func localStatsigKey(base string) string {
	return statsigMetaKey(base)
}

func (s *statsigSigner) localSign(ctx context.Context, base, method, path string) (string, uint64, error) {
	key := localStatsigKey(base)
	ch, generation, ok := s.cachedLocal(key, s.now())
	if !ok {
		return "", generation, errStatsigLocalCold
	}
	for attempt := 0; attempt < statsigLocalSignAttempts; attempt++ {
		id, err := ch.engine.signID(ctx, ch.seed, ch.curves, method, path)
		if err != nil {
			s.dropLocalIfGeneration(key, generation)
			return "", generation, err
		}
		claimed, current := s.claimSignature(id, s.now().UTC(), generation)
		if !current {
			return "", generation, errStatsigMetaInvalidated
		}
		if claimed {
			return id, generation, nil
		}
		if attempt+1 == statsigLocalSignAttempts {
			break
		}
		timer := time.NewTimer(statsigLocalRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", generation, ctx.Err()
		case <-timer.C:
		}
	}
	return "", generation, errors.New("local Statsig produced duplicate IDs")
}

func (s *statsigSigner) warmLocal(ctx context.Context, base, token string, lease *infraegress.Lease) error {
	if lease == nil {
		return errors.New("local Statsig needs egress lease")
	}
	key := localStatsigKey(base)
	for attempt := 0; attempt < statsigMetaAttempts; attempt++ {
		if _, _, ok := s.cachedLocal(key, s.now()); ok {
			return nil
		}
		generation := s.currentGeneration()
		flightKey := fmt.Sprintf("%s/%d", key, generation)
		_, err, _ := s.localRefreshes.Do(flightKey, func() (any, error) {
			if cached, cachedGeneration, ok := s.cachedLocal(key, s.now()); ok && cachedGeneration == generation {
				return cached, nil
			}
			fresh, fetchErr := s.fetchLocal(ctx, base, token, lease)
			if fetchErr != nil {
				return nil, fetchErr
			}
			now := s.now()
			fresh.expiresAt = now.Add(statsigCacheTTL)
			if !s.storeLocalIfGeneration(key, fresh, now, generation) {
				return nil, errStatsigMetaInvalidated
			}
			return fresh, nil
		})
		if errors.Is(err, errStatsigMetaInvalidated) {
			continue
		}
		return err
	}
	return errStatsigMetaInvalidated
}

func fetchStatsigLocalChallenge(ctx context.Context, base, token string, lease *infraegress.Lease) (statsigLocalChallenge, error) {
	home, err := fetchStatsigHome(ctx, base, token, lease)
	if err != nil {
		return statsigLocalChallenge{}, err
	}
	seed, err := extractStatsigMetaContent([]byte(home))
	if err != nil {
		return statsigLocalChallenge{}, err
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(seed, "="))
	if err != nil || len(decoded) != 48 {
		return statsigLocalChallenge{}, errors.New("invalid Statsig seed")
	}
	curves, err := parseStatsigCurves(home)
	if err != nil {
		return statsigLocalChallenge{}, err
	}
	curvesJSON, _ := json.Marshal(curves)
	build := statsigBuildKey(base, home)
	engine, ok := loadStatsigBuild(build, time.Now().UTC())
	if !ok {
		value, discoverErr, _ := statsigBuildRefresh.Do(build, func() (any, error) {
			if cached, cachedOK := loadStatsigBuild(build, time.Now().UTC()); cachedOK {
				return cached, nil
			}
			found, _, _, err := discoverStatsigEngine(ctx, base, home, seed, string(curvesJSON), decoded)
			if err != nil {
				return nil, err
			}
			storeStatsigBuild(build, found, time.Now().UTC())
			return found, nil
		})
		if discoverErr != nil {
			return statsigLocalChallenge{}, discoverErr
		}
		engine = value.(*statsigEngine)
	}
	return statsigLocalChallenge{seed: seed, curves: string(curvesJSON), engine: engine}, nil
}

func statsigBuildKey(base, home string) string {
	paths := statsigChunkPaths(home, nil)
	h := sha256.New()
	_, _ = io.WriteString(h, statsigMetaKey(base))
	_, _ = io.WriteString(h, "\n")
	for _, path := range paths {
		_, _ = io.WriteString(h, path)
		_, _ = io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func loadStatsigBuild(key string, now time.Time) (*statsigEngine, bool) {
	statsigBuildMu.Lock()
	defer statsigBuildMu.Unlock()
	entry, ok := statsigBuilds[key]
	if !ok || entry.engine == nil || !now.Before(entry.expiresAt) {
		delete(statsigBuilds, key)
		return nil, false
	}
	entry.lastUsed = now
	statsigBuilds[key] = entry
	return entry.engine, true
}

func storeStatsigBuild(key string, engine *statsigEngine, now time.Time) {
	if key == "" || engine == nil {
		return
	}
	statsigBuildMu.Lock()
	defer statsigBuildMu.Unlock()
	for existingKey, entry := range statsigBuilds {
		if entry.engine == nil || !now.Before(entry.expiresAt) {
			delete(statsigBuilds, existingKey)
		}
	}
	if _, exists := statsigBuilds[key]; !exists && len(statsigBuilds) >= statsigBuildMaxEntries {
		oldestKey := ""
		var oldestUsed time.Time
		for existingKey, entry := range statsigBuilds {
			if oldestKey == "" || entry.lastUsed.Before(oldestUsed) || (entry.lastUsed.Equal(oldestUsed) && existingKey < oldestKey) {
				oldestKey, oldestUsed = existingKey, entry.lastUsed
			}
		}
		delete(statsigBuilds, oldestKey)
	}
	statsigBuilds[key] = statsigBuildEntry{engine: engine, expiresAt: now.Add(statsigBuildTTL), lastUsed: now}
}

func fetchStatsigHome(ctx context.Context, base, token string, lease *infraegress.Lease) (string, error) {
	if lease == nil {
		return "", errors.New("Statsig index missing egress lease")
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(base, "/")+"/index", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", lease.UserAgent)
	req.Header.Set("Cookie", infraegress.BuildSSOCookie(token, lease.CFCookies))
	resp, err := lease.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Grok index returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, statsigMetaBodyLimit+1))
	if err != nil {
		return "", err
	}
	if len(body) > statsigMetaBodyLimit {
		return "", errors.New("Grok index exceeds limit")
	}
	return string(body), nil
}

func discoverStatsigEngine(ctx context.Context, base, home, seed, curves string, decoded []byte) (*statsigEngine, int, int, error) {
	return discoverStatsigEngineWithLimits(ctx, base, home, seed, curves, decoded, defaultStatsigDiscoveryLimits)
}

type statsigChunkResult struct {
	path  string
	body  []byte
	bytes int
	err   error
}

func discoverStatsigEngineWithLimits(ctx context.Context, base, home, seed, curves string, decoded []byte, limits statsigDiscoveryLimits) (*statsigEngine, int, int, error) {
	if limits.ChunkLimit <= 0 || limits.ChunkBytes <= 0 || limits.TotalBytes <= 0 || limits.Workers <= 0 || limits.Timeout <= 0 {
		return nil, 0, 0, errors.New("invalid Statsig discovery limits")
	}
	paths := statsigChunkPaths(home, nil)
	if len(paths) == 0 {
		return nil, 0, 0, errors.New("no Statsig chunks")
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	requestTimeout := min(12*time.Second, limits.Timeout)
	// Static chunks stay direct and credential-free: discovery must not spend
	// residential bytes or expose account/CF session state. Failure falls back
	// to the configured remote signer.
	transport := &http.Transport{Proxy: nil, IdleConnTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: requestTimeout, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	seen := make(map[string]bool, min(len(paths), limits.ChunkLimit))
	queue := make([]string, 0, min(len(paths), limits.ChunkLimit))
	for _, path := range paths {
		if seen[path] || len(seen) >= limits.ChunkLimit {
			continue
		}
		seen[path] = true
		queue = append(queue, path)
	}
	attempts, total := 0, 0
	for len(queue) > 0 && attempts < limits.ChunkLimit && total < limits.TotalBytes && discoveryCtx.Err() == nil {
		batchSize := min(limits.Workers, len(queue), limits.ChunkLimit-attempts, limits.TotalBytes-total)
		batch := append([]string(nil), queue[:batchSize]...)
		queue = queue[batchSize:]
		results := make([]statsigChunkResult, batchSize)
		remainingBytes := limits.TotalBytes - total
		var wait sync.WaitGroup
		for index, path := range batch {
			slotsLeft := batchSize - index
			budget := min(limits.ChunkBytes, remainingBytes-(slotsLeft-1))
			remainingBytes -= budget
			wait.Add(1)
			go func(index int, path string, budget int) {
				defer wait.Done()
				body, bytesRead, err := fetchStatsigChunkMeasured(discoveryCtx, client, base, path, budget)
				results[index] = statsigChunkResult{path: path, body: body, bytes: bytesRead, err: err}
			}(index, path, budget)
		}
		attempts += batchSize
		wait.Wait()
		for _, result := range results {
			total += result.bytes
			if result.err != nil {
				continue
			}
			if discoveryCtx.Err() != nil {
				break
			}
			if engine, ok := verifyStatsigChunk(discoveryCtx, string(result.body), seed, curves, decoded); ok {
				cancel()
				return engine, attempts, total, nil
			}
			for _, next := range statsigChunkPaths(string(result.body), seen) {
				if seen[next] || len(seen) >= limits.ChunkLimit {
					continue
				}
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	if err := discoveryCtx.Err(); err != nil {
		return nil, attempts, total, fmt.Errorf("Statsig discovery stopped after %d attempts/%d bytes: %w", attempts, total, err)
	}
	return nil, attempts, total, fmt.Errorf("Statsig signer not found after %d attempts/%d bytes", attempts, total)
}

func statsigChunkPaths(source string, seen map[string]bool) []string {
	values := statsigChunkPath.FindAllString(source, -1)
	out := make([]string, 0, len(values))
	added := make(map[string]bool, len(values))
	for _, value := range values {
		value = "/_next/" + strings.TrimPrefix(value, "/_next/")
		if !added[value] && (seen == nil || !seen[value]) {
			added[value] = true
			out = append(out, value)
		}
	}
	return out
}

type statsigCurve struct {
	Color  []int `json:"color"`
	Deg    int   `json:"deg"`
	Bezier []int `json:"bezier"`
}

// parseStatsigCurves accepts both plain JSON and the JSON-string escaping used
// by React Server Component flight payloads. Only the bounded curve schema is
// allowed through to the JavaScript runtime.
func parseStatsigCurves(home string) (json.RawMessage, error) {
	const directPrefix = `[[{"color"`
	const escapedPrefix = `[[{\"color\"`
	directStart := strings.Index(home, directPrefix)
	escapedStart := strings.Index(home, escapedPrefix)
	start, escapedMode := directStart, false
	if start < 0 || (escapedStart >= 0 && escapedStart < start) {
		start, escapedMode = escapedStart, true
	}
	if start < 0 {
		return nil, errors.New("Statsig curves not found")
	}
	raw, err := extractStatsigCurvesValue(home[start:], escapedMode)
	if err != nil {
		return nil, err
	}
	return validateStatsigCurves(raw)
}

func extractStatsigCurvesValue(source string, escapedMode bool) ([]byte, error) {
	limit := len(source)
	if limit > statsigCurvesBytes+1 {
		limit = statsigCurvesBytes + 1
	}
	depth, quoted, escaped := 0, false, false
	for i := 0; i < limit; i++ {
		c := source[i]
		if !escapedMode {
			if quoted {
				if escaped {
					escaped = false
				} else if c == '\\' {
					escaped = true
				} else if c == '"' {
					quoted = false
				}
				continue
			}
			if c == '"' {
				quoted = true
				continue
			}
		}
		if c == '[' {
			depth++
		} else if c == ']' {
			depth--
			if depth == 0 {
				if i+1 > statsigCurvesBytes {
					return nil, errors.New("Statsig curves exceed limit")
				}
				rawText := source[:i+1]
				if escapedMode {
					encoded := make([]byte, len(rawText)+2)
					encoded[0], encoded[len(encoded)-1] = '"', '"'
					copy(encoded[1:], rawText)
					if err := json.Unmarshal(encoded, &rawText); err != nil {
						return nil, errors.New("invalid escaped Statsig curves")
					}
				}
				return []byte(rawText), nil
			}
		}
	}
	if len(source) > statsigCurvesBytes {
		return nil, errors.New("Statsig curves exceed limit")
	}
	return nil, errors.New("Statsig curves incomplete")
}

func validateStatsigCurves(raw []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var groups [][]statsigCurve
	if err := decoder.Decode(&groups); err != nil {
		return nil, errors.New("invalid Statsig curves")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid trailing Statsig curves data")
	}
	if len(groups) == 0 || len(groups) > statsigCurveGroupsMax {
		return nil, errors.New("invalid Statsig curve group count")
	}
	for _, group := range groups {
		if len(group) == 0 || len(group) > statsigCurvesPerGroupMax {
			return nil, errors.New("invalid Statsig curves per group")
		}
		for _, curve := range group {
			if len(curve.Color) != 6 || len(curve.Bezier) != 4 {
				return nil, errors.New("invalid Statsig curve shape")
			}
		}
	}
	canonical, err := json.Marshal(groups)
	if err != nil {
		return nil, errors.New("invalid Statsig curves")
	}
	return json.RawMessage(canonical), nil
}

func fetchStatsigChunk(ctx context.Context, client *http.Client, base, path string, limit int) ([]byte, error) {
	body, _, err := fetchStatsigChunkMeasured(ctx, client, base, path, limit)
	return body, err
}

func fetchStatsigChunkMeasured(ctx context.Context, client *http.Client, base, path string, limit int) ([]byte, int, error) {
	origin, err := url.Parse(base)
	if err != nil {
		return nil, 0, err
	}
	if origin.Scheme != "https" && origin.Scheme != "http" {
		return nil, 0, errors.New("invalid chunk origin")
	}
	if !strings.HasPrefix(path, "/_next/static/chunks/") || strings.Contains(path, "..") {
		return nil, 0, errors.New("chunk path outside allowlist")
	}
	u := origin.ResolveReference(&url.URL{Path: path})
	if u.Scheme != origin.Scheme || u.Host != origin.Host || u.User != nil || u.RawQuery != "" || !strings.HasPrefix(u.EscapedPath(), "/_next/static/chunks/") {
		return nil, 0, errors.New("cross-origin chunk")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	// Deliberately no Cookie, Authorization, or Cloudflare session headers.
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > int64(limit) {
		return nil, 0, errors.New("chunk exceeds limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	if err != nil {
		return nil, len(body), err
	}
	bytesRead := len(body)
	if resp.StatusCode != http.StatusOK {
		return nil, bytesRead, fmt.Errorf("chunk returned %d", resp.StatusCode)
	}
	return body, bytesRead, nil
}

func verifyStatsigChunk(ctx context.Context, source, seed, curves string, decoded []byte) (*statsigEngine, bool) {
	if len(source) > statsigSignerSourceBytes || !strings.Contains(source, "String.fromCharCode") || !strings.Contains(source, "charCodeAt") {
		return nil, false
	}
	engine := &statsigEngine{source: statsigSourceMap.ReplaceAllString(source, ""), pool: make(chan *statsigRuntime, statsigRuntimeMax)}
	id, err := engine.signID(ctx, seed, curves, http.MethodPost, "/rest/app-chat/conversations/new")
	return engine, err == nil && validStatsigID(id) && statsigEmbedsSeed(id, decoded)
}

func statsigEmbedsSeed(id string, seed []byte) bool {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(id, "="))
	if err != nil || len(raw) != 70 || len(raw) < len(seed)+1 {
		return false
	}
	for i := range seed {
		if raw[i+1]^raw[0] != seed[i] {
			return false
		}
	}
	return true
}

func (e *statsigEngine) signID(ctx context.Context, seed, curves, method, path string) (id string, err error) {
	var rt *statsigRuntime
	good := false
	defer func() {
		if recovered := recover(); recovered != nil {
			id = ""
			err = fmt.Errorf("Statsig runtime panic: %v", recovered)
			good = false
		}
		if rt == nil {
			return
		}
		if good {
			e.pool <- rt
			return
		}
		e.mu.Lock()
		e.created--
		e.mu.Unlock()
	}()
	rt, err = e.borrow(ctx)
	if err != nil {
		return "", err
	}
	if err = rt.rt.Set("__SEED", seed); err == nil {
		err = rt.rt.Set("__CURVES", curves)
	}
	if err == nil {
		err = rt.rt.Set("__METHOD", method)
	}
	if err == nil {
		err = rt.rt.Set("__PATH", path)
	}
	if err != nil {
		return "", err
	}
	limit, err := statsigExecutionLimit(ctx, 3*time.Second)
	if err != nil {
		return "", err
	}
	timer, interruptDone := statsigInterruptAfter(rt.rt, limit, "statsig deadline")
	defer stopStatsigInterrupt(timer, interruptDone, rt.rt)
	if _, err = rt.sign(goja.Undefined()); err != nil {
		return "", err
	}
	if v := rt.rt.Get("__grokErr"); v != nil && !goja.IsNull(v) && !goja.IsUndefined(v) {
		return "", errors.New("Statsig runtime rejected signature")
	}
	value := rt.rt.Get("__grokResult")
	if value == nil || goja.IsNull(value) || goja.IsUndefined(value) {
		return "", errors.New("Statsig runtime did not settle")
	}
	id = value.String()
	if !validStatsigID(id) {
		return "", errors.New("Statsig runtime produced invalid ID")
	}
	good = true
	return id, nil
}

func (e *statsigEngine) borrow(ctx context.Context) (*statsigRuntime, error) {
	select {
	case rt := <-e.pool:
		return rt, nil
	default:
	}
	e.mu.Lock()
	if e.created < statsigRuntimeMax {
		e.created++
		e.mu.Unlock()
		rt, err := newStatsigRuntimeContext(ctx, e.source)
		if err != nil {
			e.mu.Lock()
			e.created--
			e.mu.Unlock()
		}
		return rt, err
	}
	e.mu.Unlock()
	select {
	case rt := <-e.pool:
		return rt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newStatsigRuntime(source string) (*statsigRuntime, error) {
	return newStatsigRuntimeContext(context.Background(), source)
}

func newStatsigRuntimeContext(ctx context.Context, source string) (runtime *statsigRuntime, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			runtime = nil
			err = fmt.Errorf("Statsig runtime bootstrap panic: %v", recovered)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rt := goja.New()
	limit, err := statsigExecutionLimit(ctx, 3*time.Second)
	if err != nil {
		return nil, err
	}
	timer, interruptDone := statsigInterruptAfter(rt, limit, "statsig bootstrap deadline")
	defer stopStatsigInterrupt(timer, interruptDone, rt)
	if err := rt.Set("__goSha256", func(call goja.FunctionCall) goja.Value {
		data, byteErr := statsigJSBytes(rt, call.Argument(0))
		if byteErr != nil {
			panic(rt.NewTypeError(byteErr.Error()))
		}
		sum := sha256.Sum256(data)
		return rt.ToValue(rt.NewArrayBuffer(sum[:]))
	}); err != nil {
		return nil, err
	}
	if _, err := rt.RunString(statsigShim); err != nil {
		return nil, err
	}
	if _, err := rt.RunString(source); err != nil {
		return nil, err
	}
	if _, err := rt.RunString("__grokBootstrap()"); err != nil {
		return nil, err
	}
	sign, ok := goja.AssertFunction(rt.Get("__grokSignInto"))
	if !ok {
		return nil, errors.New("Statsig signer entrypoint absent")
	}
	return &statsigRuntime{rt: rt, sign: sign}, nil
}

func statsigExecutionLimit(ctx context.Context, maximum time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		if remaining < maximum {
			maximum = remaining
		}
	}
	return maximum, nil
}

func statsigInterruptAfter(rt *goja.Runtime, delay time.Duration, reason string) (*time.Timer, <-chan struct{}) {
	done := make(chan struct{})
	timer := time.AfterFunc(delay, func() {
		defer close(done)
		rt.Interrupt(reason)
	})
	return timer, done
}

func stopStatsigInterrupt(timer *time.Timer, done <-chan struct{}, rt *goja.Runtime) {
	if !timer.Stop() {
		<-done
	}
	rt.ClearInterrupt()
}

func statsigJSBytes(rt *goja.Runtime, value goja.Value) ([]byte, error) {
	if buffer, ok := value.Export().(goja.ArrayBuffer); ok {
		if len(buffer.Bytes()) > statsigJSBytesMax {
			return nil, errors.New("Statsig byte source exceeds limit")
		}
		return buffer.Bytes(), nil
	}
	o := value.ToObject(rt)
	length := o.Get("length").ToInteger()
	if length < 0 || length > statsigJSBytesMax {
		return nil, errors.New("Statsig byte source exceeds limit")
	}
	n := int(length)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(o.Get(strconv.Itoa(i)).ToInteger())
	}
	return out, nil
}
