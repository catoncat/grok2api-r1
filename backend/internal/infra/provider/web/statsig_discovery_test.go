package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatsigDiscoveryFollowsChunkGraphWithinHardBudget(t *testing.T) {
	seed, decoded := testStatsigSeed()
	signerID := testStatsigIDWithSeed(decoded, 71)
	var refCalls, missingCalls, signerCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/_next/static/chunks/ref.js":
			refCalls.Add(1)
			_, _ = w.Write([]byte(`static/chunks/signer.js`))
		case "/_next/static/chunks/signer.js":
			signerCalls.Add(1)
			_, _ = w.Write([]byte(testStatsigSignerChunk(signerID)))
		default:
			missingCalls.Add(1)
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	home := strings.Repeat(`/_next/static/chunks/missing.js `, 3) + `/_next/static/chunks/ref.js`
	limits := statsigDiscoveryLimits{ChunkLimit: 4, ChunkBytes: 8 << 10, TotalBytes: 16 << 10, Workers: 2, Timeout: time.Second}
	engine, attempts, bytesRead, err := discoverStatsigEngineWithLimits(context.Background(), server.URL, home, seed, `[]`, decoded, limits)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || bytesRead <= 0 || bytesRead > limits.TotalBytes {
		t.Fatalf("attempts=%d bytes=%d", attempts, bytesRead)
	}
	if refCalls.Load() != 1 || missingCalls.Load() != 1 || signerCalls.Load() != 1 {
		t.Fatalf("ref=%d missing=%d signer=%d", refCalls.Load(), missingCalls.Load(), signerCalls.Load())
	}
	id, err := engine.signID(context.Background(), seed, `[]`, http.MethodPost, "/rest/test")
	if err != nil || id != signerID {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestStatsigDiscoveryChoosesFirstValidCandidateDeterministically(t *testing.T) {
	seed, decoded := testStatsigSeed()
	firstID := testStatsigIDWithSeed(decoded, 72)
	secondID := testStatsigIDWithSeed(decoded, 73)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/_next/static/chunks/first.js":
			time.Sleep(40 * time.Millisecond)
			_, _ = w.Write([]byte(testStatsigSignerChunk(firstID)))
		case "/_next/static/chunks/second.js":
			_, _ = w.Write([]byte(testStatsigSignerChunk(secondID)))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	home := `/_next/static/chunks/first.js /_next/static/chunks/second.js`
	limits := statsigDiscoveryLimits{ChunkLimit: 2, ChunkBytes: 8 << 10, TotalBytes: 16 << 10, Workers: 2, Timeout: time.Second}
	engine, attempts, _, err := discoverStatsigEngineWithLimits(context.Background(), server.URL, home, seed, `[]`, decoded, limits)
	if err != nil || attempts != 2 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
	id, err := engine.signID(context.Background(), seed, `[]`, http.MethodPost, "/rest/test")
	if err != nil || id != firstID {
		t.Fatalf("selected first=%t id=%q err=%v", id == firstID, id, err)
	}
}

func TestStatsigDiscoveryEnforcesDeadlineAndByteBudget(t *testing.T) {
	seed, decoded := testStatsigSeed()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "slow") {
			time.Sleep(200 * time.Millisecond)
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 32)))
	}))
	defer server.Close()

	t.Run("bytes", func(t *testing.T) {
		home := `/_next/static/chunks/a.js /_next/static/chunks/b.js`
		limits := statsigDiscoveryLimits{ChunkLimit: 2, ChunkBytes: 10, TotalBytes: 15, Workers: 2, Timeout: time.Second}
		_, attempts, bytesRead, err := discoverStatsigEngineWithLimits(context.Background(), server.URL, home, seed, `[]`, decoded, limits)
		if err == nil || attempts != 2 || bytesRead > limits.TotalBytes {
			t.Fatalf("attempts=%d bytes=%d err=%v", attempts, bytesRead, err)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		start := time.Now()
		home := `/_next/static/chunks/slow-a.js /_next/static/chunks/slow-b.js`
		limits := statsigDiscoveryLimits{ChunkLimit: 2, ChunkBytes: 64, TotalBytes: 128, Workers: 2, Timeout: 30 * time.Millisecond}
		_, attempts, _, err := discoverStatsigEngineWithLimits(context.Background(), server.URL, home, seed, `[]`, decoded, limits)
		if err == nil || attempts != 2 || time.Since(start) > 150*time.Millisecond {
			t.Fatalf("attempts=%d elapsed=%s err=%v", attempts, time.Since(start), err)
		}
	})
}

func TestStatsigDiscoveryDeadlineIncludesCandidateVerification(t *testing.T) {
	seed, decoded := testStatsigSeed()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`String.fromCharCode; "".charCodeAt; for (;;) {}`))
	}))
	defer server.Close()

	home := `/_next/static/chunks/a.js /_next/static/chunks/b.js`
	limits := statsigDiscoveryLimits{ChunkLimit: 2, ChunkBytes: 8 << 10, TotalBytes: 16 << 10, Workers: 2, Timeout: 50 * time.Millisecond}
	started := time.Now()
	_, attempts, _, err := discoverStatsigEngineWithLimits(context.Background(), server.URL, home, seed, `[]`, decoded, limits)
	elapsed := time.Since(started)
	if err == nil || attempts != 2 || elapsed > 500*time.Millisecond {
		t.Fatalf("attempts=%d elapsed=%s err=%v", attempts, elapsed, err)
	}
}

func TestNewStatsigRuntimeContainsInvalidNativeLengthPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("native panic escaped runtime bootstrap: %v", recovered)
		}
	}()
	_, err := newStatsigRuntime(`__goSha256({length: -1});`)
	if err == nil {
		t.Fatal("runtime accepted a throwing native byte source")
	}
}

func TestNewStatsigRuntimeRejectsOversizedNativeByteSource(t *testing.T) {
	_, err := newStatsigRuntime(`__goSha256({length: 1048577});`)
	if err == nil || !strings.Contains(err.Error(), "byte source exceeds limit") {
		t.Fatalf("oversized byte source err=%v", err)
	}
}

func TestStatsigBuildCacheIsOriginScopedBoundedAndExpiring(t *testing.T) {
	statsigBuildMu.Lock()
	original := statsigBuilds
	statsigBuilds = make(map[string]statsigBuildEntry)
	statsigBuildMu.Unlock()
	defer func() {
		statsigBuildMu.Lock()
		statsigBuilds = original
		statsigBuildMu.Unlock()
	}()

	home := `/_next/static/chunks/a.js`
	if statsigBuildKey("https://grok.example", home) == statsigBuildKey("https://other.example", home) {
		t.Fatal("build key ignored origin")
	}
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	firstKey := ""
	for index := range statsigBuildMaxEntries + 1 {
		key := fmt.Sprintf("build-%d", index)
		if index == 0 {
			firstKey = key
		}
		storeStatsigBuild(key, &statsigEngine{}, now.Add(time.Duration(index)*time.Second))
	}
	statsigBuildMu.Lock()
	size := len(statsigBuilds)
	_, firstStillPresent := statsigBuilds[firstKey]
	statsigBuildMu.Unlock()
	if size != statsigBuildMaxEntries || firstStillPresent {
		t.Fatalf("cache size=%d first_present=%t", size, firstStillPresent)
	}

	key := "expiring"
	storeStatsigBuild(key, &statsigEngine{}, now)
	if _, ok := loadStatsigBuild(key, now.Add(statsigBuildTTL)); ok {
		t.Fatal("expired build remained cached")
	}
}

func testStatsigSeed() (string, []byte) {
	decoded := make([]byte, 48)
	for index := range decoded {
		decoded[index] = byte(index + 1)
	}
	return base64.RawStdEncoding.EncodeToString(decoded), decoded
}

func testStatsigIDWithSeed(seed []byte, marker byte) string {
	raw := make([]byte, 70)
	raw[0] = marker
	for index := range seed {
		raw[index+1] = seed[index] ^ marker
	}
	raw[len(raw)-1] = marker
	return base64.RawStdEncoding.EncodeToString(raw)
}

func testStatsigSignerChunk(id string) string {
	return fmt.Sprintf(`String.fromCharCode; "".charCodeAt; TURBOPACK.push([[],{},function(c){c.s("default",function(){return function(){return Promise.resolve(%q)}})}]);`, id)
}
