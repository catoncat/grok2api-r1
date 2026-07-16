package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
)

func TestStatsigColdRequestFallsBackWithoutLocalDiscovery(t *testing.T) {
	var localFetches, remoteCalls atomic.Int64
	signer := newStatsigSigner()
	signer.fetchLocal = func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error) {
		localFetches.Add(1)
		return statsigLocalChallenge{}, fmt.Errorf("local discovery should not run on request path")
	}
	configureStatsigRemoteTestSigner(t, signer, testStatsigID(51), &remoteCalls)

	value, source, err := signer.Sign(context.Background(), "https://grok.example", "https://signer.example/sign", "token", &infraegress.Lease{NodeID: 1}, http.MethodPost, "https://grok.example/rest/test")
	if err != nil || value != testStatsigID(51) || source == "local" {
		t.Fatalf("value=%q source=%q err=%v", value, source, err)
	}
	if localFetches.Load() != 0 || remoteCalls.Load() != 1 {
		t.Fatalf("local fetches=%d remote calls=%d", localFetches.Load(), remoteCalls.Load())
	}
}

func TestStatsigWarmChallengeIsSharedAcrossEgressLeases(t *testing.T) {
	localID := testStatsigID(52)
	var localFetches, remoteCalls atomic.Int64
	signer := newStatsigSigner()
	signer.fetchLocal = func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error) {
		localFetches.Add(1)
		return statsigLocalChallenge{seed: "seed", curves: "[]", engine: testStatsigLocalEngine(localID)}, nil
	}
	configureStatsigRemoteTestSigner(t, signer, testStatsigID(53), &remoteCalls)

	if warmed, err := signer.Warm(context.Background(), "https://grok.example", "token", &infraegress.Lease{NodeID: 1, UserAgent: "ua-1"}); err != nil || warmed != 1 {
		t.Fatalf("warmed=%d err=%v", warmed, err)
	}
	value, source, err := signer.Sign(context.Background(), "https://grok.example", "https://signer.example/sign", "token", &infraegress.Lease{NodeID: 2, UserAgent: "ua-2"}, http.MethodPost, "https://grok.example/rest/test")
	if err != nil || value != localID || source != "local" {
		t.Fatalf("value=%q source=%q err=%v", value, source, err)
	}
	if localFetches.Load() != 1 || remoteCalls.Load() != 0 {
		t.Fatalf("local fetches=%d remote calls=%d", localFetches.Load(), remoteCalls.Load())
	}
}

func TestStatsigInvalidationWinsAgainstInFlightLocalWarm(t *testing.T) {
	for _, invalidate := range []struct {
		name string
		run  func(*statsigSigner)
	}{
		{name: "invalidate", run: func(s *statsigSigner) { s.Invalidate("https://grok.example") }},
		{name: "clear", run: func(s *statsigSigner) { s.Clear() }},
	} {
		t.Run(invalidate.name, func(t *testing.T) {
			var fetches atomic.Int64
			started := make(chan struct{})
			release := make(chan struct{})
			signer := newStatsigSigner()
			signer.fetchLocal = func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error) {
				sequence := fetches.Add(1)
				if sequence == 1 {
					close(started)
					<-release
					return statsigLocalChallenge{seed: "stale", curves: "[]", engine: testStatsigLocalEngine(testStatsigID(54))}, nil
				}
				return statsigLocalChallenge{seed: "fresh", curves: "[]", engine: testStatsigLocalEngine(testStatsigID(55))}, nil
			}
			configureStatsigRemoteTestSigner(t, signer, testStatsigID(56), nil)

			type warmResult struct {
				warmed int
				err    error
			}
			result := make(chan warmResult, 1)
			go func() {
				warmed, err := signer.Warm(context.Background(), "https://grok.example", "token", &infraegress.Lease{NodeID: 1})
				result <- warmResult{warmed: warmed, err: err}
			}()
			<-started
			invalidate.run(signer)
			close(release)
			got := <-result
			if got.err != nil || got.warmed != 1 {
				t.Fatalf("warmed=%d err=%v", got.warmed, got.err)
			}
			value, source, err := signer.Sign(context.Background(), "https://grok.example", "https://signer.example/sign", "token", &infraegress.Lease{NodeID: 1}, http.MethodPost, "https://grok.example/rest/test")
			if err != nil || value != testStatsigID(55) || source != "local" || fetches.Load() != 2 {
				t.Fatalf("value=%q source=%q fetches=%d err=%v", value, source, fetches.Load(), err)
			}
		})
	}
}

func TestStatsigLocalDuplicateIsNotReturned(t *testing.T) {
	first := testStatsigID(57)
	second := testStatsigID(58)
	signer := newStatsigSigner()
	signer.fetchLocal = func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error) {
		return statsigLocalChallenge{seed: "seed", curves: "[]", engine: testStatsigLocalEngine(first, first, first, second)}, nil
	}
	configureStatsigRemoteTestSigner(t, signer, testStatsigID(59), nil)
	if warmed, err := signer.Warm(context.Background(), "https://grok.example", "token", &infraegress.Lease{NodeID: 1}); err != nil || warmed != 1 {
		t.Fatalf("warmed=%d err=%v", warmed, err)
	}
	value1, source1, err1 := signer.Sign(context.Background(), "https://grok.example", "https://signer.example/sign", "token", &infraegress.Lease{NodeID: 1}, http.MethodPost, "https://grok.example/rest/test")
	value2, source2, err2 := signer.Sign(context.Background(), "https://grok.example", "https://signer.example/sign", "token", &infraegress.Lease{NodeID: 1}, http.MethodPost, "https://grok.example/rest/test")
	if err1 != nil || err2 != nil || source1 != "local" || source2 != "local" || value1 != first || value2 != second {
		t.Fatalf("first=%q/%q/%v second=%q/%q/%v", value1, source1, err1, value2, source2, err2)
	}
}

func TestStatsigRecentSignatureCapacityFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	signer := newStatsigSigner()
	generation := signer.currentGeneration()
	for sequence := range statsigRecentMaxEntries {
		claimed, current := signer.claimSignature(fmt.Sprintf("signature-%d", sequence), now, generation)
		if !claimed || !current {
			t.Fatalf("signature %d claimed=%t current=%t", sequence, claimed, current)
		}
	}
	if claimed, current := signer.claimSignature("over-capacity", now, generation); claimed || !current {
		t.Fatalf("over-capacity claimed=%t current=%t", claimed, current)
	}
	now = now.Add(statsigSignatureReplayTTL)
	if claimed, current := signer.claimSignature("after-expiry", now, generation); !claimed || !current {
		t.Fatalf("after-expiry claimed=%t current=%t", claimed, current)
	}
}

func TestStatsigGenerationScopedInvalidationRejectsLateCode7(t *testing.T) {
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	signer := newStatsigSigner()
	signer.now = func() time.Time { return now }
	key := localStatsigKey("https://grok.example")
	firstGeneration := signer.currentGeneration()
	first := statsigLocalChallenge{seed: "first", engine: testStatsigLocalEngine(testStatsigID(61)), expiresAt: now.Add(time.Hour)}
	if !signer.storeLocalIfGeneration(key, first, now, firstGeneration) {
		t.Fatal("first challenge was not stored")
	}
	if !signer.InvalidateGeneration("https://grok.example", firstGeneration) {
		t.Fatal("current generation was not invalidated")
	}

	secondGeneration := signer.currentGeneration()
	second := statsigLocalChallenge{seed: "second", engine: testStatsigLocalEngine(testStatsigID(62)), expiresAt: now.Add(time.Hour)}
	if !signer.storeLocalIfGeneration(key, second, now, secondGeneration) {
		t.Fatal("second challenge was not stored")
	}
	if signer.InvalidateGeneration("https://grok.example", firstGeneration) {
		t.Fatal("late code 7 invalidated a newer generation")
	}
	if cached, generation, ok := signer.cachedLocal(key, now); !ok || generation != secondGeneration || cached.seed != "second" {
		t.Fatalf("new challenge survived=%t generation=%d seed=%q", ok, generation, cached.seed)
	}
	if !signer.InvalidateGeneration("https://grok.example", secondGeneration) {
		t.Fatal("current code 7 was suppressed by invalidation window")
	}
	if _, _, ok := signer.cachedLocal(key, now); ok {
		t.Fatal("current rejected challenge remained cached")
	}
}

func TestApplySignedStatsigTagsRequestGeneration(t *testing.T) {
	signer := newStatsigSigner()
	signer.fetchLocal = func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error) {
		return statsigLocalChallenge{seed: "seed", curves: "[]", engine: testStatsigLocalEngine(testStatsigID(63))}, nil
	}
	if warmed, err := signer.Warm(context.Background(), "https://grok.example", "token", &infraegress.Lease{NodeID: 1}); err != nil || warmed != 1 {
		t.Fatalf("warmed=%d err=%v", warmed, err)
	}
	adapter := &Adapter{cfg: Config{BaseURL: "https://grok.example", StatsigMode: "url", StatsigSignerURL: "https://signer.example/sign"}, statsig: signer}
	request, err := http.NewRequest(http.MethodPost, "https://grok.example/rest/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.applySignedStatsig(context.Background(), request, "token", &infraegress.Lease{NodeID: 2}, false); err != nil {
		t.Fatal(err)
	}
	generation := statsigGenerationFromResponse(&http.Response{Request: request})
	if generation == 0 || generation != signer.currentGeneration() {
		t.Fatalf("request generation=%d current=%d", generation, signer.currentGeneration())
	}
}

func testStatsigLocalEngine(values ...string) *statsigEngine {
	encoded, _ := json.Marshal(values)
	source := `var __testValues=` + string(encoded) + `;var __testIndex=0;TURBOPACK.push([[],{},function(c){c.s("default",function(){return function(){var i=Math.min(__testIndex++,__testValues.length-1);return Promise.resolve(__testValues[i])}})}]);`
	return &statsigEngine{source: source, pool: make(chan *statsigRuntime, statsigRuntimeMax)}
}

func configureStatsigRemoteTestSigner(t *testing.T, signer *statsigSigner, value string, calls *atomic.Int64) {
	t.Helper()
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) { return "meta", nil }
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls != nil {
			calls.Add(1)
		}
		body, _ := json.Marshal(map[string]string{"x-statsig-id": value})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
}
