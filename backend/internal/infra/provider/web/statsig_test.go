package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func testStatsigID(sequence int) string {
	raw := make([]byte, 70)
	raw[0] = byte(sequence)
	return base64.RawStdEncoding.EncodeToString(raw)
}

func TestExtractStatsigMetaContentAcceptsCurrentMetaName(t *testing.T) {
	for _, name := range []string{"grok-site―verification", "grok-site-verification"} {
		body := []byte(`<html><head><meta name="` + name + `" content="meta-value"/></head></html>`)
		value, err := extractStatsigMetaContent(body)
		if err != nil || value != "meta-value" {
			t.Fatalf("name=%q value=%q err=%v", name, value, err)
		}
	}
}

func TestStatsigLocalFirstAndForcedRemoteFallback(t *testing.T) {
	localID := testStatsigID(11)
	remoteID := testStatsigID(12)
	engine := &statsigEngine{source: `TURBOPACK.push([[],{},function(c){c.s("default",function(){return function(){return Promise.resolve("` + localID + `")}})}]);`, pool: make(chan *statsigRuntime, statsigRuntimeMax)}
	signer := newStatsigSigner()
	signer.fetchLocal = func(context.Context, string, string, *infraegress.Lease) (statsigLocalChallenge, error) {
		return statsigLocalChallenge{seed: "seed", curves: "[]", engine: engine}, nil
	}
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) { return "meta", nil }
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	var remoteCalls atomic.Int64
	signer.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		remoteCalls.Add(1)
		body, _ := json.Marshal(map[string]string{"x-statsig-id": remoteID})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	lease := &infraegress.Lease{NodeID: 1, UserAgent: "ua"}
	if warmed, err := signer.Warm(context.Background(), "https://grok.example", "token", lease); err != nil || warmed != 1 {
		t.Fatalf("warmed=%d err=%v", warmed, err)
	}
	value, source, err := signer.Sign(context.Background(), "https://grok.example", "https://signer.example", "token", lease, http.MethodPost, "https://grok.example/rest/test")
	if err != nil || value != localID || source != "local" || remoteCalls.Load() != 0 {
		t.Fatalf("local value=%q source=%q remote=%d err=%v", value, source, remoteCalls.Load(), err)
	}
	value, source, err = signer.Sign(context.Background(), "https://grok.example", "https://signer.example", "token", lease, http.MethodPost, "https://grok.example/rest/test", true)
	if err != nil || value != remoteID || source == "local" || remoteCalls.Load() != 1 {
		t.Fatalf("remote value=%q source=%q remote=%d err=%v", value, source, remoteCalls.Load(), err)
	}
}

func TestStatsigChunkBoundaryRejectsCredentialsAndCrossOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" || request.Header.Get("CF-Connecting-IP") != "" {
			t.Fatalf("direct chunk leaked credentials: %#v", request.Header)
		}
		_, _ = w.Write([]byte("chunk"))
	}))
	defer server.Close()
	client := &http.Client{}
	if _, err := fetchStatsigChunk(context.Background(), client, server.URL, "/_next/static/chunks/a.js", 32); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchStatsigChunk(context.Background(), client, server.URL, "https://elsewhere.example/_next/static/chunks/a.js", 32); err == nil {
		t.Fatal("cross-origin chunk accepted")
	}
	if _, err := fetchStatsigChunk(context.Background(), client, server.URL, "/api/private", 32); err == nil {
		t.Fatal("non-chunk path accepted")
	}
}

func TestStatsigRuntimePoolIsBounded(t *testing.T) {
	value := testStatsigID(21)
	engine := &statsigEngine{source: `TURBOPACK.push([[],{},function(c){c.s("default",function(){return function(){return Promise.resolve("` + value + `")}})}]);`, pool: make(chan *statsigRuntime, statsigRuntimeMax)}
	var wait sync.WaitGroup
	for range 12 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := engine.signID(context.Background(), "seed", "[]", http.MethodPost, "/rest/test")
			if err != nil || got != value {
				t.Errorf("sign got=%q err=%v", got, err)
			}
		}()
	}
	wait.Wait()
	engine.mu.Lock()
	created := engine.created
	engine.mu.Unlock()
	if created > statsigRuntimeMax {
		t.Fatalf("runtime count %d exceeds %d", created, statsigRuntimeMax)
	}
}

func TestStatsigSignerSendsMethodPathAndMetaContent(t *testing.T) {
	raw := make([]byte, 70)
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload struct {
			Method      string `json:"method"`
			Path        string `json:"path"`
			Environment struct {
				MetaContent string `json:"metaContent"`
			} `json:"environment"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Method != "POST" || payload.Path != "/rest/app-chat/conversations/id/responses" || payload.Environment.MetaContent != "meta-value" {
			t.Fatalf("payload=%#v", payload)
		}
		body, _ := json.Marshal(map[string]string{"x-statsig-id": encoded})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	value, err := signer.requestSignature(context.Background(), "https://signer.example/sign", "post", "/rest/app-chat/conversations/id/responses", "meta-value")
	if err != nil || value != encoded {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestStatsigSignerRejectsInvalidShape(t *testing.T) {
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.client = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"x-statsig-id":"invalid"}`)), Header: http.Header{}}, nil
	})}
	if _, err := signer.requestSignature(context.Background(), "https://signer.example/sign", "POST", "/rest/test", "meta"); err == nil {
		t.Fatal("invalid signature was accepted")
	}
}

func TestValidateStatsigSignerEndpointUsesAdminURLBoundary(t *testing.T) {
	for _, endpoint := range []string{
		"https://grok.wodf.de/sign",
		"https://signer.example/sign",
		"http://grok-signer-go:8788/sign",
		"http://host.docker.internal:8788/sign",
		"http://127.0.0.1:8788/sign",
		"https://10.0.0.1:8443/sign",
	} {
		if err := validateStatsigSignerEndpoint(context.Background(), endpoint); err != nil {
			t.Fatalf("endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"http://grok.wodf.de/sign",
		"https://user:pass@grok.wodf.de/sign",
		"https://grok.wodf.de:8443/sign",
		"https://grok.wodf.de/sign?token=value",
		"http://8.8.8.8:8788/sign",
	} {
		if err := validateStatsigSignerEndpoint(context.Background(), endpoint); err == nil {
			t.Fatalf("unsafe endpoint %q accepted", endpoint)
		}
	}
}

func TestStatsigSignerClientRejectsRedirects(t *testing.T) {
	signer := newStatsigSigner()
	request, err := http.NewRequest(http.MethodGet, "http://grok-signer-go:8788/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.client.CheckRedirect(request, []*http.Request{request}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v", err)
	}
}

func TestStatsigSignerCachesMetaButSignsEveryRequest(t *testing.T) {
	var fetches, signatures int
	var signedMeta []string
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	signer := newStatsigSigner()
	signer.now = func() time.Time { return now }
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		fetches++
		return fmt.Sprintf("meta-%d", fetches), nil
	}
	signer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload struct {
			Environment struct {
				MetaContent string `json:"metaContent"`
			} `json:"environment"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		signedMeta = append(signedMeta, payload.Environment.MetaContent)
		signatures++
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(signatures)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	first, firstSource, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token-a", nil, http.MethodPost, "https://grok.com/rest/test")
	if err != nil {
		t.Fatal(err)
	}
	second, secondSource, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token-b", nil, http.MethodPost, "https://grok.com/rest/test")
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 || signatures != 2 || len(signedMeta) != 2 || first == second || firstSource != "meta_refresh" || secondSource != "meta_cache" {
		t.Fatalf("cached meta fetches=%d signatures=%d signedMeta=%v same=%t sources=%q/%q", fetches, signatures, signedMeta, first == second, firstSource, secondSource)
	}
	third, thirdSource, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token-b", nil, http.MethodPost, "https://grok.com/rest/other")
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 || signatures != 3 || third == second || thirdSource != "meta_cache" {
		t.Fatalf("different path fetches=%d signatures=%d same=%t source=%q", fetches, signatures, third == second, thirdSource)
	}

	now = now.Add(time.Hour)
	fourth, fourthSource, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token-b", nil, http.MethodPost, "https://grok.com/rest/test")
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 2 || signatures != 4 || fourth == third || fourthSource != "meta_refresh" {
		t.Fatalf("hourly refresh fetches=%d signatures=%d same=%t source=%q", fetches, signatures, fourth == third, fourthSource)
	}

	signer.Invalidate("https://grok.com")
	fifth, fifthSource, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token-a", nil, http.MethodPost, "https://grok.com/rest/test")
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 3 || signatures != 5 || fifth == fourth || fifthSource != "meta_refresh" {
		t.Fatalf("invalidation fetches=%d signatures=%d same=%t source=%q", fetches, signatures, fifth == fourth, fifthSource)
	}
}

func TestStatsigWarmupFetchesMetaOnceForSharedPaths(t *testing.T) {
	var fetches, signatures int
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		fetches++
		return "shared-meta", nil
	}
	signer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		signatures++
		var payload struct {
			Environment struct {
				MetaContent string `json:"metaContent"`
			} `json:"environment"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Environment.MetaContent != "shared-meta" {
			t.Fatalf("meta = %q", payload.Environment.MetaContent)
		}
		raw := make([]byte, 70)
		raw[0] = byte(signatures)
		body, _ := json.Marshal(map[string]string{"x-statsig-id": base64.RawStdEncoding.EncodeToString(raw)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	warmed, err := signer.Warm(context.Background(), "https://grok.com", "token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if warmed != 0 || fetches != 1 || signatures != 0 {
		t.Fatalf("warmed=%d fetches=%d signatures=%d", warmed, fetches, signatures)
	}
	if warmedAgain, err := signer.Warm(context.Background(), "https://grok.com", "token", nil); err != nil || warmedAgain != 0 || fetches != 1 {
		t.Fatalf("cached warmup=%d fetches=%d err=%v", warmedAgain, fetches, err)
	}
	if _, source, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/chat"); err != nil || source != "meta_cache" || fetches != 1 || signatures != 1 {
		t.Fatalf("post-warm sign source=%q fetches=%d signatures=%d err=%v", source, fetches, signatures, err)
	}
}

func TestStatsigSignerConcurrentCallsShareMetaButNotSignature(t *testing.T) {
	const requests = 8
	var fetches, signatures atomic.Int64
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		fetches.Add(1)
		time.Sleep(20 * time.Millisecond)
		return "shared-meta", nil
	}
	signer.client = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		sequence := int(signatures.Add(1))
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(sequence)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}

	start := make(chan struct{})
	values := make([]string, requests)
	errorsByRequest := make([]error, requests)
	var wait sync.WaitGroup
	wait.Add(requests)
	for index := range requests {
		go func(index int) {
			defer wait.Done()
			<-start
			values[index], _, errorsByRequest[index] = signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
		}(index)
	}
	close(start)
	wait.Wait()

	unique := make(map[string]struct{}, requests)
	for index, err := range errorsByRequest {
		if err != nil {
			t.Fatalf("request %d: %v", index, err)
		}
		unique[values[index]] = struct{}{}
	}
	if fetches.Load() != 1 || signatures.Load() != requests || len(unique) != requests {
		t.Fatalf("fetches=%d signatures=%d unique=%d", fetches.Load(), signatures.Load(), len(unique))
	}
}

func TestStatsigConcurrentInvalidationsDoNotOverlapMetaRefreshes(t *testing.T) {
	const requests = 8
	var fetches, activeFetches, maxActiveFetches, signatures atomic.Int64
	firstFetchStarted := make(chan struct{})
	releaseFirstFetch := make(chan struct{})
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		sequence := fetches.Add(1)
		active := activeFetches.Add(1)
		defer activeFetches.Add(-1)
		for {
			current := maxActiveFetches.Load()
			if active <= current || maxActiveFetches.CompareAndSwap(current, active) {
				break
			}
		}
		if sequence == 1 {
			close(firstFetchStarted)
			<-releaseFirstFetch
		}
		return fmt.Sprintf("meta-%d", sequence), nil
	}
	signer.client = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		sequence := int(signatures.Add(1))
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(sequence)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}

	values := make([]string, requests)
	errorsByRequest := make([]error, requests)
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		values[0], _, errorsByRequest[0] = signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
	}()
	<-firstFetchStarted
	for range requests {
		signer.Invalidate("https://grok.com")
	}
	for index := 1; index < requests; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			values[index], _, errorsByRequest[index] = signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
		}(index)
	}
	close(releaseFirstFetch)
	wait.Wait()

	unique := make(map[string]struct{}, requests)
	for index, err := range errorsByRequest {
		if err != nil {
			t.Fatalf("request %d: %v", index, err)
		}
		unique[values[index]] = struct{}{}
	}
	if fetches.Load() != 2 || maxActiveFetches.Load() != 1 || len(unique) != requests {
		t.Fatalf("fetches=%d max_active=%d unique=%d", fetches.Load(), maxActiveFetches.Load(), len(unique))
	}
}

func TestStatsigInvalidationDiscardsSignatureMadeFromOldMeta(t *testing.T) {
	var fetches, signatures atomic.Int64
	firstSignatureStarted := make(chan struct{})
	releaseFirstSignature := make(chan struct{})
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		return fmt.Sprintf("meta-%d", fetches.Add(1)), nil
	}
	var signedMetaMu sync.Mutex
	var signedMeta []string
	signer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload struct {
			Environment struct {
				MetaContent string `json:"metaContent"`
			} `json:"environment"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			return nil, err
		}
		signedMetaMu.Lock()
		signedMeta = append(signedMeta, payload.Environment.MetaContent)
		signedMetaMu.Unlock()
		sequence := int(signatures.Add(1))
		if sequence == 1 {
			close(firstSignatureStarted)
			<-releaseFirstSignature
		}
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(sequence)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}

	type result struct {
		value  string
		source string
		err    error
	}
	resultChannel := make(chan result, 1)
	go func() {
		value, source, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
		resultChannel <- result{value: value, source: source, err: err}
	}()
	<-firstSignatureStarted
	signer.Invalidate("https://grok.com")
	close(releaseFirstSignature)
	got := <-resultChannel
	if got.err != nil || got.value != testStatsigID(2) || got.source != "meta_refresh" {
		t.Fatalf("value_is_fresh=%t source=%q err=%v", got.value == testStatsigID(2), got.source, got.err)
	}
	signedMetaMu.Lock()
	defer signedMetaMu.Unlock()
	if fetches.Load() != 2 || signatures.Load() != 2 || len(signedMeta) != 2 || signedMeta[0] != "meta-1" || signedMeta[1] != "meta-2" {
		t.Fatalf("fetches=%d signatures=%d signed_meta=%v", fetches.Load(), signatures.Load(), signedMeta)
	}
}

func TestStatsigDuplicateGuardRetainsAllValuesForTTL(t *testing.T) {
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	signer := newStatsigSigner()
	generation := signer.currentGeneration()
	const signatures = 4097
	for sequence := 0; sequence < signatures; sequence++ {
		claimed, current := signer.claimSignature(fmt.Sprintf("signature-%d", sequence), now, generation)
		if !claimed || !current {
			t.Fatalf("signature %d claimed=%t current=%t", sequence, claimed, current)
		}
	}
	claimed, current := signer.claimSignature("signature-0", now, generation)
	if claimed || !current {
		t.Fatalf("oldest signature claimed=%t current=%t", claimed, current)
	}
	signer.Clear()
	claimed, current = signer.claimSignature("signature-0", now, signer.currentGeneration())
	if claimed || !current {
		t.Fatalf("signature after clear claimed=%t current=%t", claimed, current)
	}
}

func TestStatsigSignerRetriesDuplicateSignature(t *testing.T) {
	var signatures int
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		return "meta", nil
	}
	signer.client = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		signatures++
		sequence := 1
		if signatures >= 3 {
			sequence = 2
		}
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(sequence)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	first, _, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || signatures != 3 {
		t.Fatalf("same=%t signatures=%d", first == second, signatures)
	}
}

func TestStatsigInvalidationWinsAgainstInFlightMetaRefresh(t *testing.T) {
	var fetches atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	signer := newStatsigSigner()
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		sequence := fetches.Add(1)
		if sequence == 1 {
			close(started)
			<-release
			return "stale-meta", nil
		}
		return "fresh-meta", nil
	}
	var signedMeta string
	signer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload struct {
			Environment struct {
				MetaContent string `json:"metaContent"`
			} `json:"environment"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			return nil, err
		}
		signedMeta = payload.Environment.MetaContent
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(1)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}

	type result struct {
		value  string
		source string
		err    error
	}
	resultChannel := make(chan result, 1)
	go func() {
		value, source, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
		resultChannel <- result{value: value, source: source, err: err}
	}()
	<-started
	signer.Invalidate("https://grok.com")
	close(release)
	got := <-resultChannel
	if got.err != nil || !validStatsigID(got.value) || got.source != "meta_refresh" {
		t.Fatalf("value valid=%t source=%q err=%v", validStatsigID(got.value), got.source, got.err)
	}
	if fetches.Load() != 2 || signedMeta != "fresh-meta" {
		t.Fatalf("fetches=%d signedMeta=%q", fetches.Load(), signedMeta)
	}
}

func TestApplySignedStatsigUsesManualValue(t *testing.T) {
	value := base64.RawStdEncoding.EncodeToString(make([]byte, 70))
	adapter := &Adapter{cfg: Config{BaseURL: "https://grok.com", StatsigMode: "manual", StatsigManualValue: value}}
	request, err := http.NewRequest(http.MethodPost, "https://grok.com/rest/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.applySignedStatsig(context.Background(), request, "token", nil, false); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("x-statsig-id") != value {
		t.Fatalf("x-statsig-id = %q", request.Header.Get("x-statsig-id"))
	}
}

func TestStatsigInvalidationDoesNotReuseRejectedValue(t *testing.T) {
	var fetches, signatures int
	signer := newStatsigSigner()
	signer.fetchMeta = func(context.Context, string, string, *infraegress.Lease) (string, error) {
		fetches++
		if fetches > 1 {
			return "", errors.New("meta unavailable")
		}
		return "meta", nil
	}
	signer.validateEndpoint = func(context.Context, string) error { return nil }
	signer.client = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		signatures++
		body, _ := json.Marshal(map[string]string{"x-statsig-id": testStatsigID(signatures)})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	previous, _, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
	if err != nil {
		t.Fatal(err)
	}
	signer.Invalidate("https://grok.com")
	value, source, err := signer.Sign(context.Background(), "https://grok.com", "https://signer.example/sign", "token", nil, http.MethodPost, "https://grok.com/rest/test")
	if err == nil || value != "" || source != "" {
		t.Fatalf("previous=%q value=%q source=%q err=%v", previous, value, source, err)
	}
	if fetches != 2 || signatures != 1 {
		t.Fatalf("fetches=%d signatures=%d", fetches, signatures)
	}
}

func TestStatsigInvalidationIsRateLimited(t *testing.T) {
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	signer := newStatsigSigner()
	signer.now = func() time.Time { return now }
	initial := signer.currentGeneration()
	signer.Invalidate("https://grok.com")
	first := signer.currentGeneration()
	signer.Invalidate("https://grok.com")
	second := signer.currentGeneration()
	if first != initial+1 || second != first {
		t.Fatalf("generations initial=%d first=%d second=%d", initial, first, second)
	}
	now = now.Add(statsigInvalidateWindow)
	signer.Invalidate("https://grok.com")
	if third := signer.currentGeneration(); third != second+1 {
		t.Fatalf("generation after window=%d, want %d", third, second+1)
	}
}

func TestApplySignedStatsigNeverLeavesRandomFallback(t *testing.T) {
	adapter := &Adapter{cfg: Config{BaseURL: "https://grok.com", StatsigMode: "manual", StatsigManualValue: "invalid"}}
	request, err := http.NewRequest(http.MethodPost, "https://grok.com/rest/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("x-statsig-id", "random-fallback")
	err = adapter.applySignedStatsig(context.Background(), request, "token", nil, false)
	if value := request.Header.Get("x-statsig-id"); value != "" {
		t.Fatalf("x-statsig-id = %q", value)
	}
	if !errors.Is(err, provider.ErrRequestSigning) {
		t.Fatalf("error = %v", err)
	}
}

func TestStatsigInvalidationOnlyAppliesToURLMode(t *testing.T) {
	manual := &Adapter{cfg: Config{StatsigMode: "manual"}, statsig: newStatsigSigner()}
	if manual.invalidateSignedStatsig(http.MethodPost, "https://grok.com/rest/test") {
		t.Fatal("manual Statsig must not be invalidated automatically")
	}
	urlMode := &Adapter{cfg: Config{BaseURL: "https://grok.com", StatsigMode: "url", StatsigSignerURL: "https://signer.example/sign"}, statsig: newStatsigSigner()}
	if !urlMode.invalidateSignedStatsig(http.MethodPost, "https://grok.com/rest/test") {
		t.Fatal("URL Statsig must be invalidated after anti-bot rejection")
	}
}
