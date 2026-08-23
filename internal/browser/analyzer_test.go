package browser

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/pkg/model"
)

func TestNormalizeCaptureProducesDeterministicMinimizedSignals(t *testing.T) {
	t.Parallel()
	result := CaptureResult{
		FinalURL: "https://example.test/final?redacted",
		DOM:      `<html data-token="synthetic-secret"><body>dynamic-marker</body></html>`,
		Requests: []CaptureRequest{
			{Method: "post", URL: "https://api.example.test/z?redacted"},
			{Method: "GET", URL: "https://api.example.test/a"},
			{Method: "GET", URL: "https://api.example.test/a"},
		},
		Responses: []CaptureResponse{
			{URL: "https://api.example.test/z?redacted", Status: 204},
			{URL: "https://api.example.test/a", Status: 200},
		},
		ScriptURLs: []string{"https://cdn.example.test/z.js", "https://cdn.example.test/a.js", "https://cdn.example.test/a.js"},
		IframeURLs: []string{"https://frame.example.test/widget"},
		Cookies: []CaptureCookie{
			{Name: "zeta", Domain: "example.test"},
			{Name: "alpha", Domain: "example.test"},
			{Name: "alpha", Domain: ".third.example.test"},
		},
	}

	signals, err := normalizeCapture(result)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Signal{
		{Type: model.SignalTypeNetworkRequest, Source: analysis.SourceBrowser, Key: "GET", Value: "https://api.example.test/a", URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeNetworkRequest, Source: analysis.SourceBrowser, Key: "POST", Value: "https://api.example.test/z?redacted", URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeNetworkResponse, Source: analysis.SourceBrowser, Key: "status", Value: "200", URL: "https://api.example.test/a", Confidence: 1},
		{Type: model.SignalTypeNetworkResponse, Source: analysis.SourceBrowser, Key: "status", Value: "204", URL: "https://api.example.test/z?redacted", Confidence: 1},
		{Type: model.SignalTypePageContent, Source: analysis.SourceBrowser, Key: "dom", Value: result.DOM, URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeScriptURL, Source: analysis.SourceBrowser, Key: "src", Value: "https://cdn.example.test/a.js", URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeScriptURL, Source: analysis.SourceBrowser, Key: "src", Value: "https://cdn.example.test/z.js", URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeIframeURL, Source: analysis.SourceBrowser, Key: "src", Value: "https://frame.example.test/widget", URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeCookie, Source: analysis.SourceBrowser, Key: "alpha", Value: ".third.example.test", URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeCookie, Source: analysis.SourceBrowser, Key: "alpha", Value: "example.test", URL: result.FinalURL, Confidence: 1},
		{Type: model.SignalTypeCookie, Source: analysis.SourceBrowser, Key: "zeta", Value: "example.test", URL: result.FinalURL, Confidence: 1},
	}
	if !reflect.DeepEqual(signals, want) {
		t.Fatalf("signals = %#v\nwant %#v", signals, want)
	}
	for index, signal := range signals {
		if err := signal.Validate(); err != nil {
			t.Errorf("signal %d is invalid: %v", index, err)
		}
		if signal.Type == model.SignalTypeCookie && strings.Contains(signal.Value, "synthetic-secret") {
			t.Errorf("cookie signal retained a cookie value: %#v", signal)
		}
	}
}

func TestNormalizeCaptureRejectsInvalidNormalizedSignal(t *testing.T) {
	t.Parallel()
	_, err := normalizeCapture(CaptureResult{Cookies: []CaptureCookie{{Name: " ", Domain: "example.test"}}})
	if !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("normalizeCapture() error = %v, want ErrInvalidSignal", err)
	}
}

func TestAnalyzerObserveRunsLifecycleAndPreservesPartialCapture(t *testing.T) {
	t.Parallel()
	captureErr := errors.New("DOM snapshot failed")
	source := &fakeCaptureSource{
		result: CaptureResult{
			FinalURL: "https://example.test/",
			Requests: []CaptureRequest{{Method: "GET", URL: "https://example.test/"}},
			Warnings: []string{"final DOM reached the capture limit"},
		},
		err: captureErr,
	}
	backend := newFakeAnalyzerBackend(source, nil)
	analyzer := analyzerForBackend(t, backend)

	observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: "https://example.test/"})
	if !errors.Is(err, captureErr) {
		t.Fatalf("Observe() error = %v, want %v", err, captureErr)
	}
	if observation.Source != analysis.SourceBrowser || len(observation.Signals) != 1 {
		t.Fatalf("observation = %#v", observation)
	}
	if !reflect.DeepEqual(observation.Warnings, []string{"final DOM reached the capture limit", warningBrowserIncomplete}) {
		t.Errorf("warnings = %#v", observation.Warnings)
	}
	if backend.beginCalls.Load() != 1 || backend.navigateCalls.Load() != 1 || source.finishCalls.Load() != 1 || backend.closeCalls.Load() != 1 {
		t.Errorf("lifecycle calls = begin %d navigate %d finish %d close %d",
			backend.beginCalls.Load(), backend.navigateCalls.Load(), source.finishCalls.Load(), backend.closeCalls.Load())
	}
}

func TestAnalyzerObserveCancellationClosesRecorderAndSession(t *testing.T) {
	source := newCancellationCaptureSource()
	backend := newFakeAnalyzerBackend(source, nil)
	navigationStarted := make(chan struct{})
	backend.navigateFunc = func(ctx context.Context, _ string) error {
		close(navigationStarted)
		<-ctx.Done()
		// BeginCapture ties the recorder to the same root context. Wait for its
		// cancellation watcher so the test proves recorder cleanup, not merely
		// the later session close.
		<-source.closed
		return ctx.Err()
	}
	analyzer := analyzerForBackend(t, backend)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := analyzer.Observe(ctx, analysis.Target{URL: "https://example.test/"})
		result <- err
	}()

	select {
	case <-navigationStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("browser navigation did not start")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Observe() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Observe did not return after cancellation")
	}
	if source.closeCalls.Load() != 1 || source.finishCalls.Load() != 0 {
		t.Errorf("recorder lifecycle = close %d finish %d, want close 1 finish 0",
			source.closeCalls.Load(), source.finishCalls.Load())
	}
	if backend.closeCalls.Load() != 1 || backend.cleanupCalls.Load() != 1 {
		t.Errorf("session lifecycle = close %d cleanup %d, want 1/1",
			backend.closeCalls.Load(), backend.cleanupCalls.Load())
	}
}

func TestAnalyzerObserveReportsUnavailableBrowserWithoutLeakingError(t *testing.T) {
	t.Parallel()
	secretErr := errors.New("launch failed for --token=synthetic-secret")
	client, err := newClient(DefaultConfig(), backendFunc(func(context.Context, Config) (backendSession, Version, error) {
		return nil, Version{}, secretErr
	}), runtimeTimerFactory)
	if err != nil {
		t.Fatal(err)
	}
	observation, observeErr := newAnalyzer(client).Observe(context.Background(), analysis.Target{URL: "https://example.test/"})
	if !errors.Is(observeErr, secretErr) {
		t.Fatalf("Observe() error = %v, want %v", observeErr, secretErr)
	}
	if len(observation.Signals) != 0 || !reflect.DeepEqual(observation.Warnings, []string{warningBrowserUnavailable}) {
		t.Fatalf("observation = %#v", observation)
	}
	if strings.Contains(strings.Join(observation.Warnings, " "), "synthetic-secret") {
		t.Errorf("warning disclosed error details: %#v", observation.Warnings)
	}
}

func TestAnalyzerObserveReturnsNavigationPartialResultAndCloseError(t *testing.T) {
	t.Parallel()
	navigationErr := errors.New("navigation budget exceeded")
	closeErr := errors.New("profile cleanup failed")
	source := &fakeCaptureSource{result: CaptureResult{
		FinalURL: "https://example.test/",
		Cookies:  []CaptureCookie{{Name: "partial_cookie", Domain: "example.test"}},
	}}
	backend := newFakeAnalyzerBackend(source, navigationErr)
	backend.closeErr = closeErr
	analyzer := analyzerForBackend(t, backend)

	observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: "https://example.test/"})
	if !errors.Is(err, navigationErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Observe() error = %v, want navigation and close errors", err)
	}
	if len(observation.Signals) != 1 || observation.Signals[0].Type != model.SignalTypeCookie ||
		!reflect.DeepEqual(observation.Warnings, []string{warningBrowserIncomplete}) {
		t.Fatalf("partial observation = %#v", observation)
	}
}

func analyzerForBackend(t *testing.T, backend backendSession) *Analyzer {
	t.Helper()
	client, err := newClient(DefaultConfig(), backendFunc(func(context.Context, Config) (backendSession, Version, error) {
		return backend, Version{Product: "Chromium/test", ProtocolVersion: "1.3"}, nil
	}), runtimeTimerFactory)
	if err != nil {
		t.Fatal(err)
	}
	return newAnalyzer(client)
}

type fakeAnalyzerBackend struct {
	*fakeBackendSession
	source        captureSource
	navigateErr   error
	navigateFunc  func(context.Context, string) error
	beginCalls    atomic.Int32
	navigateCalls atomic.Int32
}

func newFakeAnalyzerBackend(source captureSource, navigateErr error) *fakeAnalyzerBackend {
	return &fakeAnalyzerBackend{
		fakeBackendSession: newFakeBackendSession(nil),
		source:             source,
		navigateErr:        navigateErr,
	}
}

func (b *fakeAnalyzerBackend) beginCapture(context.Context) (captureSource, error) {
	b.beginCalls.Add(1)
	return b.source, nil
}

func (b *fakeAnalyzerBackend) navigate(ctx context.Context, target string) error {
	b.navigateCalls.Add(1)
	if b.navigateFunc != nil {
		return b.navigateFunc(ctx, target)
	}
	return b.navigateErr
}

type cancellationCaptureSource struct {
	closed      chan struct{}
	closeOnce   sync.Once
	closeCalls  atomic.Int32
	finishCalls atomic.Int32
}

func newCancellationCaptureSource() *cancellationCaptureSource {
	return &cancellationCaptureSource{closed: make(chan struct{})}
}

func (s *cancellationCaptureSource) finish(ctx context.Context) (CaptureResult, error) {
	s.finishCalls.Add(1)
	return CaptureResult{}, ctx.Err()
}

func (s *cancellationCaptureSource) Close() error {
	s.closeCalls.Add(1)
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

var _ captureBackendSession = (*fakeAnalyzerBackend)(nil)
var _ navigationBackendSession = (*fakeAnalyzerBackend)(nil)
