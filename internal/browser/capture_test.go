package browser

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestRecorderLifecycleAndSessionExclusivity(t *testing.T) {
	t.Parallel()
	source := &fakeCaptureSource{result: CaptureResult{FinalURL: "https://example.test/"}}
	backend := newFakeCaptureBackend(source)
	session := newSession(Version{}, backend, func() {})

	recorder, err := session.BeginCapture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.BeginCapture(context.Background()); !errors.Is(err, ErrCaptureActive) {
		t.Fatalf("second BeginCapture() error = %v, want ErrCaptureActive", err)
	}
	first, err := recorder.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.FinalURL = "mutated"
	second, err := recorder.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.FinalURL != "https://example.test/" {
		t.Errorf("second result URL = %q, want cloned original", second.FinalURL)
	}
	if source.finishCalls.Load() != 1 {
		t.Errorf("finish calls = %d, want 1", source.finishCalls.Load())
	}

	backend.next = &fakeCaptureSource{}
	if next, err := session.BeginCapture(context.Background()); err != nil {
		t.Fatalf("BeginCapture() after Finish: %v", err)
	} else if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.BeginCapture(context.Background()); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("BeginCapture() after Close error = %v, want ErrSessionClosed", err)
	}
}

func TestBeginCaptureValidatesContextAndPreservesBackendError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("enable Network failed")
	backend := newFakeCaptureBackend(nil)
	backend.beginErr = wantErr
	session := newSession(Version{}, backend, func() {})
	if _, err := session.BeginCapture(nil); err == nil {
		t.Fatal("BeginCapture(nil) error = nil")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.BeginCapture(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginCapture(canceled) error = %v, want context.Canceled", err)
	}
	if _, err := session.BeginCapture(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("BeginCapture() error = %v, want %v", err, wantErr)
	}
	if backend.beginCalls.Load() != 1 {
		t.Errorf("backend begin calls = %d, want 1", backend.beginCalls.Load())
	}
	_ = session.Close()
}

func TestSessionClosePreservesRecorderAndBackendErrors(t *testing.T) {
	t.Parallel()
	recorderErr := errors.New("stop listener failed")
	backendErr := errors.New("stop Chromium failed")
	source := &fakeCaptureSource{err: recorderErr}
	backend := newFakeCaptureBackend(source)
	backend.closeErr = backendErr
	session := newSession(Version{}, backend, func() {})
	if _, err := session.BeginCapture(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := session.Close()
	if !errors.Is(err, recorderErr) || !errors.Is(err, backendErr) {
		t.Fatalf("Close() error = %v, want recorder and backend errors", err)
	}
	if err := session.Close(); !errors.Is(err, recorderErr) || !errors.Is(err, backendErr) {
		t.Fatalf("repeated Close() error = %v, want preserved errors", err)
	}
}

func TestCaptureCancellationAndSessionCloseAbandonRecorder(t *testing.T) {
	t.Parallel()
	t.Run("caller cancellation", func(t *testing.T) {
		source := &fakeCaptureSource{}
		backend := newFakeCaptureBackend(source)
		session := newSession(Version{}, backend, func() {})
		ctx, cancel := context.WithCancel(context.Background())
		recorder, err := session.BeginCapture(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		<-recorder.done
		if source.closeCalls.Load() != 1 {
			t.Errorf("source Close calls = %d, want 1", source.closeCalls.Load())
		}
		if _, err := recorder.Finish(context.Background()); !errors.Is(err, ErrRecorderClosed) {
			t.Fatalf("Finish() after cancellation error = %v, want ErrRecorderClosed", err)
		}
		_ = session.Close()
	})

	t.Run("session close", func(t *testing.T) {
		source := &fakeCaptureSource{}
		backend := newFakeCaptureBackend(source)
		session := newSession(Version{}, backend, func() {})
		recorder, err := session.BeginCapture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		<-recorder.done
		if source.closeCalls.Load() != 1 {
			t.Errorf("source Close calls = %d, want 1", source.closeCalls.Load())
		}
	})
}

func TestRecorderPreservesPartialResultAndErrors(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("DOM snapshot failed")
	source := &fakeCaptureSource{
		result: CaptureResult{Requests: []CaptureRequest{{URL: "https://example.test/"}}},
		err:    wantErr,
	}
	recorder := newRecorder(source, func(*Recorder) {})
	result, err := recorder.Finish(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Finish() error = %v, want %v", err, wantErr)
	}
	if len(result.Requests) != 1 {
		t.Fatalf("Finish() requests = %d, want partial result", len(result.Requests))
	}
	result.Requests[0].URL = "mutated"
	again, err := recorder.Finish(context.Background())
	if !errors.Is(err, wantErr) || again.Requests[0].URL != "https://example.test/" {
		t.Fatalf("repeated Finish() = %#v, %v", again, err)
	}
}

func TestRecorderFinishObservesContext(t *testing.T) {
	t.Parallel()
	source := &fakeCaptureSource{finishWithContext: true}
	recorder := newRecorder(source, func(*Recorder) {})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := recorder.Finish(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Finish(canceled) error = %v, want context.Canceled", err)
	}
}

func TestRecordNetworkEventIncludesRedirectAndPreservesOrder(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	recordNetworkEvent(collector, &network.EventRequestWillBeSent{
		Type:    network.ResourceTypeDocument,
		Request: &network.Request{Method: "GET", URL: "https://user:secret@example.test/start?token=secret#fragment"},
	})
	recordNetworkEvent(collector, &network.EventRequestWillBeSent{
		Type: network.ResourceTypeDocument,
		RedirectResponse: &network.Response{
			URL: "https://example.test/start?token=secret", Status: 302, MimeType: "text/html",
		},
		Request: &network.Request{Method: "GET", URL: "https://example.test/final"},
	})
	recordNetworkEvent(collector, &network.EventResponseReceived{
		Type:     network.ResourceTypeDocument,
		Response: &network.Response{URL: "https://example.test/final", Status: 200, MimeType: "text/html"},
	})
	result := collector.snapshot("https://example.test/final", "", nil)
	if got := []string{result.Requests[0].URL, result.Requests[1].URL}; !reflect.DeepEqual(got, []string{
		"https://example.test/start?redacted", "https://example.test/final",
	}) {
		t.Errorf("request order/URLs = %#v", got)
	}
	if got := []int64{result.Responses[0].Status, result.Responses[1].Status}; !reflect.DeepEqual(got, []int64{302, 200}) {
		t.Errorf("response order/statuses = %#v", got)
	}
	serialized := fmt.Sprintf("%#v", result)
	for _, secret := range []string{"user", "secret", "token=secret", "fragment"} {
		if strings.Contains(serialized, secret) {
			t.Errorf("capture contains secret %q: %s", secret, serialized)
		}
	}
}

func TestCaptureSnapshotExtractsResourcesAndCookieProvenance(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	dom := `<html><head><base href="https://cdn.example.test/assets/?key=secret">` +
		`<script src="a.js?auth=secret#x"></script><script src="data:text/javascript,x"></script></head>` +
		`<body><iframe src="/frame?session=secret"></iframe><script src="a.js?other=secret"></script></body></html>`
	result := collector.snapshot(
		"https://name:password@example.test/page?secret=yes#private",
		dom,
		[]CaptureCookie{
			{Name: "zeta", Domain: "example.test"},
			{Name: "alpha", Domain: "example.test"},
			{Name: "alpha", Domain: ".third.example.test"},
			{Name: "bad\nname", Domain: "example.test"},
			{Name: "omitted", Domain: "bad_domain"},
		},
	)
	if result.FinalURL != "https://example.test/page?redacted" {
		t.Errorf("FinalURL = %q", result.FinalURL)
	}
	if want := []string{"https://cdn.example.test/assets/a.js?redacted", "https://cdn.example.test/assets/a.js?redacted"}; !reflect.DeepEqual(result.ScriptURLs, want) {
		t.Errorf("ScriptURLs = %#v, want %#v", result.ScriptURLs, want)
	}
	if want := []string{"https://cdn.example.test/frame?redacted"}; !reflect.DeepEqual(result.IframeURLs, want) {
		t.Errorf("IframeURLs = %#v, want %#v", result.IframeURLs, want)
	}
	if want := []CaptureCookie{
		{Name: "alpha", Domain: ".third.example.test"},
		{Name: "alpha", Domain: "example.test"},
		{Name: "zeta", Domain: "example.test"},
	}; !reflect.DeepEqual(result.Cookies, want) {
		t.Errorf("Cookies = %#v, want %#v", result.Cookies, want)
	}
	if !strings.Contains(result.DOM, "session=secret") {
		t.Error("bounded in-memory DOM should retain page markup")
	}
}

func TestCaptureOmitsNonWebAndInvalidMetadata(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	collector.addRequest("G\nET", "file:///tmp/private", "Document")
	collector.addRequest("GET", "https://example.test/", "bad\x00type")
	collector.addRequest("GET", "HTTPS://EXAMPLE.TEST/path", "Document")
	collector.addResponse("javascript:secret", 200, "text/html", "Document")
	collector.addResponse("https://example.test/", 200, "bad\rvalue", "Document")
	result := collector.snapshot("about:blank", "<script src='blob:secret'></script>", []CaptureCookie{{Name: "bad\x00cookie", Domain: "example.test"}})
	if result.FinalURL != "" || len(result.Requests) != 2 || result.Requests[0].ResourceType != "" ||
		result.Requests[1].URL != "https://EXAMPLE.TEST/path" || len(result.Responses) != 1 || result.Responses[0].MIMEType != "" {
		t.Fatalf("invalid metadata was retained: %#v", result)
	}
	if len(result.ScriptURLs) != 0 || len(result.Cookies) != 0 {
		t.Fatalf("non-web resource or invalid cookie retained: %#v", result)
	}
}

func TestCaptureCollectionLimits(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	for i := 0; i <= maxCaptureItems; i++ {
		rawURL := fmt.Sprintf("https://example.test/%d", i)
		collector.addRequest("GET", rawURL, "Fetch")
		collector.addResponse(rawURL, 200, "text/plain", "Fetch")
	}
	longURL := "https://example.test/" + strings.Repeat("x", maxBrowserURLBytes)
	collector.addRequest("GET", longURL, "Fetch")

	var dom strings.Builder
	dom.WriteString("<html><body>")
	for i := 0; i <= maxCaptureItems; i++ {
		fmt.Fprintf(&dom, `<script src="/s/%d"></script><iframe src="/f/%d"></iframe>`, i, i)
	}
	dom.WriteString(strings.Repeat("x", maxDOMBytes))
	dom.WriteString("</body></html>")
	cookies := make([]CaptureCookie, maxCaptureItems+1)
	for i := range cookies {
		cookies[i] = CaptureCookie{Name: fmt.Sprintf("cookie-%04d", i), Domain: "example.test"}
	}
	result := collector.snapshot("https://example.test/", dom.String(), cookies)
	if len(result.Requests) != maxCaptureItems || len(result.Responses) != maxCaptureItems ||
		len(result.ScriptURLs) != maxCaptureItems || len(result.IframeURLs) != maxCaptureItems ||
		len(result.Cookies) != maxCaptureItems {
		t.Fatalf("item limits = requests %d responses %d scripts %d iframes %d cookies %d",
			len(result.Requests), len(result.Responses), len(result.ScriptURLs), len(result.IframeURLs), len(result.Cookies))
	}
	if !result.DOMTruncated || len(result.DOM) > maxDOMBytes {
		t.Errorf("DOM truncation = %t, %d bytes", result.DOMTruncated, len(result.DOM))
	}
	wants := []string{warningRequestLimit, warningResponseLimit, warningURLLimit, warningScriptLimit, warningIframeLimit, warningDOMLimit, warningCookieLimit}
	for _, warning := range wants {
		if count := countString(result.Warnings, warning); count != 1 {
			t.Errorf("warning %q count = %d, want 1; warnings %#v", warning, count, result.Warnings)
		}
	}
}

func TestBoundedDOMSnapshotPreservesSerializerLimits(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	result := collector.snapshotBounded("https://example.test/page", boundedDOMSnapshot{
		DOM:                "<html><body>partial",
		ScriptURLs:         []string{"https://example.test/app.js?secret=value"},
		IframeURLs:         []string{"https://example.test/frame#private"},
		DOMTruncated:       true,
		TraversalTruncated: true,
		URLTruncated:       true,
	}, nil)
	if result.DOM != "<html><body>partial" || !result.DOMTruncated {
		t.Fatalf("bounded DOM = %q, truncated=%t", result.DOM, result.DOMTruncated)
	}
	if fmt.Sprint(result.ScriptURLs) != fmt.Sprint([]string{"https://example.test/app.js?redacted"}) ||
		fmt.Sprint(result.IframeURLs) != fmt.Sprint([]string{"https://example.test/frame"}) {
		t.Fatalf("bounded resources were not cleaned: %#v", result)
	}
	for _, warning := range []string{warningDOMLimit, warningScriptLimit, warningIframeLimit, warningURLLimit} {
		if count := countString(result.Warnings, warning); count != 1 {
			t.Errorf("warning %q count = %d, want 1; warnings %#v", warning, count, result.Warnings)
		}
	}
}

func TestCaptureResultSlicesAreCloned(t *testing.T) {
	t.Parallel()
	original := CaptureResult{
		Requests: []CaptureRequest{{URL: "request"}}, Responses: []CaptureResponse{{URL: "response"}},
		ScriptURLs: []string{"script"}, IframeURLs: []string{"iframe"},
		Cookies: []CaptureCookie{{Name: "cookie", Domain: "example.test"}}, Warnings: []string{"warning"},
	}
	clone := cloneCaptureResult(original)
	clone.Requests[0].URL = "x"
	clone.Responses[0].URL = "x"
	clone.ScriptURLs[0], clone.IframeURLs[0], clone.Cookies[0].Name, clone.Warnings[0] = "x", "x", "x", "x"
	if original.Requests[0].URL != "request" || original.Responses[0].URL != "response" ||
		original.ScriptURLs[0] != "script" || original.IframeURLs[0] != "iframe" ||
		original.Cookies[0].Name != "cookie" || original.Warnings[0] != "warning" {
		t.Fatalf("clone aliases original: %#v", original)
	}
}

func countString(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

type fakeCaptureBackend struct {
	*fakeBackendSession
	next       captureSource
	beginErr   error
	beginCalls atomic.Int32
}

func newFakeCaptureBackend(source captureSource) *fakeCaptureBackend {
	return &fakeCaptureBackend{fakeBackendSession: newFakeBackendSession(nil), next: source}
}

func (b *fakeCaptureBackend) beginCapture(context.Context) (captureSource, error) {
	b.beginCalls.Add(1)
	return b.next, b.beginErr
}

type fakeCaptureSource struct {
	result            CaptureResult
	err               error
	finishWithContext bool
	finishCalls       atomic.Int32
	closeCalls        atomic.Int32
}

func (s *fakeCaptureSource) finish(ctx context.Context) (CaptureResult, error) {
	s.finishCalls.Add(1)
	if s.finishWithContext {
		return s.result, ctx.Err()
	}
	return s.result, s.err
}

func (s *fakeCaptureSource) Close() error {
	s.closeCalls.Add(1)
	return s.err
}
