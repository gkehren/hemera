package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cdproto "github.com/chromedp/cdproto"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	cdpruntime "github.com/chromedp/cdproto/runtime"
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
	if !result.RequestsTruncated || !result.ResponsesTruncated || !result.ScriptURLsTruncated ||
		!result.IframeURLsTruncated || !result.CookiesTruncated {
		t.Errorf("channel truncation flags = requests %t responses %t scripts %t iframes %t cookies %t, want all set",
			result.RequestsTruncated, result.ResponsesTruncated, result.ScriptURLsTruncated,
			result.IframeURLsTruncated, result.CookiesTruncated)
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
	if !result.ScriptURLsTruncated || !result.IframeURLsTruncated {
		t.Errorf("script/iframe truncation flags = %t/%t, want both set by serializer limits",
			result.ScriptURLsTruncated, result.IframeURLsTruncated)
	}
	if result.RequestsTruncated || result.ResponsesTruncated || result.CookiesTruncated {
		t.Errorf("unrelated channel flags = requests %t responses %t cookies %t, want all clear",
			result.RequestsTruncated, result.ResponsesTruncated, result.CookiesTruncated)
	}
	for _, warning := range []string{warningDOMLimit, warningScriptLimit, warningIframeLimit, warningURLLimit} {
		if count := countString(result.Warnings, warning); count != 1 {
			t.Errorf("warning %q count = %d, want 1; warnings %#v", warning, count, result.Warnings)
		}
	}
}

func TestBoundedDOMSnapshotURLTruncationIsPerChannel(t *testing.T) {
	t.Parallel()
	// The bounded serializer attributes each oversized resource URL to its own
	// channel. A diagnostic url_truncated flag alone must never widen
	// incompleteness to both resource channels.
	longURL := "https://example.test/" + strings.Repeat("x", maxBrowserURLBytes)

	t.Run("oversized serializer script leaves iframes conclusive", func(t *testing.T) {
		t.Parallel()
		collector := newCaptureCollector()
		result := collector.snapshotBounded("https://example.test/", boundedDOMSnapshot{
			DOM:             "<html><body>ok</body></html>",
			ScriptURLs:      []string{longURL},
			IframeURLs:      []string{"https://example.test/frame"},
			URLTruncated:    true,
			ScriptTruncated: true,
		}, nil)
		if !result.ScriptURLsTruncated {
			t.Error("ScriptURLsTruncated = false, want true after oversized script URL")
		}
		if result.IframeURLsTruncated {
			t.Error("IframeURLsTruncated = true, want clear for valid iframe")
		}
		if count := countString(result.Warnings, warningURLLimit); count != 1 {
			t.Errorf("warning %q count = %d, want 1; warnings %#v", warningURLLimit, count, result.Warnings)
		}
	})

	t.Run("oversized serializer iframe leaves scripts conclusive", func(t *testing.T) {
		t.Parallel()
		collector := newCaptureCollector()
		result := collector.snapshotBounded("https://example.test/", boundedDOMSnapshot{
			DOM:             "<html><body>ok</body></html>",
			ScriptURLs:      []string{"https://example.test/app.js"},
			IframeURLs:      []string{longURL},
			URLTruncated:    true,
			IframeTruncated: true,
		}, nil)
		if !result.IframeURLsTruncated {
			t.Error("IframeURLsTruncated = false, want true after oversized iframe URL")
		}
		if result.ScriptURLsTruncated {
			t.Error("ScriptURLsTruncated = true, want clear for valid script")
		}
	})

	t.Run("diagnostic url_truncated alone sets no channel flags", func(t *testing.T) {
		t.Parallel()
		collector := newCaptureCollector()
		result := collector.snapshotBounded("https://example.test/", boundedDOMSnapshot{
			DOM:          "<html><body>ok</body></html>",
			URLTruncated: true,
		}, nil)
		if result.ScriptURLsTruncated || result.IframeURLsTruncated || result.RequestsTruncated ||
			result.ResponsesTruncated || result.CookiesTruncated || result.DOMTruncated ||
			result.FinalURLIncomplete || result.NavigationIncomplete || result.DOMIncomplete ||
			result.CookiesIncomplete {
			t.Fatalf("diagnostic url_truncated set structured flags: %#v", result)
		}
		if count := countString(result.Warnings, warningURLLimit); count != 1 {
			t.Errorf("warning %q count = %d, want 1; warnings %#v", warningURLLimit, count, result.Warnings)
		}
	})
}

func TestBoundedDOMCaptureRetriesOnlyClassifiedFrameTransitions(t *testing.T) {
	t.Parallel()
	frameA := mainFrameIdentity{frameID: cdp.FrameID("main"), loaderID: cdp.LoaderID("loader-a")}
	frameB := mainFrameIdentity{frameID: cdp.FrameID("main"), loaderID: cdp.LoaderID("loader-b")}

	t.Run("context invalidation with loader transition retries once", func(t *testing.T) {
		frames := []mainFrameIdentity{frameA, frameB, frameB, frameB}
		frameCall := 0
		evaluateCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) {
				frame := frames[frameCall]
				frameCall++
				return frame, nil
			},
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				return cdpruntime.ExecutionContextID(1), nil
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				evaluateCall++
				if evaluateCall == 1 {
					return nil, nil, &cdproto.Error{Code: -32000, Message: "Execution context was destroyed."}
				}
				return serializedDOMRemoteObject(t, boundedDOMSnapshot{DOM: "stable"}), nil, nil
			},
		}
		var snapshot boundedDOMSnapshot
		if err := captureBoundedDOMWithOps(context.Background(), &snapshot, ops); err != nil {
			t.Fatal(err)
		}
		if snapshot.DOM != "stable" || evaluateCall != 2 {
			t.Fatalf("capture = %#v after %d evaluations, want stable retry", snapshot, evaluateCall)
		}
	})

	t.Run("context error without frame transition remains fatal", func(t *testing.T) {
		evaluateCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) { return frameA, nil },
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				return cdpruntime.ExecutionContextID(1), nil
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				evaluateCall++
				return nil, nil, &cdproto.Error{Code: -32000, Message: "Execution context was destroyed."}
			},
		}
		err := captureBoundedDOMWithOps(context.Background(), &boundedDOMSnapshot{}, ops)
		if err == nil || !strings.Contains(err.Error(), "Execution context was destroyed") || evaluateCall != 1 {
			t.Fatalf("capture error = %v after %d evaluations, want visible non-retried error", err, evaluateCall)
		}
	})

	t.Run("frame ID change with same loader retries once", func(t *testing.T) {
		frameOther := mainFrameIdentity{frameID: cdp.FrameID("other"), loaderID: cdp.LoaderID("loader-a")}
		frames := []mainFrameIdentity{frameA, frameOther, frameOther, frameOther}
		frameCall := 0
		evaluateCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) {
				frame := frames[frameCall]
				frameCall++
				return frame, nil
			},
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				return cdpruntime.ExecutionContextID(1), nil
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				evaluateCall++
				if evaluateCall == 1 {
					return nil, nil, &cdproto.Error{Code: -32000, Message: "Execution context was destroyed."}
				}
				return serializedDOMRemoteObject(t, boundedDOMSnapshot{DOM: "frame-change-retry"}), nil, nil
			},
		}
		var snapshot boundedDOMSnapshot
		if err := captureBoundedDOMWithOps(context.Background(), &snapshot, ops); err != nil {
			t.Fatal(err)
		}
		if snapshot.DOM != "frame-change-retry" || evaluateCall != 2 {
			t.Fatalf("capture = %#v after %d evaluations, want frame ID change retry", snapshot, evaluateCall)
		}
	})

	t.Run("frame and loader both change retries once", func(t *testing.T) {
		frameBoth := mainFrameIdentity{frameID: cdp.FrameID("other"), loaderID: cdp.LoaderID("loader-b")}
		frames := []mainFrameIdentity{frameA, frameBoth, frameBoth, frameBoth}
		frameCall := 0
		evaluateCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) {
				frame := frames[frameCall]
				frameCall++
				return frame, nil
			},
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				return cdpruntime.ExecutionContextID(1), nil
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				evaluateCall++
				if evaluateCall == 1 {
					return nil, nil, &cdproto.Error{Code: -32000, Message: "Execution context was destroyed."}
				}
				return serializedDOMRemoteObject(t, boundedDOMSnapshot{DOM: "both-change-retry"}), nil, nil
			},
		}
		var snapshot boundedDOMSnapshot
		if err := captureBoundedDOMWithOps(context.Background(), &snapshot, ops); err != nil {
			t.Fatal(err)
		}
		if snapshot.DOM != "both-change-retry" || evaluateCall != 2 {
			t.Fatalf("capture = %#v after %d evaluations, want both change retry", snapshot, evaluateCall)
		}
	})

	t.Run("second transition invalidation is fatal without third attempt", func(t *testing.T) {
		frameC := mainFrameIdentity{frameID: cdp.FrameID("main"), loaderID: cdp.LoaderID("loader-c")}
		frames := []mainFrameIdentity{frameA, frameB, frameB, frameC}
		frameCall := 0
		evaluateCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) {
				frame := frames[frameCall]
				frameCall++
				return frame, nil
			},
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				return cdpruntime.ExecutionContextID(1), nil
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				evaluateCall++
				return nil, nil, &cdproto.Error{Code: -32000, Message: "Execution context was destroyed."}
			},
		}
		err := captureBoundedDOMWithOps(context.Background(), &boundedDOMSnapshot{}, ops)
		if err == nil || !strings.Contains(err.Error(), "Execution context was destroyed") || evaluateCall != 2 {
			t.Fatalf("capture error = %v after %d evaluations, want fatal after 2 attempts", err, evaluateCall)
		}
	})

	t.Run("createIsolatedWorld transient error during transition retries once", func(t *testing.T) {
		frames := []mainFrameIdentity{frameA, frameB, frameB, frameB}
		frameCall := 0
		worldCall := 0
		evaluateCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) {
				frame := frames[frameCall]
				frameCall++
				return frame, nil
			},
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				worldCall++
				if worldCall == 1 {
					return 0, &cdproto.Error{Code: -32000, Message: "No frame with given id found."}
				}
				return cdpruntime.ExecutionContextID(2), nil
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				evaluateCall++
				return serializedDOMRemoteObject(t, boundedDOMSnapshot{DOM: "world-retry-success"}), nil, nil
			},
		}
		var snapshot boundedDOMSnapshot
		if err := captureBoundedDOMWithOps(context.Background(), &snapshot, ops); err != nil {
			t.Fatal(err)
		}
		if snapshot.DOM != "world-retry-success" || worldCall != 2 || evaluateCall != 1 {
			t.Fatalf("capture = %#v (worlds=%d evaluates=%d), want retry on transient world failure", snapshot, worldCall, evaluateCall)
		}
	})

	t.Run("createIsolatedWorld unclassified error remains fatal", func(t *testing.T) {
		frames := []mainFrameIdentity{frameA, frameB}
		frameCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) {
				frame := frames[frameCall]
				frameCall++
				return frame, nil
			},
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				return 0, errors.New("Page.createIsolatedWorld unexpected error")
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				return serializedDOMRemoteObject(t, boundedDOMSnapshot{DOM: "unexpected"}), nil, nil
			},
		}
		err := captureBoundedDOMWithOps(context.Background(), &boundedDOMSnapshot{}, ops)
		if err == nil || !strings.Contains(err.Error(), "Page.createIsolatedWorld unexpected error") {
			t.Fatalf("capture error = %v, want unclassified world error to be fatal", err)
		}
	})

	t.Run("serializer exception remains fatal across frame transition", func(t *testing.T) {
		frames := []mainFrameIdentity{frameA, frameB}
		frameCall := 0
		evaluateCall := 0
		ops := boundedDOMCaptureOps{
			mainFrame: func(context.Context) (mainFrameIdentity, error) {
				frame := frames[frameCall]
				frameCall++
				return frame, nil
			},
			createIsolatedWorld: func(context.Context, cdp.FrameID) (cdpruntime.ExecutionContextID, error) {
				return cdpruntime.ExecutionContextID(1), nil
			},
			evaluate: func(context.Context, cdpruntime.ExecutionContextID) (*cdpruntime.RemoteObject, *cdpruntime.ExceptionDetails, error) {
				evaluateCall++
				return nil, &cdpruntime.ExceptionDetails{
					Text:      "Uncaught TypeError",
					Exception: &cdpruntime.RemoteObject{Description: "TypeError: serializer defect"},
				}, nil
			},
		}
		err := captureBoundedDOMWithOps(context.Background(), &boundedDOMSnapshot{}, ops)
		if err == nil || !strings.Contains(err.Error(), "serializer defect") || evaluateCall != 1 {
			t.Fatalf("capture error = %v after %d evaluations, want visible serializer failure", err, evaluateCall)
		}
	})
}

func TestBoundedDOMExceptionDiagnosticsAreBoundedAndSanitized(t *testing.T) {
	t.Parallel()
	details := &cdpruntime.ExceptionDetails{
		Text:         "Uncaught\nTypeError",
		LineNumber:   12,
		ColumnNumber: 7,
		URL:          "https://example.test/page?token=secret",
		Exception: &cdpruntime.RemoteObject{
			Description: "TypeError:\t" + strings.Repeat("serializer failed ", 100),
		},
		StackTrace: &cdpruntime.StackTrace{CallFrames: []*cdpruntime.CallFrame{
			{FunctionName: "appendRaw\r", URL: "https://example.test/script?cookie=secret", LineNumber: 20, ColumnNumber: 4},
			{FunctionName: "walk", LineNumber: 40, ColumnNumber: 2},
			{FunctionName: "third", LineNumber: 50, ColumnNumber: 1},
			{FunctionName: "omitted", LineNumber: 60, ColumnNumber: 1},
		}},
	}
	diagnostic := formatBoundedDOMException(details).Error()
	for _, want := range []string{
		`text="Uncaught TypeError"`,
		`description="TypeError: serializer failed`,
		"location=12:7",
		"stack=appendRaw@20:4,walk@40:2,third@50:1",
	} {
		if !strings.Contains(diagnostic, want) {
			t.Errorf("diagnostic %q does not contain %q", diagnostic, want)
		}
	}
	if len(diagnostic) > maxDOMDiagnosticBytes {
		t.Errorf("diagnostic length = %d, want at most %d", len(diagnostic), maxDOMDiagnosticBytes)
	}
	for _, forbidden := range []string{"\n", "\r", "\t", "token=secret", "cookie=secret", "omitted"} {
		if strings.Contains(diagnostic, forbidden) {
			t.Errorf("diagnostic retained forbidden value %q: %q", forbidden, diagnostic)
		}
	}
}

func serializedDOMRemoteObject(t *testing.T, snapshot boundedDOMSnapshot) *cdpruntime.RemoteObject {
	t.Helper()
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return &cdpruntime.RemoteObject{Value: data}
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

func TestBoundedDOMSerializerTemplateFormat(t *testing.T) {
	t.Parallel()
	script := fmt.Sprintf(boundedDOMSerializer, maxDOMBytes, maxDOMWorkItems, maxCaptureItems, maxBrowserURLBytes)
	for _, want := range []string{
		"const encodeScratch = new Uint8Array(Math.min(maxBytes, 65536));",
		"const urlScratch = new Uint8Array(maxURLBytes + 1);",
		"let currentChunk = \"\";",
		"if (currentChunk.length >= 16384)",
		"chunks.join(\"\")",
		"encodeInto(candidate, buffer)",
		"encodeInto(value, urlScratch)",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("boundedDOMSerializer missing %q", want)
		}
	}
}

func TestBoundedDOMSnapshotUTF8MultibyteHandling(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	multibyteDOM := "<html><body>" + strings.Repeat("é€漢😀", 1000) + "</body></html>"
	result := collector.snapshotBounded("https://example.test/", boundedDOMSnapshot{
		DOM: multibyteDOM,
	}, nil)

	if !strings.Contains(result.DOM, "é€漢😀") {
		t.Error("multibyte characters were not retained")
	}
	if len([]byte(result.DOM)) > maxDOMBytes {
		t.Errorf("DOM byte size %d exceeds %d", len([]byte(result.DOM)), maxDOMBytes)
	}
}

func TestBoundedDOMSnapshotManyTinyNodesAndLargeAttributes(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	var dom strings.Builder
	dom.WriteString("<html><body>")
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&dom, `<div class="node-%d" data-custom="%s">item</div>`, i, strings.Repeat("a", 100))
	}
	dom.WriteString("</body></html>")

	result := collector.snapshotBounded("https://example.test/", boundedDOMSnapshot{
		DOM:          dom.String(),
		DOMTruncated: true,
	}, nil)

	if !result.DOMTruncated {
		t.Error("expected DOMTruncated to be preserved")
	}
	if len(result.DOM) > maxDOMBytes {
		t.Errorf("DOM length = %d, want at most %d", len(result.DOM), maxDOMBytes)
	}
}

func TestRecorderContextSeparationAndCancellation(t *testing.T) {
	t.Parallel()

	t.Run("cancelled begin or navigation context does not prevent fresh finish context", func(t *testing.T) {
		t.Parallel()
		source := &fakeCaptureSource{
			result: CaptureResult{FinalURL: "https://example.test/done", DOM: "<html>done</html>"},
		}
		recorder := newRecorder(source, func(*Recorder) {})

		// Simulate navigation context expiring or being cancelled
		navCtx, cancelNav := context.WithCancel(context.Background())
		cancelNav()
		if navCtx.Err() == nil {
			t.Fatal("navCtx must be cancelled")
		}

		// Fresh finish context succeeds
		finishCtx, cancelFinish := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFinish()
		result, err := recorder.Finish(finishCtx)
		if err != nil {
			t.Fatalf("Finish with fresh context failed: %v", err)
		}
		if result.DOM != "<html>done</html>" {
			t.Fatalf("Finish result DOM = %q, want <html>done</html>", result.DOM)
		}
	})

	t.Run("expired finish context returns cancellation without hanging", func(t *testing.T) {
		t.Parallel()
		source := &fakeCaptureSource{
			finishWithContext: true,
		}
		recorder := newRecorder(source, func(*Recorder) {})

		expiredFinishCtx, cancelExpired := context.WithCancel(context.Background())
		cancelExpired()

		result, err := recorder.Finish(expiredFinishCtx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Finish(expiredCtx) error = %v, want context.Canceled", err)
		}
		if result.DOM != "" {
			t.Fatalf("Finish(expiredCtx) returned unexpected DOM: %q", result.DOM)
		}
	})
}
