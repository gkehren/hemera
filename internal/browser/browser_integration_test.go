//go:build browser_integration

package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/networkguard"
)

func TestSandboxedChromiumLifecycle(t *testing.T) {
	config, explicit := integrationConfig(t)
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := client.Start(ctx)
	if err != nil {
		if !explicit {
			t.Skipf("sandboxed Chromium is unavailable: %v", err)
		}
		t.Fatalf("start explicitly configured Chromium: %v", err)
	}
	defer first.Close()
	second, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if version := first.Version(); version.Product == "" || version.ProtocolVersion == "" {
		t.Errorf("incomplete Browser.getVersion result: %#v", version)
	}
	firstRuntime := integrationRuntime(t, first)
	secondRuntime := integrationRuntime(t, second)
	if firstRuntime.initialURL != "about:blank" {
		t.Errorf("initial URL = %q, want about:blank", firstRuntime.initialURL)
	}
	if firstRuntime.profileDir == secondRuntime.profileDir {
		t.Errorf("sessions share profile %q", firstRuntime.profileDir)
	}
	for _, runtime := range []*chromedpSession{firstRuntime, secondRuntime} {
		if info, err := os.Stat(runtime.profileDir); err != nil || !info.IsDir() {
			t.Errorf("temporary profile %q is not an active directory: %v", runtime.profileDir, err)
		}
		assertChromiumArguments(t, runtime)
		if runtime.process == nil {
			t.Error("Chromium process is unavailable")
		}
	}

	assertStoppedAndCleaned(t, first, firstRuntime)
	assertStoppedAndCleaned(t, second, secondRuntime)
}

func TestSandboxedChromiumCapture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/start":
			http.Redirect(writer, request, "/page", http.StatusFound)
		case "/page":
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(writer, `<!doctype html><html><head><script defer src="/bootstrap.js"></script></head><body><main id="initial">ready</main></body></html>`)
		case "/bootstrap.js":
			writer.Header().Set("Content-Type", "text/javascript")
			_, _ = fmt.Fprint(writer, `
document.cookie = "browser_cookie=super-secret-cookie-value; SameSite=Lax";
const loaded = [];
loaded.push(new Promise((resolve, reject) => {
  const script = document.createElement("script");
  script.src = "/dynamic.js?credential=secret";
  script.onload = resolve;
  script.onerror = reject;
  document.head.appendChild(script);
}));
loaded.push(new Promise((resolve, reject) => {
  const frame = document.createElement("iframe");
  frame.src = "/frame?session=secret";
  frame.onload = resolve;
  frame.onerror = reject;
  document.body.appendChild(frame);
}));
loaded.push(fetch("/api?token=secret").then(response => response.text()));
Promise.all(loaded).then(() => {
  const marker = document.createElement("div");
  marker.id = "capture-complete";
  document.body.appendChild(marker);
});`)
		case "/dynamic.js":
			writer.Header().Set("Content-Type", "text/javascript")
			_, _ = fmt.Fprint(writer, `document.body.dataset.dynamicScript = "loaded";`)
		case "/frame":
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(writer, `<!doctype html><p id="frame-content">frame ready</p>`)
		case "/api":
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(writer, "api ready")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config, explicit := integrationConfig(t)
	targetURL := configureIntegrationFixture(t, &config, server)
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := client.Start(ctx)
	if err != nil {
		if !explicit {
			t.Skipf("sandboxed Chromium is unavailable: %v", err)
		}
		t.Fatalf("start explicitly configured Chromium: %v", err)
	}
	defer session.Close()
	if err := session.Navigate(ctx, server.URL+"/page"); !errors.Is(err, networkguard.ErrForbiddenDestination) {
		t.Fatalf("Navigate(loopback) error = %v, want ErrForbiddenDestination", err)
	}

	recorder, err := session.BeginCapture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Navigate(ctx, targetURL+"/start"); err != nil {
		t.Fatalf("navigate validated fixture: %v", err)
	}
	result, err := recorder.Finish(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if result.FinalURL != targetURL+"/page" {
		t.Errorf("FinalURL = %q, want %q", result.FinalURL, targetURL+"/page")
	}
	if result.DOMTruncated || !strings.Contains(result.DOM, `id="capture-complete"`) ||
		!strings.Contains(result.DOM, `data-dynamic-script="loaded"`) {
		t.Errorf("final DOM was not captured after dynamic actions: truncated=%t DOM=%q", result.DOMTruncated, result.DOM)
	}
	wantScripts := []string{targetURL + "/bootstrap.js", targetURL + "/dynamic.js?redacted"}
	if fmt.Sprint(result.ScriptURLs) != fmt.Sprint(wantScripts) {
		t.Errorf("ScriptURLs = %#v, want %#v", result.ScriptURLs, wantScripts)
	}
	if fmt.Sprint(result.IframeURLs) != fmt.Sprint([]string{targetURL + "/frame?redacted"}) {
		t.Errorf("IframeURLs = %#v", result.IframeURLs)
	}
	if fmt.Sprint(result.CookieNames) != fmt.Sprint([]string{"browser_cookie"}) {
		t.Errorf("CookieNames = %#v", result.CookieNames)
	}
	for _, path := range []string{"/start", "/page", "/bootstrap.js", "/dynamic.js?redacted", "/frame?redacted", "/api?redacted"} {
		if !captureContainsURL(result, targetURL+path) {
			t.Errorf("capture is missing traffic URL %q", targetURL+path)
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", result.Requests), "secret") ||
		strings.Contains(fmt.Sprintf("%#v", result.Responses), "secret") ||
		strings.Contains(fmt.Sprintf("%#v", result.CookieNames), "super-secret-cookie-value") {
		t.Fatalf("minimized traffic or cookies contain a secret: %#v", result)
	}
}

func TestSandboxedChromiumBoundedDOMAndRequestConcurrency(t *testing.T) {
	var activeResources atomic.Int32
	var peakResources atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/bounded-dom":
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(writer, `<html><body><script>document.body.append(document.createTextNode("x".repeat(8 * 1024 * 1024)))</script></body></html>`)
		case request.URL.Path == "/concurrency":
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(writer, `<html><body><img src="/held/one"><img src="/held/two"></body></html>`)
		case strings.HasPrefix(request.URL.Path, "/held/"):
			current := activeResources.Add(1)
			defer activeResources.Add(-1)
			for {
				peak := peakResources.Load()
				if current <= peak || peakResources.CompareAndSwap(peak, current) {
					break
				}
			}
			time.Sleep(75 * time.Millisecond)
			writer.Header().Set("Content-Type", "image/gif")
			_, _ = writer.Write([]byte("not-a-real-image"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	config, explicit := integrationConfig(t)
	targetURL := configureIntegrationFixture(t, &config, server)
	config.MaxConcurrentRequests = 1
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := client.Start(ctx)
	if err != nil {
		if !explicit {
			t.Skipf("sandboxed Chromium is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer session.Close()

	recorder, err := session.BeginCapture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Navigate(ctx, targetURL+"/bounded-dom"); err != nil {
		t.Fatal(err)
	}
	result, err := recorder.Finish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !result.DOMTruncated || len(result.DOM) > maxDOMBytes {
		t.Fatalf("DOM snapshot = %d bytes, truncated=%t", len(result.DOM), result.DOMTruncated)
	}
	if err := session.Navigate(ctx, targetURL+"/concurrency"); !errors.Is(err, ErrConcurrencyLimit) {
		t.Fatalf("concurrent resource navigation error = %v, want ErrConcurrencyLimit", err)
	}
	if peak := peakResources.Load(); peak > 1 {
		t.Fatalf("peak browser resource requests = %d, want at most 1", peak)
	}
}

func TestSandboxedChromiumNavigationLimits(t *testing.T) {
	var privateHits atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/many":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(writer, `<html><body><img src="/r/1"><img src="/r/2"><img src="/r/3"></body></html>`)
		case "/large":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(writer, strings.Repeat("x", 4096))
		case "/slow":
			select {
			case <-request.Context().Done():
			case <-time.After(2 * time.Second):
				_, _ = fmt.Fprint(writer, "late")
			}
		case "/private":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(writer, `<html><body><img src="%s/trap"></body></html>`, server.URL)
		case "/trap":
			privateHits.Add(1)
			_, _ = fmt.Fprint(writer, "unsafe")
		default:
			_, _ = fmt.Fprint(writer, "resource")
		}
	}))
	defer server.Close()

	tests := []struct {
		name      string
		path      string
		configure func(*Config)
		wantErr   error
	}{
		{"request budget", "/many", func(config *Config) { config.MaxRequests = 2 }, ErrRequestLimit},
		{"transfer budget", "/large", func(config *Config) { config.MaxTransferBytes = 1 }, ErrTransferLimit},
		{"navigation timeout", "/slow", func(config *Config) { config.NavigationTimeout = 150 * time.Millisecond }, context.DeadlineExceeded},
		{"private subresource", "/private", func(config *Config) {}, networkguard.ErrForbiddenDestination},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, explicit := integrationConfig(t)
			targetURL := configureIntegrationFixture(t, &config, server)
			test.configure(&config)
			client, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			session, err := client.Start(ctx)
			if err != nil {
				if !explicit {
					t.Skipf("sandboxed Chromium is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer session.Close()
			if err := session.Navigate(ctx, targetURL+test.path); !errors.Is(err, test.wantErr) {
				t.Fatalf("Navigate() error = %v, want %v", err, test.wantErr)
			}
			if test.path == "/private" && privateHits.Load() != 0 {
				t.Fatalf("private subresource reached loopback server %d times", privateHits.Load())
			}
		})
	}
}

func configureIntegrationFixture(t *testing.T, config *Config, server *httptest.Server) string {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	config.Resolver = navigationResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	config.Dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
	}
	return "http://fixture.test:" + port
}

func captureContainsURL(result CaptureResult, want string) bool {
	for _, request := range result.Requests {
		if request.URL == want {
			return true
		}
	}
	for _, response := range result.Responses {
		if response.URL == want {
			return true
		}
	}
	return false
}

func integrationConfig(t *testing.T) (Config, bool) {
	t.Helper()
	config := DefaultConfig()
	if path := os.Getenv("HEMERA_CHROMIUM_PATH"); path != "" {
		config.ExecutablePath = path
		return config, true
	}
	for _, name := range []string{
		"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome",
	} {
		if path, err := exec.LookPath(name); err == nil {
			config.ExecutablePath = path
			return config, false
		}
	}
	t.Skip("no local Chromium or Chrome executable found")
	return Config{}, false
}

func integrationRuntime(t *testing.T, session *Session) *chromedpSession {
	t.Helper()
	runtime, ok := session.backend.(*chromedpSession)
	if !ok {
		t.Fatalf("backend session type = %T, want *chromedpSession", session.backend)
	}
	return runtime
}

func assertChromiumArguments(t *testing.T, runtime *chromedpSession) {
	t.Helper()
	if len(runtime.commandLine) == 0 {
		t.Fatal("Browser.getBrowserCommandLine returned no arguments")
	}
	wants := map[string]bool{
		"--headless":                                                false,
		"--remote-debugging-address=127.0.0.1":                      false,
		"--remote-debugging-port=0":                                 false,
		"--user-data-dir=" + runtime.profileDir:                     false,
		"--proxy-bypass-list=<-loopback>":                           false,
		"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1":  false,
		"--disable-quic":                                            false,
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp": false,
	}
	proxyFound := false
	for _, argument := range runtime.commandLine {
		if strings.HasPrefix(argument, "--no-sandbox") {
			t.Errorf("Chromium sandbox was disabled by %q", argument)
		}
		if _, ok := wants[argument]; ok {
			wants[argument] = true
		}
		if strings.HasPrefix(argument, "--proxy-server=http://127.0.0.1:") {
			proxyFound = true
		}
	}
	for argument, found := range wants {
		if !found {
			t.Errorf("Chromium command line is missing %q", argument)
		}
	}
	if !proxyFound {
		t.Error("Chromium command line is missing the loopback safety proxy")
	}
}

func assertStoppedAndCleaned(t *testing.T, session *Session, runtime *chromedpSession) {
	t.Helper()
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.Done():
	case <-time.After(browserCloseTimeout + time.Second):
		t.Fatal("session Done did not close after shutdown deadline")
	}
	if _, err := os.Stat(runtime.profileDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary profile %q remains after Close: %v", runtime.profileDir, err)
	}
	if runtime.process == nil {
		return
	}
	if err := runtime.process.Signal(os.Interrupt); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("signal stopped Chromium process: %v, want os.ErrProcessDone", err)
	}
}
