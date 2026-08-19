package httpanalyzer

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/networkguard"
	"github.com/gkehren/hemera/pkg/model"
)

type testResolver func(context.Context, string, string) ([]netip.Addr, error)

func (f testResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func publicResolver(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func analyzerForServer(t *testing.T, serverURL string, change func(*Config)) *Analyzer {
	t.Helper()
	local, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Resolver = testResolver(publicResolver)
	config.Dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, local.Host)
	}
	if change != nil {
		change(&config)
	}
	analyzer, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer
}

func TestNewValidatesConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"total timeout", func(c *Config) { c.TotalTimeout = 0 }},
		{"connect timeout", func(c *Config) { c.ConnectTimeout = 0 }},
		{"TLS timeout", func(c *Config) { c.TLSHandshakeTimeout = 0 }},
		{"header timeout", func(c *Config) { c.ResponseHeaderTimeout = 0 }},
		{"redirects", func(c *Config) { c.MaxRedirects = -1 }},
		{"body bytes", func(c *Config) { c.MaxBodyBytes = 0 }},
		{"header bytes", func(c *Config) { c.MaxResponseHeaderBytes = 0 }},
		{"User-Agent", func(c *Config) { c.UserAgent = " " }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			config := DefaultConfig()
			tt.change(&config)
			if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestAnalyzeDoesNotFetchSubresources(t *testing.T) {
	t.Parallel()
	subresourceRequests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<script src="/loaded.js"></script>`)
	})
	mux.HandleFunc("/loaded.js", func(http.ResponseWriter, *http.Request) {
		subresourceRequests++
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	if _, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/"); err != nil {
		t.Fatal(err)
	}
	if subresourceRequests != 0 {
		t.Errorf("subresource requests = %d, want 0", subresourceRequests)
	}
}

func TestAnalyzeAppliesFirstValidBaseToEntireDocument(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<script src="before.js"></script>`+
			`<base href="javascript:void(0)"><base href="/assets/">`+
			`<base href="/ignored/"><iframe src="after.html"></iframe>`)
	}))
	defer server.Close()

	result, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/page/")
	if err != nil {
		t.Fatal(err)
	}
	var resources []string
	for _, signal := range result.Signals {
		if signal.Type == model.SignalTypeScriptURL || signal.Type == model.SignalTypeIframeURL {
			resources = append(resources, signal.Value)
		}
	}
	if got, want := strings.Join(resources, "|"), "http://example.test/assets/before.js|http://example.test/assets/after.html"; got != want {
		t.Errorf("resource URLs = %q, want %q", got, want)
	}
}

func TestAnalyzeCollectsRedirectHTTPAndHTMLSignals(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "Hemera/") {
			t.Errorf("User-Agent = %q", got)
		}
		w.Header().Set("Location", "/final?session=top-secret")
		w.Header().Set("X-Api-Token", "header-secret")
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "cookie-secret"})
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
		w.Header().Set("X-Observed", "safe-value")
		body := []byte("<html><head><base href='ftp://invalid/'><base href='/assets/'></head><body>caf\xe9" +
			"<script src='app.js?key=secret'></script><script src='app.js?key=secret'></script>" +
			"<script src='https://cdn.example.test/lib.js'></script>" +
			"<iframe src='https://widgets.example.org/frame?token=secret'></iframe>" +
			"<iframe src='javascript:alert(1)'></iframe></body></html>")
		_, _ = w.Write(body)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/start?auth=secret")
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || result.FinalURL != "http://example.test/final?redacted" {
		t.Errorf("final status/URL = %d, %q", result.StatusCode, result.FinalURL)
	}
	if result.RequestedURL != "http://example.test/start?redacted" {
		t.Errorf("requested URL = %q", result.RequestedURL)
	}
	if len(result.Redirects) != 1 || result.Redirects[0].To != "http://example.test/final?redacted" {
		t.Fatalf("redirects = %#v", result.Redirects)
	}

	var types []model.SignalType
	var scriptValues, iframeValues, resourceHosts []string
	var pageContent string
	for _, signal := range result.Signals {
		if err := signal.Validate(); err != nil {
			t.Errorf("invalid signal %#v: %v", signal, err)
		}
		if signal.Source != source {
			t.Errorf("signal source = %q", signal.Source)
		}
		types = append(types, signal.Type)
		switch signal.Type {
		case model.SignalTypeScriptURL:
			scriptValues = append(scriptValues, signal.Value)
		case model.SignalTypeIframeURL:
			iframeValues = append(iframeValues, signal.Value)
		case model.SignalTypeResourceHost:
			resourceHosts = append(resourceHosts, signal.Value)
		case model.SignalTypePageContent:
			pageContent = signal.Value
		}
	}
	if got, want := strings.Join(scriptValues, "|"), "http://example.test/assets/app.js?redacted|https://cdn.example.test/lib.js"; got != want {
		t.Errorf("script URLs = %q, want %q", got, want)
	}
	if got, want := strings.Join(iframeValues, "|"), "https://widgets.example.org/frame?redacted"; got != want {
		t.Errorf("iframe URLs = %q, want %q", got, want)
	}
	if got, want := strings.Join(resourceHosts, "|"), "widgets.example.org"; got != want {
		t.Errorf("resource hosts = %q, want %q", got, want)
	}
	if !strings.Contains(pageContent, "café") {
		t.Errorf("page content did not decode charset: %q", pageContent)
	}
	serialized := result.RequestedURL + result.FinalURL + pageContent
	for _, signal := range result.Signals {
		serialized += signal.Key + signal.Value + signal.URL
	}
	for _, secret := range []string{"top-secret", "header-secret", "cookie-secret"} {
		if strings.Contains(serialized, secret) {
			t.Errorf("result retained secret %q", secret)
		}
	}
	if len(types) == 0 || types[0] != model.SignalTypeNetworkResponse {
		t.Errorf("signal order starts with %v", types)
	}
}

func TestAnalyzeHandlesGzipAndTruncation(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html")
		writer := gzip.NewWriter(w)
		_, _ = io.WriteString(writer, "<html><body>"+strings.Repeat("x", 256)+"</body></html>")
		_ = writer.Close()
	}))
	defer server.Close()
	result, err := analyzerForServer(t, server.URL, func(config *Config) { config.MaxBodyBytes = 64 }).Analyze(context.Background(), "http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if !result.BodyTruncated || len(result.Warnings) == 0 {
		t.Errorf("truncated/warnings = %t/%v", result.BodyTruncated, result.Warnings)
	}
	foundPage := false
	for _, signal := range result.Signals {
		foundPage = foundPage || signal.Type == model.SignalTypePageContent
	}
	if !foundPage {
		t.Error("truncated HTML prefix was not analyzed")
	}
}

func TestAnalyzeKeepsHTTPSignalsOnCharsetWarning(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=definitely-unknown")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer server.Close()
	result, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("warnings = nil, want charset warning")
	}
	if len(result.Signals) == 0 || result.Signals[0].Type != model.SignalTypeNetworkResponse {
		t.Errorf("HTTP signals were lost: %#v", result.Signals)
	}
}

func TestAnalyzeRejectsOversizedResponseHeaders(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("x", 4096))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, err := analyzerForServer(t, server.URL, func(config *Config) {
		config.MaxResponseHeaderBytes = 512
	}).Analyze(context.Background(), "http://example.test/")
	if err == nil {
		t.Fatal("Analyze() error = nil, want oversized-header failure")
	}
}

func TestAnalyzeTreatsBodyReadFailureAsBlocking(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "short")
	}))
	defer server.Close()
	_, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/")
	if err == nil || !strings.Contains(err.Error(), "read response body") {
		t.Fatalf("Analyze() error = %v, want body read failure", err)
	}
}

func TestAnalyzeTreatsNon2xxAsResult(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not here", http.StatusNotFound)
	}))
	defer server.Close()
	result, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/missing")
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d", result.StatusCode)
	}
}

func TestAnalyzeRejectsInitialAndRedirectDestinations(t *testing.T) {
	t.Parallel()
	analyzer, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, err = analyzer.Analyze(context.Background(), "http://127.0.0.1/")
	if !errors.Is(err, ErrInitialTarget) || !errors.Is(err, networkguard.ErrForbiddenDestination) {
		t.Fatalf("initial private error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://private.test/secret")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	local, _ := url.Parse(server.URL)
	config := DefaultConfig()
	config.Resolver = testResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "private.test" {
			return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
		}
		return publicResolver(context.Background(), "", host)
	})
	config.Dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, local.Host)
	}
	analyzer, _ = New(config)
	_, err = analyzer.Analyze(context.Background(), "http://example.test/")
	if errors.Is(err, ErrInitialTarget) || !errors.Is(err, networkguard.ErrForbiddenDestination) {
		t.Fatalf("redirect private error = %v", err)
	}
}

func TestAnalyzeEnforcesRedirectLimit(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Path+"x")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	_, err := analyzerForServer(t, server.URL, func(config *Config) { config.MaxRedirects = 2 }).Analyze(context.Background(), "http://example.test/a")
	if !errors.Is(err, networkguard.ErrTooManyRedirects) {
		t.Fatalf("error = %v, want ErrTooManyRedirects", err)
	}
}

func TestAnalyzeStopsRedirectLoop(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			http.Redirect(w, r, "/b", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/a", http.StatusFound)
	}))
	defer server.Close()

	_, err := analyzerForServer(t, server.URL, func(config *Config) { config.MaxRedirects = 3 }).Analyze(context.Background(), "http://example.test/a")
	if !errors.Is(err, networkguard.ErrTooManyRedirects) {
		t.Fatalf("error = %v, want ErrTooManyRedirects", err)
	}
}

func TestAnalyzeDoesNotSendOrRetainFragment(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "fragment-secret") {
			t.Errorf("request URI retained fragment: %q", r.RequestURI)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/path#fragment-secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.RequestedURL+result.FinalURL, "fragment-secret") {
		t.Errorf("result retained fragment: %#v", result)
	}
}

func TestAnalyzeTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { close(release); server.Close() }()
	_, err := analyzerForServer(t, server.URL, func(config *Config) {
		config.ResponseHeaderTimeout = 20 * time.Millisecond
		config.TotalTimeout = time.Second
	}).Analyze(context.Background(), "http://example.test/")
	if err == nil {
		t.Fatal("Analyze() error = nil, want timeout")
	}
}

func TestAnalyzeIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	result, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d", result.StatusCode)
	}
}

func TestAnalyzePreservesTLSServerName(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var serverName string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		serverName = info.ServerName
		mu.Unlock()
		return nil, nil
	}}
	server.StartTLS()
	defer server.Close()
	rootTLS := server.Client().Transport.(*http.Transport).TLSClientConfig
	analyzer := analyzerForServer(t, server.URL, func(config *Config) { config.TLSConfig = rootTLS })
	if _, err := analyzer.Analyze(context.Background(), "https://example.com/"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if serverName != "example.com" {
		t.Errorf("TLS ServerName = %q", serverName)
	}
}
