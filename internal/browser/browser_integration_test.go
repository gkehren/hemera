//go:build browser_integration

package browser

import (
	"compress/gzip"
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
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/networkguard"
	"github.com/gkehren/hemera/pkg/model"
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
	corpus, err := loadFixtureCorpus(fixtureManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixtureCase := range corpus.manifest.Cases {
		fixtureCase := fixtureCase
		t.Run(fixtureCase.Name, func(t *testing.T) {
			fixture := newFixtureServer(t, corpus, map[string]http.HandlerFunc{
				"completion-barrier": func(writer http.ResponseWriter, _ *http.Request) {
					time.Sleep(250 * time.Millisecond)
					writer.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(writer, "// synthetic navigation completion barrier")
				},
			})
			config, explicit := integrationConfig(t)
			configureIntegrationFixture(t, &config, fixture.server)
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
			if err := session.Navigate(ctx, fixture.server.URL+"/negative/page"); !errors.Is(err, networkguard.ErrForbiddenDestination) {
				t.Fatalf("Navigate(loopback) error = %v, want ErrForbiddenDestination", err)
			}

			recorder, err := session.BeginCapture(ctx)
			if err != nil {
				t.Fatal(err)
			}
			entry := fixtureURL(fixture.baseURL, corpus.route(fixtureCase.EntryRoute), false)
			if fixtureCase.Name == "dynamic-sequential" {
				entry += "#fake-entry-fragment"
			}
			if err := session.Navigate(ctx, entry); err != nil {
				t.Fatalf("navigate validated fixture: %v", err)
			}
			result, err := recorder.Finish(ctx)
			if err != nil {
				t.Fatal(err)
			}

			assertFixtureCapture(t, fixture, fixtureCase, result)
		})
	}
}

func TestBrowserAnalyzerCapturesDelayedPostLoadActivity(t *testing.T) {
	corpus, err := loadFixtureCorpus(fixtureManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newFixtureServer(t, corpus, nil)
	config, explicit := integrationConfig(t)
	targetURL := configureIntegrationFixture(t, &config, fixture.server)
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	observation, err := analyzer.Observe(ctx, analysis.Target{URL: targetURL + "/delayed/page"})
	if err != nil {
		if !explicit {
			t.Skipf("sandboxed Chromium is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	wants := []struct {
		typeValue model.SignalType
		key       string
		value     string
	}{
		{model.SignalTypeNetworkRequest, "GET", targetURL + "/delayed/api"},
		{model.SignalTypeCookie, "late_browser_cookie", "fixture.test"},
		{model.SignalTypeScriptURL, "src", targetURL + "/delayed/injected.js"},
		{model.SignalTypePageContent, "dom", "late-browser-marker"},
	}
	for _, want := range wants {
		matched := false
		for _, signal := range observation.Signals {
			if signal.Type == want.typeValue && signal.Key == want.key && strings.Contains(signal.Value, want.value) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("missing delayed %s signal %q/%q in %#v", want.typeValue, want.key, want.value, observation.Signals)
		}
	}
}

func TestSandboxedChromiumPostLoadDeadlineAndBlockedChildTargets(t *testing.T) {
	corpus, err := loadFixtureCorpus(fixtureManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		path        string
		maxRequests int
		concurrency int
		wantErr     error
	}{
		{name: "worker request budget", path: "/limits/worker", maxRequests: 2, concurrency: 1, wantErr: ErrRequestLimit},
		{name: "worker concurrency budget", path: "/limits/worker", maxRequests: 10, concurrency: 1, wantErr: ErrConcurrencyLimit},
		{name: "worker blocked", path: "/limits/worker", maxRequests: 10, concurrency: 4, wantErr: ErrUnsupportedTarget},
		{name: "worker response byte budget", path: "/limits/worker-large", maxRequests: 10, concurrency: 4, wantErr: ErrTransferLimit},
		{name: "popup blocked", path: "/limits/popup", maxRequests: 10, concurrency: 4, wantErr: ErrUnsupportedTarget},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixtureServer(t, corpus, map[string]http.HandlerFunc{
				"large-worker-script": func(writer http.ResponseWriter, _ *http.Request) {
					_, _ = writer.Write([]byte("//" + strings.Repeat(" ", 64<<10)))
				},
			})
			config, explicit := integrationConfig(t)
			targetURL := configureIntegrationFixture(t, &config, fixture.server)
			config.MaxRequests = test.maxRequests
			config.MaxConcurrentRequests = test.concurrency
			if test.name == "worker response byte budget" {
				config.MaxTransferBytes = 4096
			}
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
			served, _ := fixture.snapshot()
			for _, forbidden := range []string{"limit-worker-api-one", "limit-worker-api-two", "limit-popup-child"} {
				if slices.Contains(served, forbidden) {
					t.Errorf("blocked child target reached %q: %#v", forbidden, served)
				}
			}
		})
	}

	t.Run("continuous traffic hard deadline", func(t *testing.T) {
		fixture := newFixtureServer(t, corpus, nil)
		config, explicit := integrationConfig(t)
		targetURL := configureIntegrationFixture(t, &config, fixture.server)
		config.PostLoadTimeout = 400 * time.Millisecond
		config.NetworkIdleTime = 80 * time.Millisecond
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
		started := time.Now()
		if err := session.Navigate(ctx, targetURL+"/limits/continuous"); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(started)
		if elapsed < 350*time.Millisecond || elapsed > 2*time.Second {
			t.Errorf("continuous observation duration = %s, want bounded near hard deadline", elapsed)
		}
	})

	t.Run("post-load request budget", func(t *testing.T) {
		fixture := newFixtureServer(t, corpus, nil)
		config, explicit := integrationConfig(t)
		targetURL := configureIntegrationFixture(t, &config, fixture.server)
		config.MaxRequests = 3
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
		if err := session.Navigate(ctx, targetURL+"/limits/continuous"); !errors.Is(err, ErrRequestLimit) {
			t.Fatalf("post-load request error = %v, want ErrRequestLimit", err)
		}
	})

	t.Run("long polling hard deadline", func(t *testing.T) {
		fixture := newFixtureServer(t, corpus, map[string]http.HandlerFunc{
			"long-poll": func(writer http.ResponseWriter, request *http.Request) {
				select {
				case <-request.Context().Done():
				case <-time.After(2 * time.Second):
					_, _ = writer.Write([]byte("late"))
				}
			},
		})
		config, explicit := integrationConfig(t)
		targetURL := configureIntegrationFixture(t, &config, fixture.server)
		config.PostLoadTimeout = 400 * time.Millisecond
		config.NetworkIdleTime = 80 * time.Millisecond
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
		started := time.Now()
		if err := session.Navigate(ctx, targetURL+"/limits/long-poll"); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed < 350*time.Millisecond || elapsed > 2*time.Second {
			t.Errorf("long-poll observation duration = %s, want bounded near hard deadline", elapsed)
		}
	})
}

func TestSandboxedChromiumBoundedDOMAndRequestConcurrency(t *testing.T) {
	corpus, err := loadFixtureCorpus(fixtureManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var activeResources atomic.Int32
	var peakResources atomic.Int32
	fixture := newFixtureServer(t, corpus, map[string]http.HandlerFunc{
		"held-resource": func(writer http.ResponseWriter, _ *http.Request) {
			current := activeResources.Add(1)
			defer activeResources.Add(-1)
			for {
				peak := peakResources.Load()
				if current <= peak || peakResources.CompareAndSwap(peak, current) {
					break
				}
			}
			time.Sleep(75 * time.Millisecond)
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("not-a-real-image"))
		},
	})

	config, explicit := integrationConfig(t)
	targetURL := configureIntegrationFixture(t, &config, fixture.server)
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
	if err := session.Navigate(ctx, targetURL+"/limits/bounded-dom"); err != nil {
		t.Fatal(err)
	}
	result, err := recorder.Finish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !result.DOMTruncated || len(result.DOM) > maxDOMBytes {
		t.Fatalf("DOM snapshot = %d bytes, truncated=%t", len(result.DOM), result.DOMTruncated)
	}
	recorder, err = session.BeginCapture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Navigate(ctx, targetURL+"/limits/large-postload-dom"); err != nil {
		t.Fatal(err)
	}
	postLoadResult, err := recorder.Finish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !postLoadResult.DOMTruncated || len(postLoadResult.DOM) > maxDOMBytes {
		t.Fatalf("post-load DOM snapshot = %d bytes, truncated=%t", len(postLoadResult.DOM), postLoadResult.DOMTruncated)
	}
	if err := session.Navigate(ctx, targetURL+"/limits/concurrency"); !errors.Is(err, ErrConcurrencyLimit) {
		t.Fatalf("concurrent resource navigation error = %v, want ErrConcurrencyLimit", err)
	}
	if peak := peakResources.Load(); peak > 1 {
		t.Fatalf("peak browser resource requests = %d, want at most 1", peak)
	}
}

func TestSandboxedChromiumNavigationLimits(t *testing.T) {
	corpus, err := loadFixtureCorpus(fixtureManifestPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		configure func(*Config)
		wantErr   error
	}{
		{"request budget", "/limits/many", func(config *Config) { config.MaxRequests = 2 }, ErrRequestLimit},
		{"transfer budget", "/limits/large", func(config *Config) { config.MaxTransferBytes = 1 }, ErrTransferLimit},
		{"navigation timeout", "/limits/slow", func(config *Config) { config.NavigationTimeout = 150 * time.Millisecond }, context.DeadlineExceeded},
		{"private subresource", "/limits/private", func(config *Config) {}, networkguard.ErrForbiddenDestination},
		{"recursive iframe", "/limits/recursive-frame", func(config *Config) { config.MaxRequests = 4 }, ErrRequestLimit},
		{"WebSocket", "/limits/websocket", func(config *Config) {}, networkguard.ErrInvalidURL},
		{"compressed decoded bytes", "/limits/compressed", func(config *Config) { config.MaxTransferBytes = 2048 }, ErrTransferLimit},
		{"download denied", "/limits/download", func(config *Config) {}, ErrUnsupportedTarget},
		{"redirect loop", "/limits/redirect-loop", func(config *Config) { config.MaxRedirects = 2 }, ErrRedirectLimit},
		{"credential redirect", "/limits/credential-redirect", func(config *Config) {}, networkguard.ErrInvalidURL},
		{"post-load redirect budget", "/limits/postload-redirect", func(config *Config) { config.MaxRedirects = 2 }, ErrRedirectLimit},
		{"post-load transfer budget", "/limits/postload-transfer", func(config *Config) { config.MaxTransferBytes = 4096 }, ErrTransferLimit},
		{"post-load decoded budget", "/limits/postload-decoded", func(config *Config) { config.MaxTransferBytes = 8192 }, ErrTransferLimit},
		{"post-load concurrency budget", "/limits/postload-concurrency", func(config *Config) { config.MaxConcurrentRequests = 1 }, ErrConcurrencyLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var privateHits atomic.Int32
			var fixture *fixtureServer
			fixture = newFixtureServer(t, corpus, map[string]http.HandlerFunc{
				"slow-response": func(writer http.ResponseWriter, request *http.Request) {
					select {
					case <-request.Context().Done():
					case <-time.After(2 * time.Second):
						writer.WriteHeader(http.StatusOK)
						_, _ = fmt.Fprint(writer, "late")
					}
				},
				"private-subresource": func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprintf(writer, `<html><body><img src="%s/limits/trap"></body></html>`, fixture.server.URL)
				},
				"private-trap": func(writer http.ResponseWriter, _ *http.Request) {
					privateHits.Add(1)
					writer.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprint(writer, "unsafe")
				},
				"compressed-response": func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Content-Encoding", "gzip")
					archive := gzip.NewWriter(writer)
					_, _ = archive.Write([]byte(strings.Repeat("x", 64<<10)))
					_ = archive.Close()
				},
				"redirect-loop": func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Location", "/limits/redirect-loop")
					writer.WriteHeader(http.StatusFound)
				},
				"credential-redirect": func(writer http.ResponseWriter, request *http.Request) {
					writer.Header().Set("Location", "http://user:password@"+request.Host+"/limits/ping")
					writer.WriteHeader(http.StatusFound)
				},
				"large-response": func(writer http.ResponseWriter, _ *http.Request) {
					_, _ = writer.Write([]byte(strings.Repeat("x", 64<<10)))
				},
			})
			config, explicit := integrationConfig(t)
			targetURL := configureIntegrationFixture(t, &config, fixture.server)
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
			if test.path == "/limits/download" {
				runtime := integrationRuntime(t, session)
				err := filepath.WalkDir(runtime.profileDir, func(path string, entry os.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if entry.Name() == "synthetic.bin" {
						t.Errorf("download was written to %q", path)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if test.path == "/limits/private" && privateHits.Load() != 0 {
				t.Fatalf("private subresource reached loopback server %d times", privateHits.Load())
			}
		})
	}
}

func assertFixtureCapture(t *testing.T, fixture *fixtureServer, fixtureCase fixtureCase, result CaptureResult) {
	t.Helper()
	wantFinal := fixtureURL(fixture.baseURL, fixture.corpus.route(fixtureCase.FinalRoute), true)
	if result.FinalURL != wantFinal {
		t.Errorf("FinalURL = %q, want %q", result.FinalURL, wantFinal)
	}
	if result.DOMTruncated {
		t.Error("final fixture DOM was unexpectedly truncated")
	}
	for _, marker := range fixtureCase.DOMMarkers {
		if !strings.Contains(result.DOM, marker) {
			t.Errorf("final DOM is missing marker %q", marker)
		}
	}
	wantScripts := fixtureResourceURLs(fixture.baseURL, fixtureCase.Scripts)
	if fmt.Sprint(result.ScriptURLs) != fmt.Sprint(wantScripts) {
		t.Errorf("ScriptURLs = %#v, want %#v", result.ScriptURLs, wantScripts)
	}
	wantIframes := fixtureResourceURLs(fixture.baseURL, fixtureCase.Iframes)
	if fmt.Sprint(result.IframeURLs) != fmt.Sprint(wantIframes) {
		t.Errorf("IframeURLs = %#v, want %#v", result.IframeURLs, wantIframes)
	}
	gotCookieNames := make([]string, 0, len(result.Cookies))
	for _, cookie := range result.Cookies {
		gotCookieNames = append(gotCookieNames, cookie.Name)
		if strings.TrimPrefix(cookie.Domain, ".") != fixture.corpus.manifest.Host {
			t.Errorf("cookie provenance = %#v, want fixture host", cookie)
		}
	}
	if fmt.Sprint(gotCookieNames) != fmt.Sprint(fixtureCase.Cookies) {
		t.Errorf("cookie names = %#v, want exclusively %#v", gotCookieNames, fixtureCase.Cookies)
	}

	wantURLs := make([]string, 0, len(fixtureCase.Traffic))
	wantStatuses := make([]int64, 0, len(fixtureCase.Traffic))
	for _, routeName := range fixtureCase.Traffic {
		route := fixture.corpus.route(routeName)
		wantURLs = append(wantURLs, fixtureURL(fixture.baseURL, route, true))
		wantStatuses = append(wantStatuses, int64(route.Status))
	}
	gotRequestURLs := make([]string, 0, len(result.Requests))
	for _, request := range result.Requests {
		gotRequestURLs = append(gotRequestURLs, request.URL)
		assertDeclaredCaptureURL(t, fixture, request.URL)
	}
	gotResponses := make(map[string][]int64, len(result.Responses))
	for _, response := range result.Responses {
		gotResponses[response.URL] = append(gotResponses[response.URL], response.Status)
		assertDeclaredCaptureURL(t, fixture, response.URL)
	}
	if fmt.Sprint(gotRequestURLs) != fmt.Sprint(wantURLs) {
		t.Errorf("request order = %#v, want %#v", gotRequestURLs, wantURLs)
	}
	for index, wantURL := range wantURLs {
		statuses := gotResponses[wantURL]
		if len(statuses) != 1 || statuses[0] != wantStatuses[index] {
			t.Errorf("response for %q = %#v, want [%d]", wantURL, statuses, wantStatuses[index])
		}
		delete(gotResponses, wantURL)
	}
	if len(gotResponses) != 0 {
		t.Errorf("capture contains unexpected responses: %#v", gotResponses)
	}
	served, unexpected := fixture.snapshot()
	if fmt.Sprint(served) != fmt.Sprint(fixtureCase.Traffic) {
		t.Errorf("fixture server request order = %#v, want %#v", served, fixtureCase.Traffic)
	}
	if len(unexpected) != 0 {
		t.Errorf("fixture server received undeclared requests: %#v", unexpected)
	}

	metadata := fmt.Sprintf("requests=%#v responses=%#v scripts=%#v iframes=%#v cookies=%#v final=%q",
		result.Requests, result.Responses, result.ScriptURLs, result.IframeURLs, result.Cookies, result.FinalURL)
	for _, forbidden := range fixtureCase.ForbiddenMetadata {
		if strings.Contains(metadata, forbidden) {
			t.Errorf("minimized capture metadata contains synthetic secret or fragment %q: %s", forbidden, metadata)
		}
	}
}

func fixtureURL(baseURL string, route *fixtureRoute, clean bool) string {
	rawURL := baseURL + route.Path
	if route.RawQuery != "" {
		if clean {
			return rawURL + "?redacted"
		}
		rawURL += "?" + route.RawQuery
	}
	return rawURL
}

func fixtureResourceURLs(baseURL string, paths []string) []string {
	urls := make([]string, len(paths))
	for index, resourcePath := range paths {
		urls[index] = baseURL + resourcePath
	}
	return urls
}

func assertDeclaredCaptureURL(t *testing.T, fixture *fixtureServer, rawURL string) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Errorf("parse captured URL %q: %v", rawURL, err)
		return
	}
	base, _ := url.Parse(fixture.baseURL)
	if parsed.Scheme != base.Scheme || parsed.Host != base.Host {
		t.Errorf("captured URL has undeclared destination %q", rawURL)
		return
	}
	for _, route := range fixture.corpus.manifest.Routes {
		if route.Path == parsed.Path {
			return
		}
	}
	t.Errorf("captured URL has undeclared route %q", rawURL)
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

func integrationConfig(t *testing.T) (Config, bool) {
	t.Helper()
	config := DefaultConfig()
	config.StartupTimeout = maxStartupTimeout
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
