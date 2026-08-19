package browser

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/gkehren/hemera/internal/networkguard"
)

func TestSessionNavigateLifecycle(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := newFakeNavigationBackend(func(ctx context.Context, rawURL string) error {
		if rawURL != "https://example.test/" {
			t.Errorf("raw URL = %q", rawURL)
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	session := newSession(Version{}, backend, func() {})
	result := make(chan error, 1)
	go func() { result <- session.Navigate(context.Background(), "https://example.test/") }()
	<-entered
	if err := session.Navigate(context.Background(), "https://example.test/"); !errors.Is(err, ErrNavigationActive) {
		t.Fatalf("concurrent Navigate() error = %v, want ErrNavigationActive", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if backend.navigateCalls.Load() != 1 {
		t.Errorf("navigate calls = %d, want 1", backend.navigateCalls.Load())
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Navigate(context.Background(), "https://example.test/"); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Navigate() after Close error = %v, want ErrSessionClosed", err)
	}
}

func TestBrowserRequestTrackerBoundsLifecycles(t *testing.T) {
	t.Parallel()
	tracker := newBrowserRequestTracker(1)
	stopped := make(chan struct{})
	if err := tracker.acquire(context.Background(), stopped, network.RequestID("first")); err != nil {
		t.Fatal(err)
	}
	if err := tracker.acquire(context.Background(), stopped, network.RequestID("first")); err != nil {
		t.Fatalf("redirect in the same network lifecycle acquired another slot: %v", err)
	}

	if err := tracker.acquire(context.Background(), stopped, network.RequestID("second")); !errors.Is(err, ErrConcurrencyLimit) {
		t.Fatalf("second request acquire error = %v, want ErrConcurrencyLimit", err)
	}

	tracker.release(network.RequestID("first"))
	if err := tracker.acquire(context.Background(), stopped, network.RequestID("second")); err != nil {
		t.Fatalf("second request did not acquire after the first completed: %v", err)
	}
	tracker.release(network.RequestID("second"))
}

func TestBrowserRequestTrackerRejectsAfterNavigationStops(t *testing.T) {
	t.Parallel()
	tracker := newBrowserRequestTracker(1)
	stopped := make(chan struct{})
	if err := tracker.acquire(context.Background(), stopped, network.RequestID("first")); err != nil {
		t.Fatal(err)
	}
	close(stopped)
	if err := tracker.acquire(context.Background(), stopped, network.RequestID("second")); !errors.Is(err, ErrConcurrencyLimit) {
		t.Fatalf("stopped acquire error = %v, want ErrConcurrencyLimit", err)
	}
	tracker.releaseAll()
}

func TestWaitForNetworkQuietEndsEarlyAndEnforcesHardDeadline(t *testing.T) {
	t.Run("quiet page", func(t *testing.T) {
		tracker := newBrowserRequestTracker(1)
		started := time.Now()
		if err := waitForNetworkQuiet(context.Background(), make(chan struct{}), tracker, 20*time.Millisecond, 200*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed >= 150*time.Millisecond {
			t.Errorf("quiet wait = %s, want early idle completion", elapsed)
		}
	})

	t.Run("continuous activity", func(t *testing.T) {
		tracker := newBrowserRequestTracker(1)
		activity := make(chan struct{}, 1)
		stop := make(chan struct{})
		go func() {
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case activity <- struct{}{}:
				case <-stop:
					return
				case <-ticker.C:
				}
			}
		}()
		started := time.Now()
		err := waitForNetworkQuiet(context.Background(), activity, tracker, 20*time.Millisecond, 80*time.Millisecond)
		close(stop)
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed < 65*time.Millisecond || elapsed > 250*time.Millisecond {
			t.Errorf("continuous wait = %s, want hard-deadline completion", elapsed)
		}
	})

	t.Run("long polling", func(t *testing.T) {
		tracker := newBrowserRequestTracker(1)
		stopped := make(chan struct{})
		if err := tracker.acquire(context.Background(), stopped, network.RequestID("long-poll")); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if err := waitForNetworkQuiet(context.Background(), make(chan struct{}), tracker, 15*time.Millisecond, 60*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		tracker.releaseAll()
		if elapsed := time.Since(started); elapsed < 50*time.Millisecond || elapsed > 200*time.Millisecond {
			t.Errorf("long-poll wait = %s, want hard-deadline completion", elapsed)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := waitForNetworkQuiet(ctx, make(chan struct{}), newBrowserRequestTracker(1), time.Second, 2*time.Second)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait error = %v, want context.Canceled", err)
		}
	})
}

func TestSessionNavigateValidatesContextAndPreservesError(t *testing.T) {
	t.Parallel()
	wantErr := networkguard.ErrForbiddenDestination
	backend := newFakeNavigationBackend(func(context.Context, string) error { return wantErr })
	session := newSession(Version{}, backend, func() {})
	if err := session.Navigate(nil, "https://example.test/"); err == nil {
		t.Fatal("Navigate(nil) error = nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.Navigate(ctx, "https://example.test/"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Navigate(canceled) error = %v", err)
	}
	if err := session.Navigate(context.Background(), "https://example.test/"); !errors.Is(err, wantErr) {
		t.Fatalf("Navigate() error = %v, want %v", err, wantErr)
	}
	if backend.navigateCalls.Load() != 1 {
		t.Errorf("navigate calls = %d, want 1", backend.navigateCalls.Load())
	}
	_ = session.Close()
}

func TestNavigationBudgetLimits(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.MaxRequests = 2
	config.MaxRedirects = 1
	config.MaxTransferBytes = 10
	config.MaxConcurrentRequests = 1
	budget := newNavigationBudget(config)
	defer budget.stop()
	if err := budget.authorize("https://example.test/", false); err != nil {
		t.Fatal(err)
	}
	if err := budget.authorize("https://example.test/next", true); err != nil {
		t.Fatal(err)
	}
	if err := budget.authorize("https://example.test/third", false); !errors.Is(err, ErrRequestLimit) {
		t.Errorf("third request error = %v, want ErrRequestLimit", err)
	}

	redirectBudget := newNavigationBudget(config)
	defer redirectBudget.stop()
	if err := redirectBudget.authorize("https://example.test/", true); err != nil {
		t.Fatal(err)
	}
	if err := redirectBudget.authorize("https://example.test/", true); !errors.Is(err, ErrRedirectLimit) {
		t.Errorf("second redirect error = %v, want ErrRedirectLimit", err)
	}
	if err := budget.consume(10); err != nil {
		t.Fatal(err)
	}
	if err := budget.consume(1); !errors.Is(err, ErrTransferLimit) {
		t.Errorf("transfer overflow error = %v, want ErrTransferLimit", err)
	}
	if err := budget.consumeDecoded(10); err != nil {
		t.Fatal(err)
	}
	if err := budget.consumeDecoded(1); !errors.Is(err, ErrTransferLimit) {
		t.Errorf("decoded overflow error = %v, want ErrTransferLimit", err)
	}
	if err := budget.authorize("file:///private", false); !errors.Is(err, networkguard.ErrInvalidURL) {
		t.Errorf("non-web request error = %v, want ErrInvalidURL", err)
	}
	longURL := "https://example.test/" + strings.Repeat("x", maxBrowserURLBytes)
	if err := budget.authorize(longURL, false); !errors.Is(err, networkguard.ErrInvalidURL) {
		t.Errorf("oversized URL error = %v, want ErrInvalidURL", err)
	}
	if err := budget.authorizeProxy(); err != nil {
		t.Fatal(err)
	}
	if err := budget.authorizeProxy(); err != nil {
		t.Fatal(err)
	}
	if err := budget.authorizeProxy(); !errors.Is(err, ErrRequestLimit) {
		t.Errorf("third proxy request error = %v, want ErrRequestLimit", err)
	}
}

func TestParseBrowserURLRejectsAdversarialNavigationInputs(t *testing.T) {
	t.Parallel()
	tests := []string{
		"file:///etc/passwd",
		"ws://example.test/socket",
		"https://user:password@example.test/",
		"https://example.test/%zz",
		"not a URL",
		"https://example.test/" + strings.Repeat("x", maxBrowserURLBytes),
	}
	for _, rawURL := range tests {
		if _, err := parseBrowserURL(rawURL); !errors.Is(err, networkguard.ErrInvalidURL) {
			t.Errorf("parseBrowserURL(%q) error = %v, want ErrInvalidURL", rawURL, err)
		}
	}
}

func TestSafeProxyPinsValidatedConnections(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "safe response")
	}))
	defer server.Close()
	config, target, dialed := proxyTestConfig(t, server, nil)
	proxy, err := newSafeProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	budget, normalized, err := proxy.begin(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.end(budget)
	response, err := proxyClient(t, proxy).Get(normalized)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if failure := budget.failure(); failure != nil {
		t.Fatalf("proxy budget failure = %v", failure)
	}
	if got := dialed.Load().(string); !strings.HasPrefix(got, "8.8.8.8:") {
		t.Errorf("dialed address = %q, want validated public IP", got)
	}
}

func TestSafeProxyPinsHTTPSConnectTunnel(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "secure response")
	}))
	defer server.Close()
	config, _, dialed := proxyTestConfig(t, server, nil)
	proxy, err := newSafeProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://example.com:" + port
	budget, _, err := proxy.begin(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.end(budget)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	proxyURL, _ := url.Parse("http://" + proxy.address())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
	}}
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if failure := budget.failure(); failure != nil {
		t.Fatalf("proxy budget failure = %v", failure)
	}
	if got := dialed.Load().(string); !strings.HasPrefix(got, "8.8.8.8:") {
		t.Errorf("dialed address = %q, want validated public IP", got)
	}
}

func TestSafeProxyRejectsPrivateRedirectDestination(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			http.Redirect(writer, request, "http://private.test"+request.URL.RequestURI(), http.StatusFound)
			return
		}
		_, _ = io.WriteString(writer, "unexpected")
	}))
	defer server.Close()
	config, target, _ := proxyTestConfig(t, server, func(host string) []netip.Addr {
		if host == "private.test" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	})
	proxy, err := newSafeProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	budget, _, err := proxy.begin(context.Background(), target+"/start")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.end(budget)
	response, err := proxyClient(t, proxy).Get(target + "/start")
	if err == nil && response != nil {
		response.Body.Close()
	}
	if failure := budget.failure(); !errors.Is(failure, networkguard.ErrForbiddenDestination) {
		t.Fatalf("proxy failure = %v, want ErrForbiddenDestination", failure)
	}
}

func TestSafeProxyRejectsDNSRebinding(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "unexpected")
	}))
	defer server.Close()
	var resolveCalls atomic.Int32
	config, target, _ := proxyTestConfig(t, server, func(string) []netip.Addr {
		if resolveCalls.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	})
	proxy, err := newSafeProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	budget, _, err := proxy.begin(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.end(budget)
	response, err := proxyClient(t, proxy).Get(target)
	if err == nil && response != nil {
		response.Body.Close()
	}
	if failure := budget.failure(); !errors.Is(failure, networkguard.ErrForbiddenDestination) {
		t.Fatalf("proxy failure = %v, want ErrForbiddenDestination", failure)
	}
}

func TestSafeProxyEnforcesTransferLimit(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat("x", 4096))
	}))
	defer server.Close()
	config, target, _ := proxyTestConfig(t, server, nil)
	config.MaxTransferBytes = 256
	proxy, err := newSafeProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	budget, _, err := proxy.begin(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.end(budget)
	response, err := proxyClient(t, proxy).Get(target)
	if err == nil && response != nil {
		_, _ = io.ReadAll(response.Body)
		response.Body.Close()
	}
	if failure := budget.failure(); !errors.Is(failure, ErrTransferLimit) {
		t.Fatalf("proxy failure = %v, want ErrTransferLimit", failure)
	}
}

func proxyTestConfig(t *testing.T, server *httptest.Server, resolve func(string) []netip.Addr) (Config, string, *atomic.Value) {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Resolver = navigationResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if resolve != nil {
			return resolve(host), nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	var dialed atomic.Value
	dialed.Store("")
	config.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Store(address)
		return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
	}
	return config, "http://public.test:" + port, &dialed
}

func proxyClient(t *testing.T, proxy *safeProxy) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
}

type navigationResolver func(context.Context, string, string) ([]netip.Addr, error)

func (r navigationResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r(ctx, network, host)
}

type fakeNavigationBackend struct {
	*fakeBackendSession
	navigateFn    func(context.Context, string) error
	navigateCalls atomic.Int32
}

func newFakeNavigationBackend(navigate func(context.Context, string) error) *fakeNavigationBackend {
	return &fakeNavigationBackend{fakeBackendSession: newFakeBackendSession(nil), navigateFn: navigate}
}

func (b *fakeNavigationBackend) navigate(ctx context.Context, rawURL string) error {
	b.navigateCalls.Add(1)
	return b.navigateFn(ctx, rawURL)
}

var _ networkguard.Resolver = navigationResolver(nil)
var _ navigationBackendSession = (*fakeNavigationBackend)(nil)
