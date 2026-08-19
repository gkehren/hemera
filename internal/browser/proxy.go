package browser

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gkehren/hemera/internal/networkguard"
)

const browserProxyMaxHeaderBytes = 1 << 20

type safeProxy struct {
	guard     *networkguard.Guard
	transport *http.Transport
	listener  net.Listener
	server    *http.Server
	config    Config

	mu        sync.Mutex
	active    *navigationBudget
	handlerMu sync.Mutex
	handlers  sync.WaitGroup
	closing   bool
}

func newSafeProxy(config Config) (*safeProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for browser safety proxy: %w", err)
	}
	guard := networkguard.New(networkguard.Config{Resolver: config.Resolver, Dialer: config.Dialer})
	proxy := &safeProxy{
		guard:    guard,
		listener: listener,
		config:   config,
		transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				connectCtx, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
				defer cancel()
				return guard.DialContext(connectCtx, network, address)
			},
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    config.ConnectTimeout,
			ResponseHeaderTimeout:  config.ConnectTimeout,
			MaxResponseHeaderBytes: browserProxyMaxHeaderBytes,
			MaxConnsPerHost:        config.MaxConcurrentRequests,
			MaxIdleConns:           config.MaxConcurrentRequests,
			MaxIdleConnsPerHost:    config.MaxConcurrentRequests,
			DisableCompression:     true,
		},
	}
	proxy.server = &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: config.ConnectTimeout,
		MaxHeaderBytes:    browserProxyMaxHeaderBytes,
	}
	go func() {
		_ = proxy.server.Serve(listener)
	}()
	return proxy, nil
}

func (p *safeProxy) address() string {
	return p.listener.Addr().String()
}

func (p *safeProxy) begin(ctx context.Context, rawURL string) (*navigationBudget, string, error) {
	parsed, err := parseBrowserURL(rawURL)
	if err != nil {
		return nil, "", err
	}
	validationCtx, cancel := context.WithTimeout(ctx, p.config.ConnectTimeout)
	err = p.guard.Validate(validationCtx, parsed)
	cancel()
	if err != nil {
		return nil, "", err
	}
	budget := newNavigationBudget(p.config)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != nil {
		budget.stop()
		return nil, "", ErrNavigationActive
	}
	p.active = budget
	return budget, parsed.String(), nil
}

func (p *safeProxy) end(budget *navigationBudget) {
	p.mu.Lock()
	if p.active == budget {
		p.active = nil
	}
	p.mu.Unlock()
	budget.stop()
	p.transport.CloseIdleConnections()
}

func (p *safeProxy) current() *navigationBudget {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

func (p *safeProxy) Close() error {
	p.handlerMu.Lock()
	p.closing = true
	p.handlerMu.Unlock()
	p.mu.Lock()
	budget := p.active
	p.active = nil
	p.mu.Unlock()
	if budget != nil {
		budget.stop()
	}
	p.transport.CloseIdleConnections()
	var closeErr error
	if err := p.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		closeErr = fmt.Errorf("close browser safety proxy: %w", err)
	}
	p.handlers.Wait()
	return closeErr
}

func (p *safeProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !p.startHandler() {
		http.Error(writer, "browser proxy is closing", http.StatusServiceUnavailable)
		return
	}
	defer p.handlers.Done()
	budget := p.current()
	if budget == nil {
		http.Error(writer, "browser navigation is not active", http.StatusServiceUnavailable)
		return
	}
	if err := budget.authorizeProxy(); err != nil {
		budget.fail(err)
		http.Error(writer, "browser resource limit exceeded", http.StatusServiceUnavailable)
		return
	}
	requestBytes := headerSize(request.Header) + int64(len(request.Method)+len(request.Host)+len(request.URL.String()))
	if err := budget.consume(requestBytes); err != nil {
		budget.fail(err)
		http.Error(writer, "browser resource limit exceeded", http.StatusServiceUnavailable)
		return
	}
	if request.Method == http.MethodConnect {
		p.connect(writer, request, budget)
		return
	}
	p.forwardHTTP(writer, request, budget)
}

func (p *safeProxy) startHandler() bool {
	p.handlerMu.Lock()
	defer p.handlerMu.Unlock()
	if p.closing {
		return false
	}
	p.handlers.Add(1)
	return true
}

func (p *safeProxy) forwardHTTP(writer http.ResponseWriter, request *http.Request, budget *navigationBudget) {
	parsed, err := parseBrowserURL(request.URL.String())
	if err != nil {
		budget.fail(err)
		http.Error(writer, "invalid browser destination", http.StatusBadGateway)
		return
	}
	requestCtx, cancel := linkedDoneContext(request.Context(), budget.done)
	defer cancel()
	upstream := request.Clone(requestCtx)
	upstream.URL = parsed
	upstream.Host = parsed.Host
	upstream.RequestURI = ""
	removeHopByHopHeaders(upstream.Header)
	if upstream.Body != nil {
		upstream.Body = &budgetReadCloser{reader: upstream.Body, closer: upstream.Body, budget: budget}
	}
	response, err := p.transport.RoundTrip(upstream)
	if err != nil {
		if failure := budget.failure(); failure == nil {
			budget.fail(err)
		}
		http.Error(writer, "browser destination failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopByHopHeaders(response.Header)
	if err := budget.consume(headerSize(response.Header)); err != nil {
		budget.fail(err)
		http.Error(writer, "browser resource limit exceeded", http.StatusBadGateway)
		return
	}
	copyHeader(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	if err := copyWithBudget(writer, response.Body, budget); err != nil {
		budget.fail(err)
	}
}

func (p *safeProxy) connect(writer http.ResponseWriter, request *http.Request, budget *navigationBudget) {
	parsed, err := parseBrowserURL("https://" + request.Host)
	if err != nil {
		budget.fail(err)
		http.Error(writer, "invalid browser destination", http.StatusBadGateway)
		return
	}
	baseCtx, cancelBase := linkedDoneContext(request.Context(), budget.done)
	connectCtx, cancel := context.WithTimeout(baseCtx, p.config.ConnectTimeout)
	upstream, err := p.guard.DialContext(connectCtx, "tcp", parsed.Host)
	cancel()
	cancelBase()
	if err != nil {
		budget.fail(err)
		http.Error(writer, "browser destination failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		upstream.Close()
		budget.fail(errors.New("browser safety proxy cannot create a tunnel"))
		http.Error(writer, "browser destination failed", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		budget.fail(err)
		return
	}
	defer client.Close()
	defer upstream.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		budget.fail(err)
		return
	}
	if err := buffered.Flush(); err != nil {
		budget.fail(err)
		return
	}

	results := make(chan error, 2)
	go func() { results <- copyWithBudget(upstream, client, budget) }()
	go func() { results <- copyWithBudget(client, upstream, budget) }()
	select {
	case err := <-results:
		if err != nil && !budget.stopped() {
			budget.fail(err)
		}
	case <-budget.done:
	}
}

type navigationBudget struct {
	config   Config
	done     chan struct{}
	stopOnce sync.Once

	mu            sync.Mutex
	requests      int
	proxyRequests int
	redirects     int
	transferBytes int64
	decodedBytes  int64
	err           error
}

func newNavigationBudget(config Config) *navigationBudget {
	return &navigationBudget{
		config: config,
		done:   make(chan struct{}),
	}
}

func (b *navigationBudget) authorize(rawURL string, redirect bool) error {
	if _, err := parseBrowserURL(rawURL); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if b.requests >= b.config.MaxRequests {
		return ErrRequestLimit
	}
	b.requests++
	if redirect {
		if b.redirects >= b.config.MaxRedirects {
			return ErrRedirectLimit
		}
		b.redirects++
	}
	return nil
}

func (b *navigationBudget) authorizeProxy() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if b.proxyRequests >= b.config.MaxRequests {
		return ErrRequestLimit
	}
	b.proxyRequests++
	return nil
}

func (b *navigationBudget) consume(count int64) error {
	if count <= 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if count > b.config.MaxTransferBytes-b.transferBytes {
		return ErrTransferLimit
	}
	b.transferBytes += count
	return nil
}

func (b *navigationBudget) consumeDecoded(count int64) error {
	if count <= 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if count > b.config.MaxTransferBytes-b.decodedBytes {
		return ErrTransferLimit
	}
	b.decodedBytes += count
	return nil
}

func (b *navigationBudget) fail(err error) {
	if err == nil {
		return
	}
	b.mu.Lock()
	if b.err == nil {
		b.err = err
		b.stop()
	}
	b.mu.Unlock()
}

func (b *navigationBudget) failure() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *navigationBudget) stop() {
	b.stopOnce.Do(func() { close(b.done) })
}

func (b *navigationBudget) stopped() bool {
	select {
	case <-b.done:
		return true
	default:
		return false
	}
}

type budgetReadCloser struct {
	reader io.Reader
	closer io.Closer
	budget *navigationBudget
}

func (r *budgetReadCloser) Read(buffer []byte) (int, error) {
	count, err := r.reader.Read(buffer)
	if budgetErr := r.budget.consume(int64(count)); budgetErr != nil {
		return 0, budgetErr
	}
	return count, err
}

func (r *budgetReadCloser) Close() error {
	return r.closer.Close()
}

func copyWithBudget(destination io.Writer, source io.Reader, budget *navigationBudget) error {
	buffer := make([]byte, 32<<10)
	for {
		count, readErr := source.Read(buffer)
		if count > 0 {
			if err := budget.consume(int64(count)); err != nil {
				return err
			}
			written, writeErr := destination.Write(buffer[:count])
			if writeErr != nil {
				return writeErr
			}
			if written != count {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func linkedDoneContext(parent context.Context, done <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		cancel()
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(name))
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func copyHeader(destination, source http.Header) {
	for name, values := range source {
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

func headerSize(header http.Header) int64 {
	var size int64
	for name, values := range header {
		for _, value := range values {
			size += int64(len(name) + len(value) + 4)
		}
	}
	return size
}

func parseBrowserURL(rawURL string) (*url.URL, error) {
	if len(rawURL) > maxBrowserURLBytes {
		return nil, fmt.Errorf("%w: URL exceeds %d bytes", networkguard.ErrInvalidURL, maxBrowserURLBytes)
	}
	return networkguard.ParseURL(rawURL)
}

var _ http.Handler = (*safeProxy)(nil)
var _ io.ReadCloser = (*budgetReadCloser)(nil)
