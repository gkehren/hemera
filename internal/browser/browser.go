// Package browser manages Hemera's local sandboxed Chromium sessions.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/gkehren/hemera/internal/networkguard"
)

const (
	defaultStartupTimeout = 5 * time.Second
	maxStartupTimeout     = 20 * time.Second
	backendStopTimeout    = 5 * time.Second

	defaultNavigationTimeout           = 15 * time.Second
	maxNavigationTimeout               = 15 * time.Second
	defaultPostLoadTimeout             = 1500 * time.Millisecond
	maxPostLoadTimeout                 = 3 * time.Second
	defaultNetworkIdleTime             = 250 * time.Millisecond
	maxNetworkIdleTime                 = time.Second
	defaultConnectTimeout              = 5 * time.Second
	maxBrowserConnectTimeout           = 5 * time.Second
	defaultMaxBrowserRequests          = 256
	maxBrowserRequests                 = 4096
	defaultMaxBrowserRedirects         = 10
	maxBrowserRedirects                = 10
	defaultMaxBrowserBytes       int64 = 16 << 20
	maxBrowserBytes              int64 = 16 << 20
	defaultMaxBrowserConcurrency       = 16
	maxBrowserConcurrency              = 32
	maxBrowserURLBytes                 = 8192
)

var (
	// ErrInvalidConfig identifies browser configuration outside safe bounds.
	ErrInvalidConfig = errors.New("invalid browser configuration")
	// ErrCaptureActive indicates that a session already has an active recorder.
	ErrCaptureActive = errors.New("browser capture is already active")
	// ErrSessionClosed indicates that an operation targeted a stopped session.
	ErrSessionClosed = errors.New("browser session is closed")
	// ErrRecorderClosed indicates that a recorder was abandoned before finishing.
	ErrRecorderClosed = errors.New("browser recorder is closed")
	// ErrNavigationActive indicates that the session is already navigating.
	ErrNavigationActive = errors.New("browser navigation is already active")
	// ErrRequestLimit indicates that a page exceeded its request budget.
	ErrRequestLimit = errors.New("browser request limit exceeded")
	// ErrRedirectLimit indicates that a page exceeded its redirect budget.
	ErrRedirectLimit = errors.New("browser redirect limit exceeded")
	// ErrTransferLimit indicates that a page exceeded its byte budget.
	ErrTransferLimit = errors.New("browser transfer limit exceeded")
	// ErrConcurrencyLimit indicates that a page exceeded its active request budget.
	ErrConcurrencyLimit = errors.New("browser concurrency limit exceeded")
	// ErrUnsupportedTarget indicates that a page attempted to create a worker,
	// popup, or another child execution target blocked by the Milestone 1 model.
	ErrUnsupportedTarget = errors.New("unsupported browser child target")
)

// ObservationCounters is a bounded, presentation-safe snapshot of live
// capture volume during one navigation. It never carries URLs or any other
// observed content.
type ObservationCounters struct {
	Requests  int
	Responses int
}

// Config controls local Chromium startup. ExecutablePath may be empty to use
// chromedp's platform-specific executable discovery.
type Config struct {
	ExecutablePath        string
	StartupTimeout        time.Duration
	NavigationTimeout     time.Duration
	PostLoadTimeout       time.Duration
	NetworkIdleTime       time.Duration
	ConnectTimeout        time.Duration
	MaxRequests           int
	MaxRedirects          int
	MaxTransferBytes      int64
	MaxConcurrentRequests int
	Resolver              networkguard.Resolver
	Dialer                networkguard.Dialer
	// Forms enables the bounded interaction phase: after the passive
	// post-load window, Hemera fills and submits exactly one eligible
	// same-origin form with fixed benign synthetic data, once, without
	// retries. It is opt-in and stays within every navigation budget.
	Forms bool
	// ObservationProgress, when non-nil, receives live aggregate counter
	// snapshots during capture. It is invoked on CDP event goroutines and
	// must not block: a slow callback stalls browser event processing.
	ObservationProgress func(ObservationCounters)
}

// DefaultConfig returns the browser startup defaults and safety ceiling.
func DefaultConfig() Config {
	return Config{
		StartupTimeout:        defaultStartupTimeout,
		NavigationTimeout:     defaultNavigationTimeout,
		PostLoadTimeout:       defaultPostLoadTimeout,
		NetworkIdleTime:       defaultNetworkIdleTime,
		ConnectTimeout:        defaultConnectTimeout,
		MaxRequests:           defaultMaxBrowserRequests,
		MaxRedirects:          defaultMaxBrowserRedirects,
		MaxTransferBytes:      defaultMaxBrowserBytes,
		MaxConcurrentRequests: defaultMaxBrowserConcurrency,
	}
}

// DeepConfig returns a browser configuration with maximal safe resource, timeout,
// and concurrency ceilings for deep web protection inspection.
func DeepConfig() Config {
	return Config{
		StartupTimeout:        maxStartupTimeout,
		NavigationTimeout:     maxNavigationTimeout,
		PostLoadTimeout:       maxPostLoadTimeout,
		NetworkIdleTime:       maxNetworkIdleTime,
		ConnectTimeout:        maxBrowserConnectTimeout,
		MaxRequests:           maxBrowserRequests,
		MaxRedirects:          maxBrowserRedirects,
		MaxTransferBytes:      maxBrowserBytes,
		MaxConcurrentRequests: maxBrowserConcurrency,
	}
}

// Version contains the minimal browser identity returned by Browser.getVersion.
type Version struct {
	Product         string
	ProtocolVersion string
}

// Client starts independent local Chromium sessions.
type Client struct {
	config   Config
	backend  backend
	newTimer timerFactory
}

// New validates config and constructs a browser client.
func New(config Config) (*Client, error) {
	return newClient(config, chromedpBackend{}, runtimeTimerFactory)
}

func newClient(config Config, backend backend, newTimer timerFactory) (*Client, error) {
	if config.StartupTimeout <= 0 || config.StartupTimeout > maxStartupTimeout {
		return nil, fmt.Errorf("%w: startup timeout must be between 1ns and %s", ErrInvalidConfig, maxStartupTimeout)
	}
	if config.NavigationTimeout <= 0 || config.NavigationTimeout > maxNavigationTimeout {
		return nil, fmt.Errorf("%w: navigation timeout must be between 1ns and %s", ErrInvalidConfig, maxNavigationTimeout)
	}
	if config.PostLoadTimeout <= 0 || config.PostLoadTimeout > maxPostLoadTimeout {
		return nil, fmt.Errorf("%w: post-load timeout must be between 1ns and %s", ErrInvalidConfig, maxPostLoadTimeout)
	}
	if config.NetworkIdleTime <= 0 || config.NetworkIdleTime > maxNetworkIdleTime || config.NetworkIdleTime > config.PostLoadTimeout {
		return nil, fmt.Errorf("%w: network idle time must be between 1ns and the post-load timeout, with a ceiling of %s", ErrInvalidConfig, maxNetworkIdleTime)
	}
	if config.ConnectTimeout <= 0 || config.ConnectTimeout > maxBrowserConnectTimeout {
		return nil, fmt.Errorf("%w: connect timeout must be between 1ns and %s", ErrInvalidConfig, maxBrowserConnectTimeout)
	}
	if config.MaxRequests <= 0 || config.MaxRequests > maxBrowserRequests {
		return nil, fmt.Errorf("%w: request count must be between 1 and %d", ErrInvalidConfig, maxBrowserRequests)
	}
	if config.MaxRedirects < 0 || config.MaxRedirects > maxBrowserRedirects {
		return nil, fmt.Errorf("%w: redirect count must be between 0 and %d", ErrInvalidConfig, maxBrowserRedirects)
	}
	if config.MaxTransferBytes <= 0 || config.MaxTransferBytes > maxBrowserBytes {
		return nil, fmt.Errorf("%w: transfer bytes must be between 1 and %d", ErrInvalidConfig, maxBrowserBytes)
	}
	if config.MaxConcurrentRequests <= 0 || config.MaxConcurrentRequests > maxBrowserConcurrency {
		return nil, fmt.Errorf("%w: concurrent requests must be between 1 and %d", ErrInvalidConfig, maxBrowserConcurrency)
	}
	if config.Dialer == nil {
		config.Dialer = (&net.Dialer{Timeout: config.ConnectTimeout}).DialContext
	}
	if config.ExecutablePath != "" {
		resolved, err := exec.LookPath(config.ExecutablePath)
		if err != nil {
			return nil, fmt.Errorf("%w: Chromium executable %q: %w", ErrInvalidConfig, config.ExecutablePath, err)
		}
		config.ExecutablePath = resolved
	}
	if backend == nil {
		return nil, fmt.Errorf("%w: browser backend is required", ErrInvalidConfig)
	}
	if newTimer == nil {
		return nil, fmt.Errorf("%w: timer factory is required", ErrInvalidConfig)
	}
	return &Client{config: config, backend: backend, newTimer: newTimer}, nil
}

// Start launches Chromium, establishes CDP, and verifies Browser.getVersion.
// The returned session remains tied to ctx until Close or context cancellation.
func (c *Client) Start(ctx context.Context) (*Session, error) {
	if ctx == nil {
		return nil, errors.New("start browser: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("start browser: %w", err)
	}

	lifetimeCtx, cancelLifetime := context.WithCancel(ctx)
	results := make(chan startResult, 1)
	go func() {
		backendSession, version, err := c.backend.start(lifetimeCtx, c.config)
		results <- startResult{session: backendSession, version: version, err: err}
	}()

	timer := c.newTimer(c.config.StartupTimeout)
	defer timer.Stop()

	select {
	case result := <-results:
		if result.err != nil {
			cancelLifetime()
			cleanupErr := closeBackendSession(result.session)
			return nil, errors.Join(fmt.Errorf("start browser: %w", result.err), cleanupErr)
		}
		if result.session == nil {
			cancelLifetime()
			return nil, errors.New("start browser: backend returned no session")
		}
		if err := ctx.Err(); err != nil {
			cancelLifetime()
			cleanupErr := result.session.Close()
			return nil, errors.Join(fmt.Errorf("start browser: %w", err), cleanupErr)
		}
		return newSession(result.version, result.session, cancelLifetime), nil

	case <-ctx.Done():
		cancelLifetime()
		cleanupErr := stopPendingStart(results)
		return nil, errors.Join(fmt.Errorf("start browser: %w", ctx.Err()), cleanupErr)

	case <-timer.C():
		cancelLifetime()
		cleanupErr := stopPendingStart(results)
		return nil, errors.Join(
			fmt.Errorf("start browser: startup exceeded %s: %w", c.config.StartupTimeout, context.DeadlineExceeded),
			cleanupErr,
		)
	}
}

func stopPendingStart(results <-chan startResult) error {
	timer := time.NewTimer(backendStopTimeout)
	defer timer.Stop()
	select {
	case result := <-results:
		return errors.Join(wrapBackendStartError(result.err), closeBackendSession(result.session))
	case <-timer.C:
		go func() {
			result := <-results
			_ = closeBackendSession(result.session)
		}()
		return fmt.Errorf("stop browser startup within %s: %w", backendStopTimeout, context.DeadlineExceeded)
	}
}

func wrapBackendStartError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("browser backend startup: %w", err)
}

func closeBackendSession(session backendSession) error {
	if session == nil {
		return nil
	}
	if err := session.Close(); err != nil {
		return fmt.Errorf("clean up browser session: %w", err)
	}
	return nil
}

type startResult struct {
	session backendSession
	version Version
	err     error
}

type backend interface {
	start(context.Context, Config) (backendSession, Version, error)
}

type backendSession interface {
	Close() error
	Done() <-chan struct{}
}

type captureBackendSession interface {
	backendSession
	beginCapture(context.Context) (captureSource, error)
}

type navigationBackendSession interface {
	backendSession
	navigate(context.Context, string) error
}

type captureSource interface {
	finish(context.Context) (CaptureResult, error)
	Close() error
}

// Session owns one Chromium process and its isolated temporary profile.
type Session struct {
	version      Version
	backend      backendSession
	cancel       context.CancelFunc
	closeOnce    sync.Once
	closeDone    chan struct{}
	closeErr     error
	captureMu    sync.Mutex
	active       *Recorder
	stopped      bool
	navigationMu sync.Mutex
	navigating   bool
}

// Navigate performs one bounded navigation through the session's validated
// network boundary. It does not return observations; callers may use a Recorder
// around the navigation when raw capture is needed.
func (s *Session) Navigate(ctx context.Context, rawURL string) error {
	if ctx == nil {
		return errors.New("navigate browser: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("navigate browser: %w", err)
	}
	s.captureMu.Lock()
	stopped := s.stopped
	s.captureMu.Unlock()
	if stopped {
		return ErrSessionClosed
	}
	s.navigationMu.Lock()
	if s.navigating {
		s.navigationMu.Unlock()
		return ErrNavigationActive
	}
	s.navigating = true
	s.navigationMu.Unlock()
	defer func() {
		s.navigationMu.Lock()
		s.navigating = false
		s.navigationMu.Unlock()
	}()
	backend, ok := s.backend.(navigationBackendSession)
	if !ok {
		return errors.New("navigate browser: backend does not support navigation")
	}
	if err := backend.navigate(ctx, rawURL); err != nil {
		return fmt.Errorf("navigate browser: %w", err)
	}
	return nil
}

func newSession(version Version, backend backendSession, cancel context.CancelFunc) *Session {
	session := &Session{
		version:   version,
		backend:   backend,
		cancel:    cancel,
		closeDone: make(chan struct{}),
	}
	go func() {
		<-backend.Done()
		session.stopActiveRecorder()
		cancel()
	}()
	return session
}

// Version returns the product and CDP protocol version observed at startup.
func (s *Session) Version() Version {
	return s.version
}

// BeginCapture enables passive CDP collection for the current target. A
// session permits only one active recorder at a time.
func (s *Session) BeginCapture(ctx context.Context) (*Recorder, error) {
	if ctx == nil {
		return nil, errors.New("begin browser capture: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("begin browser capture: %w", err)
	}

	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	if s.stopped {
		return nil, ErrSessionClosed
	}
	select {
	case <-s.backend.Done():
		s.stopped = true
		return nil, ErrSessionClosed
	default:
	}
	if s.active != nil {
		return nil, ErrCaptureActive
	}
	backend, ok := s.backend.(captureBackendSession)
	if !ok {
		return nil, errors.New("begin browser capture: backend does not support capture")
	}
	source, err := backend.beginCapture(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin browser capture: %w", err)
	}
	if source == nil {
		return nil, errors.New("begin browser capture: backend returned no recorder")
	}
	recorder := newRecorder(source, func(recorder *Recorder) {
		s.captureMu.Lock()
		if s.active == recorder {
			s.active = nil
		}
		s.captureMu.Unlock()
	})
	s.active = recorder
	go func() {
		select {
		case <-ctx.Done():
			_ = recorder.Close()
		case <-recorder.done:
		}
	}()
	return recorder, nil
}

// Close stops Chromium and removes its temporary profile. It is idempotent and
// bounded by the backend's shutdown deadline.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.captureMu.Lock()
		s.stopped = true
		recorder := s.active
		s.captureMu.Unlock()
		var recorderErr error
		if recorder != nil {
			recorderErr = recorder.Close()
		}
		s.closeErr = errors.Join(recorderErr, s.backend.Close())
		s.cancel()
		close(s.closeDone)
	})
	<-s.closeDone
	return s.closeErr
}

func (s *Session) stopActiveRecorder() {
	s.captureMu.Lock()
	s.stopped = true
	recorder := s.active
	s.captureMu.Unlock()
	if recorder != nil {
		_ = recorder.Close()
	}
}

// Done is closed after Chromium has stopped and its temporary profile cleanup
// has completed.
func (s *Session) Done() <-chan struct{} {
	return s.backend.Done()
}

type timer interface {
	C() <-chan time.Time
	Stop() bool
}

type timerFactory func(time.Duration) timer

type runtimeTimer struct {
	*time.Timer
}

func (t runtimeTimer) C() <-chan time.Time {
	return t.Timer.C
}

func runtimeTimerFactory(timeout time.Duration) timer {
	return runtimeTimer{Timer: time.NewTimer(timeout)}
}
