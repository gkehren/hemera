// Package browser manages Hemera's local sandboxed Chromium sessions.
package browser

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

const (
	defaultStartupTimeout = 5 * time.Second
	maxStartupTimeout     = 10 * time.Second
	backendStopTimeout    = 5 * time.Second
)

var (
	// ErrInvalidConfig identifies browser configuration outside safe bounds.
	ErrInvalidConfig = errors.New("invalid browser configuration")
)

// Config controls local Chromium startup. ExecutablePath may be empty to use
// chromedp's platform-specific executable discovery.
type Config struct {
	ExecutablePath string
	StartupTimeout time.Duration
}

// DefaultConfig returns the browser startup defaults and safety ceiling.
func DefaultConfig() Config {
	return Config{StartupTimeout: defaultStartupTimeout}
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

// Session owns one Chromium process and its isolated temporary profile.
type Session struct {
	version   Version
	backend   backendSession
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
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
		cancel()
	}()
	return session
}

// Version returns the product and CDP protocol version observed at startup.
func (s *Session) Version() Version {
	return s.version
}

// Close stops Chromium and removes its temporary profile. It is idempotent and
// bounded by the backend's shutdown deadline.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.backend.Close()
		s.cancel()
		close(s.closeDone)
	})
	<-s.closeDone
	return s.closeErr
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
