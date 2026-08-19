package browser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	if config.ExecutablePath != "" {
		t.Errorf("ExecutablePath = %q, want automatic discovery", config.ExecutablePath)
	}
	if config.StartupTimeout != defaultStartupTimeout {
		t.Errorf("StartupTimeout = %s, want %s", config.StartupTimeout, defaultStartupTimeout)
	}
	if config.StartupTimeout <= 0 || config.StartupTimeout > maxStartupTimeout {
		t.Errorf("StartupTimeout = %s, want positive value at or below %s", config.StartupTimeout, maxStartupTimeout)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()
	missingExecutable := t.TempDir() + string(os.PathSeparator) + "missing"
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"zero timeout", func(config *Config) { config.StartupTimeout = 0 }},
		{"negative timeout", func(config *Config) { config.StartupTimeout = -time.Nanosecond }},
		{"timeout above ceiling", func(config *Config) { config.StartupTimeout = maxStartupTimeout + time.Nanosecond }},
		{"missing executable", func(config *Config) { config.ExecutablePath = missingExecutable }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig()
			test.change(&config)
			if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	config := DefaultConfig()
	config.StartupTimeout = maxStartupTimeout
	if _, err := New(config); err != nil {
		t.Fatalf("New() at timeout ceiling: %v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config.ExecutablePath = executable
	if client, err := New(config); err != nil {
		t.Fatalf("New() with executable path: %v", err)
	} else if client.config.ExecutablePath == "" {
		t.Error("resolved executable path is empty")
	}
}

func TestStartReturnsVersionAndCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	fakeSession := newFakeBackendSession(nil)
	backend := backendFunc(func(context.Context, Config) (backendSession, Version, error) {
		return fakeSession, Version{Product: "Chromium/140.0", ProtocolVersion: "1.3"}, nil
	})
	timer := newManualTimer()
	client := testClient(t, backend, timer)

	session, err := client.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := session.Version(), (Version{Product: "Chromium/140.0", ProtocolVersion: "1.3"}); got != want {
		t.Errorf("Version() = %#v, want %#v", got, want)
	}
	if timer.duration != defaultStartupTimeout {
		t.Errorf("startup timer = %s, want %s", timer.duration, defaultStartupTimeout)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := fakeSession.closeCalls.Load(); calls != 1 {
		t.Errorf("backend Close calls = %d, want 1", calls)
	}
	select {
	case <-session.Done():
	default:
		t.Error("Done() remained open after Close()")
	}
}

func TestStartPropagatesBackendError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("CDP handshake failed")
	backend := backendFunc(func(context.Context, Config) (backendSession, Version, error) {
		return nil, Version{}, wantErr
	})
	client := testClient(t, backend, newManualTimer())
	if _, err := client.Start(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
}

func TestStartCleansSessionReturnedWithBackendError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("CDP handshake failed")
	fakeSession := newFakeBackendSession(nil)
	backend := backendFunc(func(context.Context, Config) (backendSession, Version, error) {
		return fakeSession, Version{}, wantErr
	})
	client := testClient(t, backend, newManualTimer())
	if _, err := client.Start(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want %v", err, wantErr)
	}
	if got := fakeSession.cleanupCalls.Load(); got != 1 {
		t.Errorf("cleanup calls = %d, want 1", got)
	}
}

func TestStartRejectsNilAndCanceledContexts(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	backend := backendFunc(func(context.Context, Config) (backendSession, Version, error) {
		calls.Add(1)
		return newFakeBackendSession(nil), Version{}, nil
	})
	client := testClient(t, backend, newManualTimer())
	if _, err := client.Start(nil); err == nil {
		t.Fatal("Start(nil) error = nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(canceled context) error = %v, want context.Canceled", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("backend start calls = %d, want 0", got)
	}
}

func TestStartCancellationCleansUpPendingBackend(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	cleaned := make(chan struct{})
	backend := backendFunc(func(ctx context.Context, _ Config) (backendSession, Version, error) {
		close(entered)
		<-ctx.Done()
		close(cleaned)
		return nil, Version{}, ctx.Err()
	})
	client := testClient(t, backend, newManualTimer())
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Start(ctx)
		result <- err
	}()
	<-entered
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context.Canceled", err)
	}
	select {
	case <-cleaned:
	default:
		t.Error("Start() returned before backend cleanup")
	}
}

func TestStartTimeoutCleansUpPendingBackend(t *testing.T) {
	t.Parallel()
	backendErr := errors.New("profile cleanup failed")
	entered := make(chan struct{})
	cleaned := make(chan struct{})
	backend := backendFunc(func(ctx context.Context, _ Config) (backendSession, Version, error) {
		close(entered)
		<-ctx.Done()
		close(cleaned)
		return nil, Version{}, errors.Join(ctx.Err(), backendErr)
	})
	timer := newManualTimer()
	client := testClient(t, backend, timer)
	result := make(chan error, 1)
	go func() {
		_, err := client.Start(context.Background())
		result <- err
	}()
	<-entered
	timer.Fire()
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start() error = %v, want context.DeadlineExceeded", err)
	} else if !errors.Is(err, backendErr) {
		t.Fatalf("Start() error = %v, want backend error %v", err, backendErr)
	}
	select {
	case <-cleaned:
	default:
		t.Error("Start() returned before backend cleanup")
	}
}

func TestStopPendingStartPreservesBackendAndCloseErrors(t *testing.T) {
	t.Parallel()
	backendErr := errors.New("backend cleanup failed")
	closeErr := errors.New("session cleanup failed")
	fakeSession := newFakeBackendSession(closeErr)
	results := make(chan startResult, 1)
	results <- startResult{session: fakeSession, err: backendErr}

	err := stopPendingStart(results)
	if !errors.Is(err, backendErr) {
		t.Errorf("stopPendingStart() error = %v, want backend error %v", err, backendErr)
	}
	if !errors.Is(err, closeErr) {
		t.Errorf("stopPendingStart() error = %v, want close error %v", err, closeErr)
	}
}

func TestValidateSandboxCommandLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		arguments []string
		wantError bool
	}{
		{
			name:      "sandboxed Chromium",
			arguments: []string{"/usr/bin/chromium", "--headless", "--disable-dev-shm-usage"},
		},
		{
			name:      "no arguments cannot be verified",
			wantError: true,
		},
		{
			name:      "no sandbox",
			arguments: []string{"chromium", "--no-sandbox"},
			wantError: true,
		},
		{
			name:      "no sandbox with value",
			arguments: []string{"chromium", "--no-sandbox=false"},
			wantError: true,
		},
		{
			name:      "setuid sandbox disabled",
			arguments: []string{"chromium", "--disable-setuid-sandbox"},
			wantError: true,
		},
		{
			name:      "GPU sandbox disabled",
			arguments: []string{"chromium", "--disable-gpu-sandbox=1"},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSandboxCommandLine(test.arguments)
			if (err != nil) != test.wantError {
				t.Errorf("validateSandboxCommandLine(%q) error = %v, wantError %t", test.arguments, err, test.wantError)
			}
		})
	}
}

func TestCallerCancellationStopsStartedSession(t *testing.T) {
	t.Parallel()
	fakeSession := newFakeBackendSession(nil)
	backend := backendFunc(func(ctx context.Context, _ Config) (backendSession, Version, error) {
		go func() {
			<-ctx.Done()
			fakeSession.finish()
		}()
		return fakeSession, Version{}, nil
	})
	client := testClient(t, backend, newManualTimer())
	ctx, cancel := context.WithCancel(context.Background())
	session, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-session.Done()
	if got := fakeSession.cleanupCalls.Load(); got != 1 {
		t.Errorf("cleanup calls = %d, want 1", got)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if got := fakeSession.cleanupCalls.Load(); got != 1 {
		t.Errorf("cleanup calls after Close = %d, want 1", got)
	}
}

func TestSessionCloseReturnsBackendErrorOnce(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("profile cleanup failed")
	fakeSession := newFakeBackendSession(wantErr)
	session := newSession(Version{}, fakeSession, func() {})
	if err := session.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("first Close() error = %v, want %v", err, wantErr)
	}
	if err := session.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("second Close() error = %v, want %v", err, wantErr)
	}
	if got := fakeSession.closeCalls.Load(); got != 1 {
		t.Errorf("backend Close calls = %d, want 1", got)
	}
}

func TestChromedpSessionRunsCleanupOnce(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	session := newChromedpSession("unused", func() error {
		calls.Add(1)
		return nil
	})
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("cleanup calls = %d, want 1", got)
	}
}

func TestChromedpSessionCloseDeadlineIsBounded(t *testing.T) {
	t.Parallel()
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	session := newChromedpSession("unused", func() error {
		close(cleanupStarted)
		<-releaseCleanup
		return nil
	})
	manual := newManualTimer()
	session.closeAfter = time.Second
	session.newTimer = func(duration time.Duration) timer {
		manual.duration = duration
		return manual
	}
	result := make(chan error, 1)
	go func() {
		result <- session.Close()
	}()
	<-cleanupStarted
	manual.Fire()
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want context.DeadlineExceeded", err)
	}
	if manual.duration != time.Second {
		t.Errorf("close timer = %s, want 1s", manual.duration)
	}
	close(releaseCleanup)
	<-session.Done()
}

func TestChromedpBackendCleansProfileWhenExecutableFails(t *testing.T) {
	profileRoot := t.TempDir()
	config := DefaultConfig()
	config.ExecutablePath = filepath.Join(profileRoot, "missing-chromium")
	if session, _, err := (chromedpBackend{profileRoot: profileRoot}).start(context.Background(), config); err == nil {
		t.Fatal("start() error = nil")
	} else if session != nil {
		t.Errorf("start() session = %T, want nil", session)
	}
	entries, err := os.ReadDir(profileRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("profile root contains %d entries after failed startup, want 0", len(entries))
	}
}

func testClient(t *testing.T, backend backend, manual *manualTimer) *Client {
	t.Helper()
	client, err := newClient(DefaultConfig(), backend, func(duration time.Duration) timer {
		manual.duration = duration
		return manual
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type backendFunc func(context.Context, Config) (backendSession, Version, error)

func (f backendFunc) start(ctx context.Context, config Config) (backendSession, Version, error) {
	return f(ctx, config)
}

type fakeBackendSession struct {
	closeOnce    sync.Once
	done         chan struct{}
	closeErr     error
	closeCalls   atomic.Int32
	cleanupCalls atomic.Int32
}

func newFakeBackendSession(closeErr error) *fakeBackendSession {
	return &fakeBackendSession{done: make(chan struct{}), closeErr: closeErr}
}

func (s *fakeBackendSession) Close() error {
	s.closeCalls.Add(1)
	s.finish()
	return s.closeErr
}

func (s *fakeBackendSession) finish() {
	s.closeOnce.Do(func() {
		s.cleanupCalls.Add(1)
		close(s.done)
	})
}

func (s *fakeBackendSession) Done() <-chan struct{} {
	return s.done
}

type manualTimer struct {
	duration time.Duration
	channel  chan time.Time
}

func newManualTimer() *manualTimer {
	return &manualTimer{channel: make(chan time.Time, 1)}
}

func (t *manualTimer) C() <-chan time.Time {
	return t.channel
}

func (t *manualTimer) Stop() bool {
	return true
}

func (t *manualTimer) Fire() {
	t.channel <- time.Now()
}
