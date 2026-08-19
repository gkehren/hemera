package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

const (
	profilePrefix        = "hemera-chromium-"
	gracefulCloseTimeout = 2 * time.Second
	browserCloseTimeout  = 5 * time.Second
)

type chromedpBackend struct {
	profileRoot string
}

func (b chromedpBackend) start(ctx context.Context, config Config) (backendSession, Version, error) {
	profileDir, err := os.MkdirTemp(b.profileRoot, profilePrefix)
	if err != nil {
		return nil, Version{}, fmt.Errorf("create temporary Chromium profile: %w", err)
	}

	options := append([]chromedp.ExecAllocatorOption(nil), chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options,
		chromedp.UserDataDir(profileDir),
		chromedp.Flag("remote-debugging-address", "127.0.0.1"),
		chromedp.Flag("remote-debugging-port", "0"),
		chromedp.Flag("no-sandbox", false),
		chromedp.WSURLReadTimeout(config.StartupTimeout),
	)
	if config.ExecutablePath != "" {
		options = append(options, chromedp.ExecPath(config.ExecutablePath))
	}

	allocatorCtx, cancelAllocator := chromedp.NewExecAllocator(ctx, options...)
	taskCtx, cancelTask := chromedp.NewContext(allocatorCtx)
	session := newChromedpSession(profileDir, func() error {
		var cleanupErrors []error
		chromedpContext := chromedp.FromContext(taskCtx)
		if taskCtx.Err() == nil && chromedpContext != nil && chromedpContext.Browser != nil {
			gracefulCtx, cancelGraceful := context.WithTimeout(taskCtx, gracefulCloseTimeout)
			if err := chromedp.Cancel(gracefulCtx); err != nil &&
				!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("close Chromium through CDP: %w", err))
			}
			cancelGraceful()
		}
		cancelTask()
		cancelAllocator()
		if err := os.RemoveAll(profileDir); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove temporary Chromium profile: %w", err))
		}
		return errors.Join(cleanupErrors...)
	})
	go func() {
		<-taskCtx.Done()
		session.startCleanup()
	}()

	var version Version
	err = chromedp.Run(taskCtx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		chromedpContext := chromedp.FromContext(actionCtx)
		if chromedpContext == nil || chromedpContext.Browser == nil {
			return errors.New("CDP browser context is unavailable")
		}
		browserCtx := cdp.WithExecutor(actionCtx, chromedpContext.Browser)
		protocolVersion, product, _, _, _, err := cdpbrowser.GetVersion().Do(browserCtx)
		if err != nil {
			return fmt.Errorf("Browser.getVersion: %w", err)
		}
		version = Version{Product: product, ProtocolVersion: protocolVersion}

		arguments, err := cdpbrowser.GetBrowserCommandLine().Do(browserCtx)
		if err != nil {
			return fmt.Errorf("verify Chromium sandbox command line: %w", err)
		}
		if err := validateSandboxCommandLine(arguments); err != nil {
			return err
		}
		session.commandLine = slices.Clone(arguments)
		if chromedpContext.Target != nil {
			params := target.GetTargetInfo().WithTargetID(chromedpContext.Target.TargetID)
			if info, targetErr := params.Do(browserCtx); targetErr == nil && info != nil {
				session.initialURL = info.URL
			}
		}
		return nil
	}))
	if err != nil {
		cleanupErr := session.Close()
		return nil, Version{}, errors.Join(fmt.Errorf("establish CDP session: %w", err), cleanupErr)
	}

	chromedpContext := chromedp.FromContext(taskCtx)
	if chromedpContext != nil && chromedpContext.Browser != nil {
		session.process = chromedpContext.Browser.Process()
	}
	return session, version, nil
}

func validateSandboxCommandLine(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("verify Chromium sandbox command line: Browser.getBrowserCommandLine returned no arguments")
	}
	for _, argument := range arguments {
		if sandboxDisablingSwitch(argument) {
			return fmt.Errorf("Chromium sandbox is disabled by command-line switch %q", argument)
		}
	}
	return nil
}

func sandboxDisablingSwitch(argument string) bool {
	if !strings.HasPrefix(argument, "--") {
		return false
	}
	name := strings.TrimPrefix(argument, "--")
	if before, _, found := strings.Cut(name, "="); found {
		name = before
	}
	return name == "no-sandbox" ||
		(strings.HasPrefix(name, "disable-") && strings.HasSuffix(name, "-sandbox"))
}

type chromedpSession struct {
	profileDir string
	process    *os.Process

	commandLine []string
	initialURL  string

	cleanup     func() error
	cleanupOnce sync.Once
	done        chan struct{}
	errMu       sync.Mutex
	cleanupErr  error
	closeAfter  time.Duration
	newTimer    timerFactory
}

func newChromedpSession(profileDir string, cleanup func() error) *chromedpSession {
	return &chromedpSession{
		profileDir: profileDir,
		cleanup:    cleanup,
		done:       make(chan struct{}),
		closeAfter: browserCloseTimeout,
		newTimer:   runtimeTimerFactory,
	}
}

func (s *chromedpSession) startCleanup() {
	s.cleanupOnce.Do(func() {
		go func() {
			err := s.cleanup()
			s.errMu.Lock()
			s.cleanupErr = err
			s.errMu.Unlock()
			close(s.done)
		}()
	})
}

func (s *chromedpSession) Close() error {
	s.startCleanup()
	timer := s.newTimer(s.closeAfter)
	defer timer.Stop()
	select {
	case <-s.done:
		s.errMu.Lock()
		defer s.errMu.Unlock()
		return s.cleanupErr
	case <-timer.C():
		return fmt.Errorf("stop Chromium within %s: %w", s.closeAfter, context.DeadlineExceeded)
	}
}

func (s *chromedpSession) Done() <-chan struct{} {
	return s.done
}
