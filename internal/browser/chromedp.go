package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/gkehren/hemera/internal/networkguard"
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
	proxy, err := newSafeProxy(config)
	if err != nil {
		return nil, Version{}, errors.Join(err, os.RemoveAll(profileDir))
	}

	options := append([]chromedp.ExecAllocatorOption(nil), chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options,
		chromedp.UserDataDir(profileDir),
		chromedp.Flag("remote-debugging-address", "127.0.0.1"),
		chromedp.Flag("remote-debugging-port", "0"),
		chromedp.Flag("no-sandbox", false),
		chromedp.ProxyServer("http://"+proxy.address()),
		chromedp.Flag("proxy-bypass-list", "<-loopback>"),
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"),
		chromedp.Flag("disable-quic", true),
		chromedp.Flag("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"),
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
		if err := proxy.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
		if err := os.RemoveAll(profileDir); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove temporary Chromium profile: %w", err))
		}
		return errors.Join(cleanupErrors...)
	})
	session.startCapture = func(ctx context.Context) (captureSource, error) {
		return beginChromedpCapture(taskCtx, ctx)
	}
	session.navigateTarget = func(ctx context.Context, rawURL string) error {
		return navigateChromedp(taskCtx, ctx, rawURL, proxy, config)
	}
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
			return fmt.Errorf("verify Chromium security command line: %w", err)
		}
		if err := validateSecurityCommandLine(arguments, proxy.address()); err != nil {
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

func validateSecurityCommandLine(arguments []string, expectedProxyAddress string) error {
	if expectedProxyAddress == "" {
		return errors.New("verify Chromium security command line: expected proxy address is unavailable")
	}
	if len(arguments) == 0 {
		return errors.New("verify Chromium security command line: Browser.getBrowserCommandLine returned no arguments")
	}
	switches := make(map[string][]string)
	for _, argument := range arguments {
		if sandboxDisablingSwitch(argument) {
			return errors.New("Chromium sandbox is disabled by its effective command line")
		}
		if !strings.HasPrefix(argument, "--") {
			continue
		}
		name, value, _ := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
		switches[name] = append(switches[name], value)
	}
	if len(switches["no-proxy-server"]) != 0 {
		return errors.New("Chromium effective command line disables the Hemera safety proxy")
	}
	requireEffectiveSwitch := func(name, value string) error {
		values := switches[name]
		if len(values) != 1 || values[0] != value {
			return fmt.Errorf("Chromium effective command line has invalid %s security configuration", name)
		}
		return nil
	}
	for _, required := range []struct{ name, value string }{
		{"proxy-server", "http://" + expectedProxyAddress},
		{"proxy-bypass-list", "<-loopback>"},
		{"host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"},
		{"disable-quic", ""},
		{"force-webrtc-ip-handling-policy", "disable_non_proxied_udp"},
	} {
		if err := requireEffectiveSwitch(required.name, required.value); err != nil {
			return err
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

	cleanup        func() error
	cleanupOnce    sync.Once
	done           chan struct{}
	errMu          sync.Mutex
	cleanupErr     error
	closeAfter     time.Duration
	newTimer       timerFactory
	startCapture   func(context.Context) (captureSource, error)
	navigateTarget func(context.Context, string) error
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

func (s *chromedpSession) beginCapture(ctx context.Context) (captureSource, error) {
	if s.startCapture == nil {
		return nil, errors.New("CDP capture is unavailable")
	}
	return s.startCapture(ctx)
}

func (s *chromedpSession) navigate(ctx context.Context, rawURL string) error {
	if s.navigateTarget == nil {
		return errors.New("CDP navigation is unavailable")
	}
	return s.navigateTarget(ctx, rawURL)
}

func navigateChromedp(taskCtx, callerCtx context.Context, rawURL string, proxy *safeProxy, config Config) error {
	navigationCtx, cancelNavigation := context.WithTimeout(callerCtx, config.NavigationTimeout)
	defer cancelNavigation()
	if err := navigationCtx.Err(); err != nil {
		return err
	}
	budget, targetURL, err := proxy.begin(navigationCtx, rawURL)
	if err != nil {
		return err
	}
	defer proxy.end(budget)

	runCtx, cancelRun := context.WithCancel(navigationCtx)
	defer cancelRun()
	budgetEnded := make(chan struct{})
	defer close(budgetEnded)
	go func() {
		select {
		case <-budget.done:
			cancelRun()
		case <-navigationCtx.Done():
			budget.stop()
			cancelRun()
		case <-budgetEnded:
		}
	}()

	listenerCtx, stopListener := context.WithCancel(taskCtx)
	commandCtx := listenerCtx
	browserCtx := listenerCtx
	if chromedpContext := chromedp.FromContext(taskCtx); chromedpContext != nil && chromedpContext.Target != nil {
		commandCtx = cdp.WithExecutor(listenerCtx, chromedpContext.Target)
		if chromedpContext.Browser != nil {
			browserCtx = cdp.WithExecutor(listenerCtx, chromedpContext.Browser)
		}
	}
	pausedRequests := make(chan *fetch.EventRequestPaused, config.MaxRequests+1)
	requestTracker := newBrowserRequestTracker(config.MaxConcurrentRequests)
	activity := make(chan struct{}, 1)
	notifyActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	stopWorker := make(chan struct{})
	workerDone := make(chan struct{})
	blockedTargets := make(chan target.ID, 4)
	go func() {
		defer close(workerDone)
		for {
			select {
			case event := <-pausedRequests:
				handlePausedRequest(commandCtx, budget, requestTracker, event)
			case targetID := <-blockedTargets:
				closeErr := target.CloseTarget(targetID).Do(browserCtx)
				budget.fail(errors.Join(ErrUnsupportedTarget, closeErr))
			case <-stopWorker:
				return
			}
		}
	}()
	chromedp.ListenTarget(listenerCtx, func(value any) {
		switch event := value.(type) {
		case *network.EventDataReceived:
			notifyActivity()
			if err := budget.consumeDecoded(event.DataLength); err != nil {
				budget.fail(err)
			}
		case *fetch.EventRequestPaused:
			notifyActivity()
			select {
			case pausedRequests <- event:
			default:
				budget.fail(ErrRequestLimit)
			}
		case *network.EventLoadingFinished:
			requestTracker.release(event.RequestID)
			notifyActivity()
		case *network.EventLoadingFailed:
			requestTracker.release(event.RequestID)
			notifyActivity()
		case *network.EventWebSocketCreated:
			budget.fail(fmt.Errorf("%w: WebSocket transport is not allowed", networkguard.ErrInvalidURL))
		case *page.EventWindowOpen:
			budget.fail(ErrUnsupportedTarget)
		case *target.EventAttachedToTarget:
			if event.TargetInfo == nil || !blockedChildTargetType(event.TargetInfo.Type) {
				return
			}
			select {
			case blockedTargets <- event.TargetInfo.TargetID:
			default:
				budget.fail(ErrUnsupportedTarget)
			}
		default:
			return
		}
	})
	defer func() {
		stopListener()
		close(stopWorker)
		<-workerDone
		requestTracker.releaseAll()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = runChromedpWithCaller(taskCtx, cleanupCtx, fetch.Disable(), page.StopLoading())
		_ = runChromedpWithCaller(taskCtx, cleanupCtx, target.SetAutoAttach(false, false))
	}()

	patterns := []*fetch.RequestPattern{
		{URLPattern: "http://*", RequestStage: fetch.RequestStageRequest},
		{URLPattern: "https://*", RequestStage: fetch.RequestStageRequest},
	}
	if err := runChromedpWithCaller(taskCtx, runCtx,
		network.Enable(),
		network.SetCacheDisabled(true),
		network.SetBypassServiceWorker(true),
		fetch.Enable().WithPatterns(patterns),
		target.SetAutoAttach(true, true).WithFlatten(true).WithFilter(target.Filter{
			{Type: "page"},
			{Type: "worker"},
			{Type: "shared_worker"},
			{Type: "service_worker"},
			{Exclude: true},
		}),
		chromedp.ActionFunc(func(actionCtx context.Context) error {
			chromedpContext := chromedp.FromContext(actionCtx)
			if chromedpContext == nil || chromedpContext.Browser == nil {
				return errors.New("CDP browser context is unavailable")
			}
			browserCtx := cdp.WithExecutor(actionCtx, chromedpContext.Browser)
			return cdpbrowser.SetDownloadBehavior(cdpbrowser.SetDownloadBehaviorBehaviorDeny).Do(browserCtx)
		}),
	); err != nil {
		return err
	}

	navigationErr := runChromedpWithCaller(taskCtx, runCtx, chromedp.Navigate(targetURL))
	if navigationErr == nil {
		navigationErr = waitForNetworkQuiet(runCtx, activity, requestTracker, config.NetworkIdleTime, config.PostLoadTimeout)
	}
	if failure := budget.failure(); failure != nil {
		return failure
	}
	if err := navigationCtx.Err(); err != nil {
		return err
	}
	return navigationErr
}

func blockedChildTargetType(targetType string) bool {
	switch targetType {
	case "page", "worker", "shared_worker", "service_worker":
		return true
	default:
		return false
	}
}

// waitForNetworkQuiet keeps the complete navigation boundary alive after load.
// It returns once no browser request is active and no meaningful network event
// has occurred for idleTime, or when the hard post-load deadline is reached.
func waitForNetworkQuiet(ctx context.Context, activity <-chan struct{}, tracker *browserRequestTracker, idleTime, hardTimeout time.Duration) error {
	for {
		select {
		case <-activity:
			continue
		default:
		}
		break
	}
	idle := time.NewTimer(idleTime)
	defer idle.Stop()
	hard := time.NewTimer(hardTimeout)
	defer hard.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-hard.C:
			return nil
		case <-activity:
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(idleTime)
		case <-idle.C:
			if tracker.activeCount() == 0 {
				return nil
			}
			idle.Reset(idleTime)
		}
	}
}

func handlePausedRequest(ctx context.Context, budget *navigationBudget, tracker *browserRequestTracker, event *fetch.EventRequestPaused) {
	if event == nil || event.Request == nil {
		budget.fail(errors.New("CDP paused request is missing metadata"))
		return
	}
	if err := budget.authorize(event.Request.URL, event.RedirectedRequestID != ""); err != nil {
		failErr := fetch.FailRequest(event.RequestID, network.ErrorReasonAborted).Do(ctx)
		budget.fail(errors.Join(err, failErr))
		return
	}
	requestID := event.NetworkID
	if requestID == "" {
		err := ErrUnsupportedTarget
		failErr := fetch.FailRequest(event.RequestID, network.ErrorReasonAborted).Do(ctx)
		budget.fail(errors.Join(err, failErr))
		return
	}
	if err := tracker.acquire(ctx, budget.done, requestID); err != nil {
		failErr := fetch.FailRequest(event.RequestID, network.ErrorReasonAborted).Do(ctx)
		budget.fail(errors.Join(err, failErr))
		return
	}
	if err := fetch.ContinueRequest(event.RequestID).Do(ctx); err != nil {
		tracker.release(requestID)
		budget.fail(fmt.Errorf("continue validated browser request: %w", err))
	}
}

// browserRequestTracker applies the concurrency ceiling to browser request
// lifecycles rather than proxy connections. HTTPS can multiplex many requests
// through one CONNECT tunnel, so tunnel-level accounting alone is insufficient.
type browserRequestTracker struct {
	sem chan struct{}

	mu     sync.Mutex
	active map[network.RequestID]struct{}
}

func newBrowserRequestTracker(limit int) *browserRequestTracker {
	return &browserRequestTracker{
		sem:    make(chan struct{}, limit),
		active: make(map[network.RequestID]struct{}),
	}
}

func (t *browserRequestTracker) acquire(ctx context.Context, stopped <-chan struct{}, requestID network.RequestID) error {
	t.mu.Lock()
	_, active := t.active[requestID]
	t.mu.Unlock()
	if active {
		return nil
	}
	select {
	case <-stopped:
		return ErrConcurrencyLimit
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	select {
	case t.sem <- struct{}{}:
	default:
		return ErrConcurrencyLimit
	}
	t.mu.Lock()
	if _, active = t.active[requestID]; active {
		t.mu.Unlock()
		<-t.sem
		return nil
	}
	t.active[requestID] = struct{}{}
	t.mu.Unlock()
	return nil
}

func (t *browserRequestTracker) release(requestID network.RequestID) {
	t.mu.Lock()
	if _, active := t.active[requestID]; !active {
		t.mu.Unlock()
		return
	}
	delete(t.active, requestID)
	t.mu.Unlock()
	<-t.sem
}

func (t *browserRequestTracker) releaseAll() {
	t.mu.Lock()
	count := len(t.active)
	clear(t.active)
	t.mu.Unlock()
	for range count {
		<-t.sem
	}
}

func (t *browserRequestTracker) activeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.active)
}

type chromedpCapture struct {
	collector *captureCollector
	stop      context.CancelFunc
	run       func(context.Context, chromedp.Action) error
	once      sync.Once
	done      chan struct{}
	result    CaptureResult
	err       error
}

func beginChromedpCapture(taskCtx, callerCtx context.Context) (captureSource, error) {
	listenerCtx, stopListener := context.WithCancel(taskCtx)
	collector := newCaptureCollector()
	chromedp.ListenTarget(listenerCtx, func(event any) {
		recordNetworkEvent(collector, event)
	})

	if err := runChromedpWithCaller(taskCtx, callerCtx, network.Enable(), page.Enable()); err != nil {
		stopListener()
		return nil, err
	}
	return &chromedpCapture{
		collector: collector,
		stop:      stopListener,
		run: func(ctx context.Context, action chromedp.Action) error {
			return runChromedpWithCaller(taskCtx, ctx, action)
		},
		done: make(chan struct{}),
	}, nil
}

func recordNetworkEvent(collector *captureCollector, value any) {
	switch event := value.(type) {
	case *network.EventRequestWillBeSent:
		if event.RedirectResponse != nil {
			collector.addResponse(
				event.RedirectResponse.URL,
				event.RedirectResponse.Status,
				event.RedirectResponse.MimeType,
				event.Type.String(),
			)
		}
		if event.Request != nil {
			collector.addRequest(event.Request.Method, event.Request.URL, event.Type.String())
		}
	case *network.EventResponseReceived:
		if event.Response != nil {
			collector.addResponse(
				event.Response.URL,
				event.Response.Status,
				event.Response.MimeType,
				event.Type.String(),
			)
		}
	}
}

func (c *chromedpCapture) finish(ctx context.Context) (CaptureResult, error) {
	c.once.Do(func() {
		c.stop()
		var finalURL string
		var domSnapshot boundedDOMSnapshot
		var cookies []CaptureCookie
		c.err = c.run(ctx, chromedp.ActionFunc(func(actionCtx context.Context) error {
			var captureErrors []error
			chromedpContext := chromedp.FromContext(actionCtx)
			if chromedpContext == nil || chromedpContext.Browser == nil || chromedpContext.Target == nil {
				captureErrors = append(captureErrors, errors.New("CDP target context is unavailable"))
			} else {
				browserCtx := cdp.WithExecutor(actionCtx, chromedpContext.Browser)
				info, err := target.GetTargetInfo().WithTargetID(chromedpContext.Target.TargetID).Do(browserCtx)
				if err != nil {
					captureErrors = append(captureErrors, fmt.Errorf("Target.getTargetInfo: %w", err))
				} else if info != nil {
					finalURL = info.URL
				}
				rawCookies, err := storage.GetCookies().Do(browserCtx)
				if err != nil {
					captureErrors = append(captureErrors, fmt.Errorf("Storage.getCookies: %w", err))
				} else {
					minimized := make([]CaptureCookie, 0, len(rawCookies))
					for _, cookie := range rawCookies {
						if cookie != nil {
							cookie.Value = ""
							minimized = append(minimized, CaptureCookie{Name: cookie.Name, Domain: cookie.Domain})
						}
					}
					cookies = minimized
				}
			}

			if err := captureBoundedDOM(actionCtx, &domSnapshot); err != nil {
				captureErrors = append(captureErrors, err)
			}
			return errors.Join(captureErrors...)
		}))
		c.result = c.collector.snapshotBounded(finalURL, domSnapshot, cookies)
		close(c.done)
	})
	<-c.done
	return cloneCaptureResult(c.result), c.err
}

func captureBoundedDOM(ctx context.Context, snapshot *boundedDOMSnapshot) error {
	frameTree, err := page.GetFrameTree().Do(ctx)
	if err != nil {
		return fmt.Errorf("Page.getFrameTree: %w", err)
	}
	if frameTree == nil || frameTree.Frame == nil {
		return errors.New("Page.getFrameTree returned no main frame")
	}
	executionContextID, err := page.CreateIsolatedWorld(frameTree.Frame.ID).
		WithWorldName("hemera-bounded-capture").
		Do(ctx)
	if err != nil {
		return fmt.Errorf("Page.createIsolatedWorld: %w", err)
	}
	expression := fmt.Sprintf(boundedDOMSerializer, maxDOMBytes, maxDOMWorkItems, maxCaptureItems, maxBrowserURLBytes)
	value, exception, err := cdpruntime.Evaluate(expression).
		WithContextID(executionContextID).
		WithReturnByValue(true).
		WithSilent(true).
		WithDisableBreaks(true).
		Do(ctx)
	if err != nil {
		return fmt.Errorf("Runtime.evaluate bounded DOM serializer: %w", err)
	}
	if exception != nil {
		return errors.New("bounded DOM serializer failed in the isolated world")
	}
	if value == nil || len(value.Value) == 0 {
		return errors.New("bounded DOM serializer returned no value")
	}
	if err := json.Unmarshal(value.Value, snapshot); err != nil {
		return fmt.Errorf("decode bounded DOM snapshot: %w", err)
	}
	return nil
}

const boundedDOMSerializer = `(() => {
  "use strict";
  const maxBytes = %d;
  const maxWork = %d;
  const maxResources = %d;
  const maxURLBytes = %d;
  const encoder = new TextEncoder();
  const chunks = [];
  const scripts = [];
  const iframes = [];
  const voidElements = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
  let bytes = 0;
  let work = 0;
  let domTruncated = false;
  let traversalTruncated = false;
  let scriptTruncated = false;
  let iframeTruncated = false;
  let urlTruncated = false;

  function appendRaw(input) {
    if (bytes >= maxBytes) {
      domTruncated = true;
      return;
    }
    const value = String(input);
    let offset = 0;
    while (offset < value.length && bytes < maxBytes) {
      const capacity = Math.min(maxBytes - bytes, 65536);
      const candidate = value.slice(offset, offset + capacity);
      const buffer = new Uint8Array(capacity);
      const progress = encoder.encodeInto(candidate, buffer);
      if (progress.read === 0) {
        domTruncated = true;
        break;
      }
      chunks.push(candidate.slice(0, progress.read));
      offset += progress.read;
      bytes += progress.written;
    }
    if (offset < value.length) {
      domTruncated = true;
    }
  }

  function appendEscaped(input, attribute) {
    const value = String(input);
    let offset = 0;
    while (offset < value.length && bytes < maxBytes) {
      const part = value.slice(offset, offset + 4096);
      const escaped = part.replace(attribute ? /[&<>\"]/g : /[&<>]/g, character => {
        if (character === "&") return "&amp;";
        if (character === "<") return "&lt;";
        if (character === ">") return "&gt;";
        return "&quot;";
      });
      appendRaw(escaped);
      offset += part.length;
    }
    if (offset < value.length) {
      domTruncated = true;
    }
  }

  function fitsURL(value) {
    if (value.length > maxURLBytes) return false;
    const buffer = new Uint8Array(maxURLBytes + 1);
    return encoder.encodeInto(value, buffer).read === value.length;
  }

  function collectResource(kind, rawURL) {
    if (!fitsURL(rawURL)) {
      urlTruncated = true;
      return;
    }
    let parsed;
    try {
      parsed = new URL(rawURL, document.baseURI);
    } catch (_) {
      return;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return;
    const resolved = parsed.href;
    if (!fitsURL(resolved)) {
      urlTruncated = true;
      return;
    }
    const destination = kind === "script" ? scripts : iframes;
    if (destination.length === maxResources) {
      if (kind === "script") scriptTruncated = true;
      else iframeTruncated = true;
      return;
    }
    destination.push(resolved);
  }

  const stack = [{node: document, entered: false, child: null, name: "", closes: false, rawText: false}];
  walk: while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    if (!frame.entered) {
      if (++work > maxWork) {
        traversalTruncated = true;
        break;
      }
      frame.entered = true;
      const node = frame.node;
      switch (node.nodeType) {
        case 1: {
          const name = String(node.localName || node.nodeName).toLowerCase();
          frame.name = name;
          frame.closes = !voidElements.has(name);
          frame.rawText = name === "script" || name === "style" || name === "xmp" || name === "iframe" ||
            name === "noembed" || name === "noframes" || name === "plaintext";
          appendRaw("<" + name);
          let source = null;
          const attributes = node.attributes;
          for (let index = 0; index < attributes.length; index++) {
            if (++work > maxWork) {
              traversalTruncated = true;
              break walk;
            }
            const attribute = attributes[index];
            const attributeName = String(attribute.name);
            const attributeValue = String(attribute.value);
            appendRaw(" " + attributeName + "=\"");
            appendEscaped(attributeValue, true);
            appendRaw("\"");
            if (attributeName.toLowerCase() === "src") source = attributeValue;
          }
          appendRaw(">");
          if (source !== null && (name === "script" || name === "iframe")) {
            collectResource(name, source);
          }
          frame.child = node.firstChild;
          break;
        }
        case 3: {
          const parent = stack.length > 1 ? stack[stack.length - 2] : null;
          if (parent !== null && parent.rawText) appendRaw(node.data);
          else appendEscaped(node.data, false);
          break;
        }
        case 4:
          appendRaw("<![CDATA[");
          appendRaw(node.data);
          appendRaw("]]>");
          break;
        case 7:
          appendRaw("<?" + node.target + " ");
          appendRaw(node.data);
          appendRaw("?>");
          break;
        case 8:
          appendRaw("<!--");
          appendRaw(node.data);
          appendRaw("-->");
          break;
        case 10:
          appendRaw("<!DOCTYPE ");
          appendRaw(node.name);
          appendRaw(">");
          break;
        default:
          frame.child = node.firstChild;
      }
    }

    if (frame.child !== null) {
      const child = frame.child;
      frame.child = child.nextSibling;
      stack.push({node: child, entered: false, child: null, name: "", closes: false, rawText: false});
      continue;
    }
    if (frame.closes) appendRaw("</" + frame.name + ">");
    stack.pop();
  }
  if (traversalTruncated) domTruncated = true;
  return {
    dom: chunks.join(""),
    script_urls: scripts,
    iframe_urls: iframes,
    dom_truncated: domTruncated,
    script_truncated: scriptTruncated,
    iframe_truncated: iframeTruncated,
    traversal_truncated: traversalTruncated,
    url_truncated: urlTruncated
  };
})()`

func (c *chromedpCapture) Close() error {
	c.once.Do(func() {
		c.stop()
		close(c.done)
	})
	<-c.done
	return c.err
}

func runChromedpWithCaller(taskCtx, callerCtx context.Context, actions ...chromedp.Action) error {
	if err := callerCtx.Err(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(taskCtx)
	stop := context.AfterFunc(callerCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	return chromedp.Run(runCtx, actions...)
}
