package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/tui"
	"github.com/gkehren/hemera/pkg/model"
)

// TestMain detaches tests from any real terminal so the interactive mode
// stays off unless a test explicitly opts in.
func TestMain(m *testing.M) {
	if os.Getenv(signalHelperEnv) == "1" {
		os.Exit(runSignalHelper())
	}
	stdinIsTTY = func() bool { return false }
	stdoutIsTTY = func() bool { return false }
	os.Exit(m.Run())
}

func TestRunStartsInteractiveModeOnlyOnTerminals(t *testing.T) {
	originalStdin, originalStdout := stdinIsTTY, stdoutIsTTY
	originalWizard := runWizard
	t.Cleanup(func() {
		stdinIsTTY, stdoutIsTTY = originalStdin, originalStdout
		runWizard = originalWizard
	})

	tests := []struct {
		name       string
		stdin      bool
		stdout     bool
		wantWizard bool
	}{
		{name: "terminals launch wizard", stdin: true, stdout: true, wantWizard: true},
		{name: "piped stdin keeps usage", stdin: false, stdout: true},
		{name: "piped stdout keeps usage", stdin: true, stdout: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			stdinIsTTY = func() bool { return testCase.stdin }
			stdoutIsTTY = func() bool { return testCase.stdout }
			wizardCalls := 0
			runWizard = func(context.Context) (tui.Options, error) {
				wizardCalls++
				return tui.Options{}, tui.ErrAborted
			}

			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), nil, &stdout, &stderr); code != 0 {
				t.Fatalf("run() code = %d, want 0", code)
			}
			if got := wizardCalls > 0; got != testCase.wantWizard {
				t.Fatalf("wizard invoked = %v, want %v", got, testCase.wantWizard)
			}
			if testCase.wantWizard {
				if !strings.Contains(stderr.String(), "canceled") {
					t.Errorf("stderr = %q, want cancellation note", stderr.String())
				}
				return
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Errorf("stdout = %q, want usage", stdout.String())
			}
		})
	}
}

func TestRunInteractiveReportsWizardAbort(t *testing.T) {
	originalWizard := runWizard
	t.Cleanup(func() { runWizard = originalWizard })
	runWizard = func(context.Context) (tui.Options, error) { return tui.Options{}, tui.ErrAborted }

	var stdout, stderr bytes.Buffer
	if code := runInteractive(context.Background(), &stdout, &stderr); code != 0 {
		t.Fatalf("runInteractive() code = %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "canceled") {
		t.Errorf("stderr = %q, want cancellation note", stderr.String())
	}
}

func TestRunInteractivePropagatesWizardFailure(t *testing.T) {
	originalWizard := runWizard
	t.Cleanup(func() { runWizard = originalWizard })
	runWizard = func(context.Context) (tui.Options, error) {
		return tui.Options{}, errors.New("terminal unavailable")
	}

	var stdout, stderr bytes.Buffer
	if code := runInteractive(context.Background(), &stdout, &stderr); code != 1 {
		t.Fatalf("runInteractive() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "terminal unavailable") {
		t.Errorf("stderr = %q, want wizard error", stderr.String())
	}
}

func TestRunInteractiveExternalCancellationDominatesWizardAbort(t *testing.T) {
	originalWizard := runWizard
	t.Cleanup(func() { runWizard = originalWizard })
	started := make(chan struct{})
	runWizard = func(ctx context.Context) (tui.Options, error) {
		close(started)
		<-ctx.Done()
		// Model the reported race: even if the UI reports an abort concurrently,
		// the canceled application context is authoritative.
		return tui.Options{}, tui.ErrAborted
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr bytes.Buffer
	codeDone := make(chan int, 1)
	go func() { codeDone <- runInteractive(ctx, &stdout, &stderr) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("wizard did not start")
	}
	cancel()

	select {
	case code := <-codeDone:
		if code != 1 {
			t.Fatalf("runInteractive() code = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runInteractive did not return after external cancellation")
	}
	if stdout.Len() != 0 || stderr.String() != "hemera: canceled\n" {
		t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
}

func TestRunInteractiveCancellationBetweenWizardAndScanIsFatal(t *testing.T) {
	originalWizard := runWizard
	originalProgress := runProgressView
	t.Cleanup(func() {
		runWizard = originalWizard
		runProgressView = originalProgress
	})
	ctx, cancel := context.WithCancel(context.Background())
	runWizard = func(context.Context) (tui.Options, error) {
		cancel()
		return tui.Options{URL: "https://example.test/"}, nil
	}
	progressCalls := 0
	runProgressView = func(context.Context, io.Writer, []string, string, string, <-chan tui.Msg) error {
		progressCalls++
		return nil
	}

	var stdout, stderr bytes.Buffer
	if code := runInteractive(ctx, &stdout, &stderr); code != 1 {
		t.Fatalf("runInteractive() code = %d, want 1", code)
	}
	if stdout.Len() != 0 || stderr.String() != "hemera: canceled\n" {
		t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
	if progressCalls != 0 {
		t.Fatalf("progress view calls = %d, want 0", progressCalls)
	}
}

func TestRunInteractiveScanPrintsSummaryAndTextReport(t *testing.T) {
	restoreQuietProgressView(t)
	engine := newStubEngine(t, stubAnalyzer{
		source:      analysis.SourceHTTP,
		observation: analysis.Observation{Source: analysis.SourceHTTP},
	}, scanner.FailurePolicyContinue)

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: "https://example.test/", Deep: false}
	if code := runInteractiveScan(context.Background(), opts, &stdout, &stderr, engine); code != 0 {
		t.Fatalf("runInteractiveScan() code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{
		"Hemera scan report", "https://example.test/",
		"0 detected", "Not detected", "Insufficient coverage",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("output lacks %q: %q", expected, output)
		}
	}
}

func TestRunInteractiveScanClassifiesFailures(t *testing.T) {
	tests := []struct {
		name       string
		analyzer   stubAnalyzer
		wantCode   int
		wantStderr string
	}{
		{
			name: "invalid initial target",
			analyzer: stubAnalyzer{
				source:      analysis.SourceHTTP,
				observation: analysis.Observation{Source: analysis.SourceHTTP},
				err:         httpanalyzer.ErrInitialTarget,
			},
			wantCode:   2,
			wantStderr: "scan failed",
		},
		{
			name: "runtime failure",
			analyzer: stubAnalyzer{
				source:      analysis.SourceHTTP,
				observation: analysis.Observation{Source: analysis.SourceHTTP},
				err:         errors.New("connection refused"),
			},
			wantCode:   1,
			wantStderr: "scan failed",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			restoreQuietProgressView(t)
			engine := newStubEngine(t, testCase.analyzer, scanner.FailurePolicyAbort)

			var stdout, stderr bytes.Buffer
			opts := tui.Options{URL: "https://example.test/"}
			if code := runInteractiveScan(context.Background(), opts, &stdout, &stderr, engine); code != testCase.wantCode {
				t.Fatalf("code = %d, want %d", code, testCase.wantCode)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), testCase.wantStderr) {
				t.Errorf("stderr = %q, want %q", stderr.String(), testCase.wantStderr)
			}
		})
	}
}

// TestRunInteractiveScanSanitizesScanFailure proves the interactive path
// renders the same bounded, secret-free diagnostic as the classic scan.
func TestRunInteractiveScanSanitizesScanFailure(t *testing.T) {
	restoreQuietProgressView(t)
	engine := newStubEngine(t, stubAnalyzer{
		source:      analysis.SourceHTTP,
		observation: analysis.Observation{Source: analysis.SourceHTTP},
		err:         fmt.Errorf("request to https://example.test/api?token=SUPER_SECRET failed"),
	}, scanner.FailurePolicyAbort)

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: "https://example.test/"}
	if code := runInteractiveScan(context.Background(), opts, &stdout, &stderr, engine); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	stderrText := stderr.String()
	if strings.Contains(stderrText, "SUPER_SECRET") || strings.Contains(stderrText, "token=") {
		t.Errorf("stderr leaks the secret: %q", stderrText)
	}
	if !strings.Contains(stderrText, "?redacted") || !strings.Contains(stderrText, "scan failed") {
		t.Errorf("stderr = %q, want sanitized scan-failure diagnostic", stderrText)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no report", stdout.String())
	}
}

// TestRunInteractiveScanSeparatesScanURLFromDisplayURL proves the
// data-flow separation: the analyzer observes the exact user target while
// the progress view receives only the minimized display copy.
func TestRunInteractiveScanSeparatesScanURLFromDisplayURL(t *testing.T) {
	restoreQuietProgressView(t)
	rawTarget := "https://example.test/api?token=SUPER_SECRET"

	var observedURLs []string
	engine := newStubEngine(t, stubAnalyzer{
		source:      analysis.SourceHTTP,
		observation: analysis.Observation{Source: analysis.SourceHTTP},
		observe: func(_ context.Context, target analysis.Target) (analysis.Observation, error) {
			observedURLs = append(observedURLs, target.URL)
			return analysis.Observation{Source: analysis.SourceHTTP}, nil
		},
	}, scanner.FailurePolicyContinue)

	var viewTargets []string
	original := runProgressView
	t.Cleanup(func() { runProgressView = original })
	runProgressView = func(_ context.Context, _ io.Writer, _ []string, target, _ string, msgs <-chan tui.Msg) error {
		viewTargets = append(viewTargets, target)
		for msg := range msgs {
			if msg.Final {
				return nil
			}
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: rawTarget}
	if code := runInteractiveScan(context.Background(), opts, &stdout, &stderr, engine); code != 0 {
		t.Fatalf("runInteractiveScan() code = %d, stderr = %q", code, stderr.String())
	}
	if len(observedURLs) != 1 || observedURLs[0] != rawTarget {
		t.Errorf("analyzer observed %q, want the exact original target", observedURLs)
	}
	if len(viewTargets) != 1 || viewTargets[0] != "https://example.test/api?redacted" {
		t.Errorf("view received %q, want the minimized display copy", viewTargets)
	}
}

type stubAnalyzer struct {
	source      string
	observation analysis.Observation
	err         error
	observe     func(context.Context, analysis.Target) (analysis.Observation, error)
}

func (a stubAnalyzer) Source() string { return a.source }

func (a stubAnalyzer) Capabilities() []model.SignalType {
	if implemented := analysis.SupportedSignalTypes(a.source); len(implemented) > 0 {
		return implemented
	}
	return []model.SignalType{
		model.SignalTypeResponseHeader,
		model.SignalTypeCookie,
		model.SignalTypeScriptURL,
		model.SignalTypeNetworkRequest,
		model.SignalTypeNetworkResponse,
		model.SignalTypeDOMSelector,
		model.SignalTypeIframeURL,
		model.SignalTypeJSGlobal,
		model.SignalTypeDNSRecord,
		model.SignalTypeTLSProperty,
		model.SignalTypeRedirect,
		model.SignalTypePageContent,
		model.SignalTypeResourceHost,
	}
}

func (a stubAnalyzer) Observe(ctx context.Context, target analysis.Target) (analysis.Observation, error) {
	if a.observe != nil {
		return a.observe(ctx, target)
	}
	return a.observation, a.err
}

func newStubEngine(t *testing.T, analyzer stubAnalyzer, policy scanner.FailurePolicy) *scanner.Scanner {
	t.Helper()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scanner.New(scanner.Config{
		Analyzers: []scanner.AnalyzerConfig{
			{Analyzer: analyzer, FailurePolicy: policy},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// restoreQuietProgressView replaces the live progress view with a fake that
// mirrors the production contract: the real view exits without an error as
// soon as the scan goroutine delivers its final message; the producer closes
// the channel afterwards, once the scan goroutine has joined.
func restoreQuietProgressView(t *testing.T) {
	t.Helper()
	original := runProgressView
	t.Cleanup(func() { runProgressView = original })
	runProgressView = func(_ context.Context, _ io.Writer, _ []string, _ string, _ string, msgs <-chan tui.Msg) error {
		for msg := range msgs {
			if msg.Final {
				return nil
			}
		}
		return nil
	}
}

// TestRunInteractiveScanJoinsScanBeforeReturn proves the cancellation
// ordering: when the progress view exits early, the scan observes context
// cancellation and completes its deferred cleanup (for example closing the
// sandboxed browser session) BEFORE runInteractiveScan returns. os.Exit would
// otherwise skip that cleanup.
func TestRunInteractiveScanJoinsScanBeforeReturn(t *testing.T) {
	started := make(chan struct{})
	original := runProgressView
	t.Cleanup(func() { runProgressView = original })
	// The view "exits" only once the analyzer is mid-flight, exactly like a
	// Ctrl+C arriving during a live scan: the model quits cleanly, so the
	// real RunProgress returns the view-canceled sentinel rather than nil.
	runProgressView = func(context.Context, io.Writer, []string, string, string, <-chan tui.Msg) error {
		<-started
		return tui.ErrViewCanceled
	}

	var orderMu sync.Mutex
	var order []string
	cleanupDone := make(chan struct{})
	engine := newStubEngine(t, stubAnalyzer{
		source: analysis.SourceHTTP,
		observe: func(ctx context.Context, _ analysis.Target) (analysis.Observation, error) {
			close(started)
			<-ctx.Done() // analyzer is mid-flight when the view exits
			orderMu.Lock()
			order = append(order, "cleanup")
			orderMu.Unlock()
			close(cleanupDone)
			return analysis.Observation{Source: analysis.SourceHTTP}, ctx.Err()
		},
	}, scanner.FailurePolicyContinue)

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: "https://example.test/"}
	code := runInteractiveScan(context.Background(), opts, &stdout, &stderr, engine)
	orderMu.Lock()
	order = append(order, "returned")
	defer orderMu.Unlock()

	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "canceled") {
		t.Errorf("stderr = %q, want cancellation note", stderr.String())
	}
	if strings.Contains(stderr.String(), "scan failed") {
		t.Errorf("stderr = %q, want no scan-failure report for a user cancel", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no report", stdout.String())
	}
	select {
	case <-cleanupDone:
	default:
		t.Fatal("analyzer cleanup did not complete before runInteractiveScan returned")
	}
	if len(order) != 2 || order[0] != "cleanup" || order[1] != "returned" {
		t.Fatalf("ordering = %#v, want [cleanup returned]", order)
	}
}

func TestRunInteractiveScanJoinsAfterExternalCancellation(t *testing.T) {
	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	analyzerStarted := make(chan struct{})
	viewStarted := make(chan struct{})
	cleanupDone := make(chan struct{})

	original := runProgressView
	t.Cleanup(func() { runProgressView = original })
	runProgressView = func(ctx context.Context, _ io.Writer, _ []string, _ string, _ string, _ <-chan tui.Msg) error {
		close(viewStarted)
		<-ctx.Done()
		return ctx.Err()
	}

	engine := newStubEngine(t, stubAnalyzer{
		source: analysis.SourceHTTP,
		observe: func(ctx context.Context, _ analysis.Target) (analysis.Observation, error) {
			close(analyzerStarted)
			defer close(cleanupDone)
			<-ctx.Done()
			return analysis.Observation{Source: analysis.SourceHTTP}, ctx.Err()
		},
	}, scanner.FailurePolicyContinue)

	var stdout, stderr bytes.Buffer
	codeDone := make(chan int, 1)
	go func() {
		codeDone <- runInteractiveScan(
			parentCtx,
			tui.Options{URL: "https://example.test/"},
			&stdout,
			&stderr,
			engine,
		)
	}()

	for name, started := range map[string]<-chan struct{}{
		"analyzer": analyzerStarted,
		"view":     viewStarted,
	} {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not start", name)
		}
	}
	cancelParent()

	select {
	case code := <-codeDone:
		if code != 1 {
			t.Fatalf("runInteractiveScan() code = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runInteractiveScan did not return after external cancellation")
	}
	select {
	case <-cleanupDone:
	default:
		t.Fatal("analyzer cleanup did not finish before runInteractiveScan returned")
	}
	if stdout.Len() != 0 || stderr.String() != "hemera: canceled\n" {
		t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
}

// TestRunInteractiveScanDetachesProgressCallback proves a Scanner that went
// through the interactive flow can be scanned again without panicking on the
// closed progress channel.
func TestRunInteractiveScanDetachesProgressCallback(t *testing.T) {
	restoreQuietProgressView(t)
	engine := newStubEngine(t, stubAnalyzer{
		source:      analysis.SourceHTTP,
		observation: analysis.Observation{Source: analysis.SourceHTTP},
	}, scanner.FailurePolicyContinue)

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: "https://example.test/"}
	if code := runInteractiveScan(context.Background(), opts, &stdout, &stderr, engine); code != 0 {
		t.Fatalf("runInteractiveScan() code = %d", code)
	}

	// Reusing the engine must be safe: the observer was detached after the
	// first run, so no event is sent into the closed channel.
	if _, err := engine.Scan(context.Background(), "https://example.test/"); err != nil {
		t.Fatalf("second Scan() error = %v, want nil", err)
	}
}

func TestRunInteractiveScanHandlesEarlyViewExit(t *testing.T) {
	tests := []struct {
		name       string
		runErr     error
		wantCode   int
		wantStderr string
	}{
		{
			// The realistic Ctrl+C path: the model quits cleanly, so
			// RunProgress reports the view-canceled sentinel.
			name:       "view-canceled sentinel renders no report",
			runErr:     tui.ErrViewCanceled,
			wantCode:   0,
			wantStderr: "canceled",
		},
		{
			name:       "unexpected view context cancellation is fatal",
			runErr:     context.Canceled,
			wantCode:   1,
			wantStderr: "canceled",
		},
		{
			name:       "broken view fails without report",
			runErr:     errors.New("terminal unavailable"),
			wantCode:   1,
			wantStderr: "terminal unavailable",
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			restoreQuietProgressView(t)
			engine := newStubEngine(t, stubAnalyzer{
				source:      analysis.SourceHTTP,
				observation: analysis.Observation{Source: analysis.SourceHTTP},
			}, scanner.FailurePolicyContinue)
			original := runProgressView
			t.Cleanup(func() { runProgressView = original })
			runProgressView = func(context.Context, io.Writer, []string, string, string, <-chan tui.Msg) error {
				return testCase.runErr
			}

			var stdout, stderr bytes.Buffer
			opts := tui.Options{URL: "https://example.test/"}
			if code := runInteractiveScan(context.Background(), opts, &stdout, &stderr, engine); code != testCase.wantCode {
				t.Fatalf("code = %d, want %d", code, testCase.wantCode)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want no report after early exit", stdout.String())
			}
			if !strings.Contains(stderr.String(), testCase.wantStderr) {
				t.Errorf("stderr = %q, want %q", stderr.String(), testCase.wantStderr)
			}
		})
	}
}

func TestRunInteractiveMultiScanAggregatesPagesWithSummary(t *testing.T) {
	var viewLabels []string
	original := runProgressView
	t.Cleanup(func() { runProgressView = original })
	runProgressView = func(_ context.Context, _ io.Writer, _ []string, _ string, pageLabel string, msgs <-chan tui.Msg) error {
		viewLabels = append(viewLabels, pageLabel)
		for msg := range msgs {
			if msg.Final {
				return nil
			}
		}
		return nil
	}
	engine := newStubEngine(t, stubAnalyzer{
		source:      analysis.SourceHTTP,
		observation: analysis.Observation{Source: analysis.SourceHTTP},
	}, scanner.FailurePolicyContinue)

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: "https://a.test/", Pages: []string{"https://b.test/"}}
	code := runInteractiveMultiScan(context.Background(), opts,
		[]string{"https://a.test/", "https://b.test/"}, &stdout, &stderr, engine)
	if code != 0 {
		t.Fatalf("runInteractiveMultiScan() code = %d, stderr = %q", code, stderr.String())
	}
	if len(viewLabels) != 2 || viewLabels[0] != "Page 1 of 2" || viewLabels[1] != "Page 2 of 2" {
		t.Errorf("view labels = %#v, want one labeled view per page", viewLabels)
	}
	if !strings.Contains(stdout.String(), "Page 1 of 2") || !strings.Contains(stdout.String(), "Page 2 of 2") {
		t.Errorf("report lacks per-page sections: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Summary across pages") {
		t.Errorf("report lacks the cross-page summary: %q", stdout.String())
	}
}

func TestRunInteractiveMultiScanContinuesAfterPageFailure(t *testing.T) {
	restoreQuietProgressView(t)
	engine := newStubEngine(t, stubAnalyzer{
		source: analysis.SourceHTTP,
		observe: func(_ context.Context, target analysis.Target) (analysis.Observation, error) {
			if target.URL == "https://broken.test/" {
				return analysis.Observation{Source: analysis.SourceHTTP}, errors.New("connection refused")
			}
			return analysis.Observation{Source: analysis.SourceHTTP}, nil
		},
	}, scanner.FailurePolicyAbort)

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: "https://a.test/"}
	code := runInteractiveMultiScan(context.Background(), opts,
		[]string{"https://a.test/", "https://broken.test/"}, &stdout, &stderr, engine)
	if code != 0 {
		t.Fatalf("runInteractiveMultiScan() code = %d, want 0 when at least one page succeeded", code)
	}
	if !strings.Contains(stderr.String(), "page 2") {
		t.Errorf("stderr = %q, want the failed page notice", stderr.String())
	}
	if !strings.Contains(stdout.String(), "page scan failed") {
		t.Errorf("report lacks the failed page entry: %q", stdout.String())
	}
}

func TestRunInteractiveMultiScanKeepsCompletedPagesOnCancel(t *testing.T) {
	calls := 0
	original := runProgressView
	t.Cleanup(func() { runProgressView = original })
	runProgressView = func(_ context.Context, _ io.Writer, _ []string, _ string, _ string, msgs <-chan tui.Msg) error {
		calls++
		if calls == 1 {
			for msg := range msgs {
				if msg.Final {
					return nil
				}
			}
			return nil
		}
		return tui.ErrViewCanceled
	}
	engine := newStubEngine(t, stubAnalyzer{
		source:      analysis.SourceHTTP,
		observation: analysis.Observation{Source: analysis.SourceHTTP},
	}, scanner.FailurePolicyContinue)

	var stdout, stderr bytes.Buffer
	opts := tui.Options{URL: "https://a.test/"}
	code := runInteractiveMultiScan(context.Background(), opts,
		[]string{"https://a.test/", "https://b.test/"}, &stdout, &stderr, engine)
	if code != 0 {
		t.Errorf("runInteractiveMultiScan() code = %d, want 0 after user cancellation", code)
	}
	if !strings.Contains(stderr.String(), "canceled") {
		t.Errorf("stderr = %q, want the cancellation note", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Hemera scan report") {
		t.Errorf("stdout = %q, want the report of completed pages", stdout.String())
	}
}
