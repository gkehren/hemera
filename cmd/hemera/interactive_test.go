package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/tui"
)

// TestMain detaches tests from any real terminal so the interactive mode
// stays off unless a test explicitly opts in.
func TestMain(m *testing.M) {
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
			runWizard = func() (tui.Options, error) {
				wizardCalls++
				return tui.Options{}, tui.ErrAborted
			}

			var stdout, stderr bytes.Buffer
			if code := run(nil, &stdout, &stderr); code != 0 {
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
	runWizard = func() (tui.Options, error) { return tui.Options{}, tui.ErrAborted }

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
	runWizard = func() (tui.Options, error) { return tui.Options{}, errors.New("terminal unavailable") }

	var stdout, stderr bytes.Buffer
	if code := runInteractive(context.Background(), &stdout, &stderr); code != 1 {
		t.Fatalf("runInteractive() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "terminal unavailable") {
		t.Errorf("stderr = %q, want wizard error", stderr.String())
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

type stubAnalyzer struct {
	source      string
	observation analysis.Observation
	err         error
	observe     func(context.Context, analysis.Target) (analysis.Observation, error)
}

func (a stubAnalyzer) Source() string { return a.source }

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
// drains the message channel until the scan goroutine closes it and returns
// the final outcome it carried. This mirrors the production ordering in which
// the view exits only after the outcome is delivered, keeping the deferred
// cancellation race-free and deterministic.
func restoreQuietProgressView(t *testing.T) {
	t.Helper()
	original := runProgressView
	t.Cleanup(func() { runProgressView = original })
	runProgressView = func(_ context.Context, _ io.Writer, _ []string, _ string, msgs <-chan tui.Msg) (tui.Outcome, error) {
		var final tui.Outcome
		for msg := range msgs {
			if msg.Final {
				final = msg.Outcome
			}
		}
		return final, nil
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
			name:       "canceled view renders no report",
			runErr:     context.Canceled,
			wantCode:   0,
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
			runProgressView = func(_ context.Context, _ io.Writer, _ []string, _ string, msgs <-chan tui.Msg) (tui.Outcome, error) {
				// Drain so the scan goroutine never leaks; the early exit
				// discards its outcome exactly like the real view.
				for range msgs {
				}
				return tui.Outcome{}, testCase.runErr
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
