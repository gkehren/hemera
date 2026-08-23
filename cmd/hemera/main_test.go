package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/browser"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/safeoutput"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
)

func TestRunShowsHelpWhenNoArgumentsAreProvided(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := run(context.Background(), nil, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("run() stdout = %q, want usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("run() stderr = %q, want empty output", stderr.String())
	}
}

func TestRunShowsVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := run(context.Background(), []string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if got, want := stdout.String(), "hemera "+toolVersion+"\n"; got != want {
		t.Errorf("run() stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("run() stderr = %q, want empty output", stderr.String())
	}
}

func TestRunShowsHelp(t *testing.T) {
	t.Parallel()

	for _, argument := range []string{"-h", "--help"} {
		argument := argument
		t.Run(argument, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			if code := run(context.Background(), []string{argument}, &stdout, &stderr); code != 0 {
				t.Fatalf("run() code = %d, want 0", code)
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Errorf("run() stdout = %q, want usage", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run() stderr = %q, want empty output", stderr.String())
			}
		})
	}
}

func TestRunHelpTakesPriorityOverVersion(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--version", "--help"},
		{"--help", "--version"},
	} {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != 0 {
				t.Fatalf("run() code = %d, want 0", code)
			}
			if !strings.Contains(stdout.String(), "Usage:") || strings.Contains(stdout.String(), "hemera "+toolVersion+"\n") {
				t.Errorf("run() stdout = %q, want root usage only", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run() stderr = %q, want empty output", stderr.String())
			}
		})
	}
}

func TestRunScanHelpTakesPriorityOverVersion(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"scan", "--version", "--help"},
		{"scan", "--help", "--version"},
	} {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != 0 {
				t.Fatalf("run() code = %d, want 0", code)
			}
			if !strings.Contains(stdout.String(), "hemera scan") || !strings.Contains(stdout.String(), "--format") {
				t.Errorf("run() stdout = %q, want scan usage", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run() stderr = %q, want empty output", stderr.String())
			}
		})
	}
}

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := run(context.Background(), []string{"unknown"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, want empty output", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unexpected argument "unknown"`) {
		t.Errorf("run() stderr = %q, want unexpected argument error", stderr.String())
	}
}

type fakeScanner struct {
	result scanner.Result
	err    error
}

func (f fakeScanner) Scan(context.Context, string) (scanner.Result, error) {
	return f.result, f.err
}

type scanRunnerFunc func(context.Context, string) (scanner.Result, error)

func (f scanRunnerFunc) Scan(ctx context.Context, target string) (scanner.Result, error) {
	return f(ctx, target)
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRunScanRequiresExactlyOneURL(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"one", "two"}} {
		var stdout, stderr bytes.Buffer
		if code := runScan(context.Background(), args, &stdout, &stderr, fakeScanner{}); code != 2 {
			t.Errorf("runScan(%v) code = %d, want 2", args, code)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "exactly one URL") {
			t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
		}
	}
}

func TestRunScanPrintsTextReportForAnyHTTPStatus(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/?redacted",
		FinalURL:     "https://example.test/login?redacted",
		StatusCode:   403,
		Redirects: []httpanalyzer.Redirect{{
			From: "https://example.test/?redacted", To: "https://example.test/login?redacted", Status: 302,
		}},
		BodyTruncated: true,
		Warnings:      []string{"response body was truncated"},
	})
	result.Detections = []scoring.Detection{{
		RuleID: "test.rule", Name: "Test product", Detected: true,
		ConditionMatched: true, MinimumEvidenceMet: true,
		EvidenceScore: 75, Score: 75, Level: scoring.LevelHigh,
		PositiveEvidence: []scoring.ScoredEvidence{{
			Match:           rules.EvidenceMatch{EvidenceID: "script", Group: "static_integration", Weight: 75},
			RawContribution: 75, Contribution: 75,
		}},
		PositiveEvidenceGroups: []scoring.EvidenceGroup{{
			ID: "static_integration", EvidenceIDs: []string{"script"},
			SelectedEvidenceID: "script", RawContribution: 75, Contribution: 75,
		}},
	}}
	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), []string{"https://example.test/"}, &stdout, &stderr, fakeScanner{result: result}); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q", stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{"Hemera scan report", "HTTP status: 403", "Body: truncated", "Test product", "HIGH"} {
		if !strings.Contains(output, expected) {
			t.Errorf("stdout lacks %q: %q", expected, output)
		}
	}
}

func TestRunScanPrintsJSONOnlyOnStdout(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 404,
	})
	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), []string{"--format", "json", "https://example.test/"}, &stdout, &stderr, fakeScanner{result: result}); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	for _, expected := range []string{`"schema_version": 6`, `"tool_version": "` + toolVersion + `"`, `"status_code": 404`, `"detections": []`} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("JSON lacks %q: %s", expected, stdout.String())
		}
	}
}

func TestRunScanHelpAndInvalidFormat(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--help"},
		{"--format", "json", "--help"},
		{"-h", "--format", "json"},
	} {
		args := args
		t.Run("help "+strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runScan(context.Background(), args, &stdout, &stderr, fakeScanner{}); code != 0 {
				t.Fatalf("code = %d", code)
			}
			if !strings.Contains(stdout.String(), "--format") || stderr.Len() != 0 {
				t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
			}
		})
	}
	t.Run("invalid format", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := runScan(context.Background(), []string{"--format", "xml", "https://example.test/"}, &stdout, &stderr, fakeScanner{}); code != 2 {
			t.Fatalf("code = %d", code)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "unsupported report format") {
			t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
		}
	})
}

func TestRunScanReportsOutputFailure(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	})
	var stderr bytes.Buffer
	if code := runScan(context.Background(), []string{"https://example.test/"}, errorWriter{}, &stderr, fakeScanner{result: result}); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "write report") {
		t.Errorf("stderr = %q, want report output error", stderr.String())
	}
}

func TestRunScanClassifiesFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"initial target", httpanalyzer.ErrInitialTarget, 2},
		{"network", errors.New("connection failed"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := runScan(context.Background(), []string{"https://example.test"}, &stdout, &stderr, fakeScanner{err: tt.err}); code != tt.code {
				t.Errorf("code = %d, want %d", code, tt.code)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "scan failed") {
				t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunScanCancellationWaitsForScannerCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	cleanupDone := make(chan struct{})
	runner := scanRunnerFunc(func(ctx context.Context, _ string) (scanner.Result, error) {
		close(started)
		defer close(cleanupDone)
		<-ctx.Done()
		return scanner.Result{}, fmt.Errorf(
			"cancel https://user:password@example.test/?token=SUPER_SECRET: %w",
			ctx.Err(),
		)
	})

	var stdout, stderr bytes.Buffer
	codeDone := make(chan int, 1)
	go func() {
		codeDone <- runScan(ctx, []string{"https://example.test/"}, &stdout, &stderr, runner)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scanner did not start")
	}
	cancel()

	select {
	case code := <-codeDone:
		if code != 1 {
			t.Fatalf("runScan() code = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runScan did not return after cancellation")
	}
	select {
	case <-cleanupDone:
	default:
		t.Fatal("scanner cleanup did not finish before runScan returned")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); got != "hemera: scan canceled\n" {
		t.Errorf("stderr = %q, want deterministic cancellation diagnostic", got)
	}
}

func TestRunScanRootCancellationDominatesConcurrentError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := scanRunnerFunc(func(context.Context, string) (scanner.Result, error) {
		cancel()
		return scanner.Result{}, fmt.Errorf(
			"reject https://example.test/?token=SUPER_SECRET: %w",
			httpanalyzer.ErrInitialTarget,
		)
	})

	var stdout, stderr bytes.Buffer
	if code := runScan(ctx, []string{"https://example.test/"}, &stdout, &stderr, runner); code != 1 {
		t.Fatalf("runScan() code = %d, want cancellation code 1", code)
	}
	if stdout.Len() != 0 || stderr.String() != "hemera: scan canceled\n" {
		t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
}

func TestRunScanRootCancellationDominatesConcurrentSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := scanRunnerFunc(func(context.Context, string) (scanner.Result, error) {
		cancel()
		return scanner.Result{}, nil
	})

	var stdout, stderr bytes.Buffer
	if code := runScan(ctx, []string{"https://example.test/"}, &stdout, &stderr, runner); code != 1 {
		t.Fatalf("runScan() code = %d, want cancellation code 1", code)
	}
	if stdout.Len() != 0 || stderr.String() != "hemera: scan canceled\n" {
		t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
}

func TestRunPassesCanceledRootContextToClassicScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"scan", "https://example.test/?token=SUPER_SECRET"}, &stdout, &stderr); code != 1 {
		t.Fatalf("run() code = %d, want 1; stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.String() != "hemera: scan canceled\n" {
		t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
}

// TestRunScanSanitizesDiagnosticsAndPreservesClassification proves the
// privacy boundary never changes control flow: exit codes are classified from
// the original wrapped error while the rendered text is minimized.
func TestRunScanSanitizesDiagnosticsAndPreservesClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		code int
	}{
		{
			name: "invalid initial target with sensitive URL exits 2",
			err: fmt.Errorf("fetch https://example.test/api?token=SUPER_SECRET failed: %w",
				httpanalyzer.ErrInitialTarget),
			code: 2,
		},
		{
			name: "runtime failure with sensitive URL exits 1",
			err:  errors.New("dial https://user:pw@example.test/api?token=SUPER_SECRET#frag refused"),
			code: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := runScan(context.Background(), []string{"https://example.test"}, &stdout, &stderr, fakeScanner{err: tt.err}); code != tt.code {
				t.Fatalf("code = %d, want %d", code, tt.code)
			}
			stderrText := stderr.String()
			for _, leaked := range []string{"SUPER_SECRET", "token=", "user:", "pw@", "#frag"} {
				if strings.Contains(stderrText, leaked) {
					t.Errorf("stderr leaks %q: %q", leaked, stderrText)
				}
			}
			if !strings.Contains(stderrText, "?redacted") || !strings.Contains(stderrText, "scan failed") {
				t.Errorf("stderr = %q, want sanitized scan-failure diagnostic", stderrText)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestRunPreservesHTTPOnlyInvalidTargetBehavior(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"scan", "ftp://example.test/"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run() code = %d, want 2; stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid or forbidden initial target") {
		t.Errorf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
}

func TestRunScanSupportsDeepModeAndRejectsInvalidMode(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	})
	for _, flag := range []string{"--deep", "--mode=deep", "--mode=default"} {
		var stdout, stderr bytes.Buffer
		if code := runScan(context.Background(), []string{flag, "https://example.test/"}, &stdout, &stderr, fakeScanner{result: result}); code != 0 {
			t.Fatalf("runScan(%q) code = %d, want 0; stderr = %q", flag, code, stderr.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), []string{"--mode=invalid", "https://example.test/"}, &stdout, &stderr, fakeScanner{result: result}); code != 2 {
		t.Fatalf("runScan(invalid mode) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unsupported scan mode "invalid"`) {
		t.Errorf("stderr = %q, want unsupported scan mode error", stderr.String())
	}
}

func TestBrowserConfigFromEnvironment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		deep         bool
		chromiumPath string
		want         browser.Config
	}{
		{name: "unset uses automatic discovery", want: browser.DefaultConfig()},
		{name: "empty uses automatic discovery", chromiumPath: "", want: browser.DefaultConfig()},
		{
			name:         "default mode uses explicit executable",
			chromiumPath: "chromium-test",
			want: func() browser.Config {
				config := browser.DefaultConfig()
				config.ExecutablePath = "chromium-test"
				return config
			}(),
		},
		{
			name:         "deep mode preserves deep limits and explicit executable",
			deep:         true,
			chromiumPath: "chromium-deep-test",
			want: func() browser.Config {
				config := browser.DeepConfig()
				config.ExecutablePath = "chromium-deep-test"
				return config
			}(),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lookup := func(name string) string {
				if name != chromiumPathEnvironment {
					t.Errorf("environment lookup name = %q, want %q", name, chromiumPathEnvironment)
				}
				return test.chromiumPath
			}
			if got := browserConfigFromEnvironment(test.deep, lookup); !reflect.DeepEqual(got, test.want) {
				t.Errorf("browserConfigFromEnvironment() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestNewScannerEngineUsesChromiumEnvironment(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing-chromium")

	tests := []struct {
		name         string
		deep         bool
		chromiumPath string
		wantErr      error
	}{
		{name: "unset", chromiumPath: ""},
		{name: "valid executable", chromiumPath: executable},
		{name: "valid executable in deep mode", deep: true, chromiumPath: executable},
		{name: "invalid executable", chromiumPath: missing, wantErr: browser.ErrInvalidConfig},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			lookup := func(string) string { return test.chromiumPath }
			engine, err := newScannerEngineWithEnvironment(test.deep, nil, lookup)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("newScannerEngineWithEnvironment() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && engine == nil {
				t.Fatal("newScannerEngineWithEnvironment() returned nil engine")
			}
		})
	}
}

func TestRunScanReportsInvalidChromiumEnvironment(t *testing.T) {
	t.Parallel()
	invalidPath := strings.Repeat("missing-chromium-", 100)
	lookup := func(string) string { return invalidPath }
	var stdout, stderr bytes.Buffer

	code := runScanWithEnvironment(
		context.Background(),
		[]string{"https://example.test/"},
		&stdout,
		&stderr,
		nil,
		lookup,
	)
	if code != 1 {
		t.Fatalf("runScanWithEnvironment() code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); !strings.Contains(got, "hemera: configure scanner: configure browser analyzer: invalid browser configuration") {
		t.Errorf("stderr = %q, want visible browser configuration failure", got)
	} else if len(got) > len("hemera: configure scanner: ")+safeoutput.MaxDiagnosticBytes+1 {
		t.Errorf("stderr length = %d, want bounded diagnostic", len(got))
	} else if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Errorf("stderr = %q, want one bounded diagnostic line", got)
	}
}

func scanResultWithHTTP(result httpanalyzer.Result) scanner.Result {
	redirects := make([]analysis.HTTPRedirect, 0, len(result.Redirects))
	for _, redirect := range result.Redirects {
		redirects = append(redirects, analysis.HTTPRedirect{
			From: redirect.From, To: redirect.To, Status: redirect.Status,
		})
	}
	return scanner.Result{Analyzers: []scanner.AnalyzerResult{{
		Observation: analysis.Observation{
			Source:   analysis.SourceHTTP,
			Warnings: append([]string{}, result.Warnings...),
			Metadata: analysis.Metadata{HTTP: &analysis.HTTPMetadata{
				RequestedURL: result.RequestedURL, FinalURL: result.FinalURL,
				StatusCode: result.StatusCode, Redirects: redirects,
				BodyTruncated: result.BodyTruncated,
			}},
		},
		Status: scanner.AnalyzerStatusComplete,
	}}}
}
