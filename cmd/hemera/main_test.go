package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
)

func TestRunShowsHelpWhenNoArgumentsAreProvided(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := run(nil, &stdout, &stderr); code != 0 {
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

	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if got, want := stdout.String(), "hemera dev\n"; got != want {
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

			if code := run([]string{argument}, &stdout, &stderr); code != 0 {
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

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := run([]string{"unknown"}, &stdout, &stderr); code != 2 {
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
	result := scanner.Result{HTTP: httpanalyzer.Result{
		RequestedURL: "https://example.test/?redacted",
		FinalURL:     "https://example.test/login?redacted",
		StatusCode:   403,
		Redirects: []httpanalyzer.Redirect{{
			From: "https://example.test/?redacted", To: "https://example.test/login?redacted", Status: 302,
		}},
		BodyTruncated: true,
		Warnings:      []string{"response body was truncated"},
	}, Detections: []scoring.Detection{{
		RuleID: "test.rule", Name: "Test product", Detected: true, Score: 75, Level: scoring.LevelHigh,
		PositiveEvidence: []rules.EvidenceMatch{{EvidenceID: "script", Weight: 75}},
	}}}
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
	result := scanner.Result{HTTP: httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 404,
	}}
	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), []string{"--format", "json", "https://example.test/"}, &stdout, &stderr, fakeScanner{result: result}); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	for _, expected := range []string{`"schema_version": 1`, `"status_code": 404`, `"detections": []`} {
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
	result := scanner.Result{HTTP: httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	}}
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
