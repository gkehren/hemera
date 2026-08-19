package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/pkg/model"
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
	result httpanalyzer.Result
	err    error
}

func (f fakeScanner) Analyze(context.Context, string) (httpanalyzer.Result, error) {
	return f.result, f.err
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

func TestRunScanPrintsSafeDiagnosticForAnyHTTPStatus(t *testing.T) {
	t.Parallel()
	result := httpanalyzer.Result{
		RequestedURL: "https://example.test/?redacted",
		FinalURL:     "https://example.test/login?redacted",
		StatusCode:   403,
		Redirects: []httpanalyzer.Redirect{{
			From: "https://example.test/?redacted", To: "https://example.test/login?redacted", Status: 302,
		}},
		BodyTruncated: true,
		Warnings:      []string{"response body was truncated"},
		Signals: []model.Signal{
			{Type: model.SignalTypeResponseHeader, Source: "http_analyzer", Key: "Authorization", Value: "header-secret", Confidence: 1},
			{Type: model.SignalTypeCookie, Source: "http_analyzer", Key: "session", Value: "cookie-secret", Confidence: 1},
			{Type: model.SignalTypePageContent, Source: "http_analyzer", Key: "body", Value: "<html>private</html>", Confidence: 1},
			{Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src", Value: "https://cdn.test/app.js?redacted", Confidence: 1},
		},
	}
	var stdout, stderr bytes.Buffer
	if code := runScan(context.Background(), []string{"https://example.test/"}, &stdout, &stderr, fakeScanner{result: result}); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q", stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{"unstable format", "Status: 403", "Body truncated: true", "app.js?redacted", "[content omitted]"} {
		if !strings.Contains(output, expected) {
			t.Errorf("stdout lacks %q: %q", expected, output)
		}
	}
	for _, secret := range []string{"header-secret", "cookie-secret", "<html>private</html>"} {
		if strings.Contains(output, secret) {
			t.Errorf("stdout disclosed %q", secret)
		}
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
