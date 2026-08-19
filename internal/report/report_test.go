package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

func TestBuildMinimizesSecretsAndSanitizesURLs(t *testing.T) {
	t.Parallel()
	result := scanner.Result{
		HTTP: httpanalyzer.Result{
			RequestedURL: "https://user:password@example.test/start?token=secret#fragment",
			FinalURL:     "https://example.test/final?session=secret",
			StatusCode:   403,
			Redirects: []httpanalyzer.Redirect{{
				From: "https://example.test/start?secret=value", To: "https://example.test/final?key=value", Status: 302,
			}},
			Warnings: []string{"response body was truncated"},
		},
		Detections: []scoring.Detection{{
			RuleID: "test.rule", Name: "Test detector", Vendor: "Test", Product: "Widget",
			Detected: true, ConditionMatched: true, MinimumEvidenceMet: true,
			EvidenceScore: 75, Score: 75, Level: scoring.LevelHigh,
			PositiveEvidence: []rules.EvidenceMatch{
				{EvidenceID: "script", Weight: 75, Signal: model.Signal{
					Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src",
					Value: "https://cdn.test/app.js?api_key=secret#fragment", URL: "https://example.test/?token=secret", Confidence: 1,
				}},
				{EvidenceID: "header", Weight: 10, Signal: model.Signal{
					Type: model.SignalTypeResponseHeader, Source: "http_analyzer", Key: "Authorization",
					Value: "header-secret", Confidence: 1,
				}},
				{EvidenceID: "cookie", Weight: 10, Signal: model.Signal{
					Type: model.SignalTypeCookie, Source: "http_analyzer", Key: "session",
					Value: "cookie-secret", Confidence: 1,
				}},
				{EvidenceID: "body", Weight: 10, Signal: model.Signal{
					Type: model.SignalTypePageContent, Source: "http_analyzer", Key: "body",
					Value: "<html>private-body</html>", Confidence: 1,
				}},
			},
		}},
	}

	report := Build("test-version", result)
	if got, want := report.RequestedURL, "https://example.test/start?redacted"; got != want {
		t.Errorf("RequestedURL = %q, want %q", got, want)
	}
	if got, want := report.FinalURL, "https://example.test/final?redacted"; got != want {
		t.Errorf("FinalURL = %q, want %q", got, want)
	}
	values := report.Detections[0].Evidence.Positive
	if got, want := values[0].Value, "https://cdn.test/app.js?redacted"; got != want {
		t.Errorf("script value = %q, want %q", got, want)
	}
	if got, want := values[0].URL, "https://example.test/?redacted"; got != want {
		t.Errorf("script URL = %q, want %q", got, want)
	}
	for _, evidence := range values[1:] {
		if evidence.Value != "" {
			t.Errorf("sensitive evidence %q value = %q, want empty", evidence.ID, evidence.Value)
		}
	}

	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", "secret", "header-secret", "cookie-secret", "private-body", "fragment"} {
		if strings.Contains(output.String(), secret) {
			t.Errorf("JSON disclosed %q: %s", secret, output.String())
		}
	}
}

func TestWriteJSONUsesVersionedStableShape(t *testing.T) {
	t.Parallel()
	report := Build("1.2.3", scanner.Result{HTTP: httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	}})
	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"schema_version", "tool_version", "requested_url", "final_url", "http", "detections"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing top-level field %q", key)
		}
	}
	if got := decoded["schema_version"]; got != float64(SchemaVersion) {
		t.Errorf("schema_version = %v, want %d", got, SchemaVersion)
	}
	if strings.Contains(output.String(), "null") {
		t.Errorf("JSON contains null collection: %s", output.String())
	}
	want, err := os.ReadFile(filepath.Join("testdata", "empty-report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != string(want) {
		t.Errorf("JSON contract changed\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteJSONPreservesCompleteDetectionShape(t *testing.T) {
	t.Parallel()
	result := scanner.Result{
		HTTP: httpanalyzer.Result{
			RequestedURL:  "https://user:password@example.test/start?token=secret#fragment",
			FinalURL:      "https://example.test/final?session=secret",
			StatusCode:    403,
			BodyTruncated: true,
			Redirects: []httpanalyzer.Redirect{{
				From: "https://example.test/start?token=secret",
				To:   "https://example.test/final?session=secret", Status: 302,
			}},
			Warnings: []string{"response body was truncated at 2097152 bytes"},
		},
		Detections: []scoring.Detection{{
			RuleID: "test.complete", Name: "Complete synthetic detector",
			Category: rules.CategoryCAPTCHAChallenge, Vendor: "Example", Product: "Widget",
			Detected: true, ConditionMatched: true, MinimumEvidenceMet: true,
			EvidenceScore: 82.5, Score: 82.5, Level: scoring.LevelHigh,
			PositiveEvidence: []rules.EvidenceMatch{{
				EvidenceID: "client-script", Description: "Documented client script", Weight: 100,
				Signal: model.Signal{
					Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src",
					Value: "https://challenges.cloudflare.com/turnstile/v0/api.js?key=secret#fragment",
					URL:   "https://example.test/final?session=secret", Confidence: 1,
				},
			}},
			NegativeEvidence: []rules.EvidenceMatch{{
				EvidenceID: "conflicting-cookie", Description: "Synthetic conflicting cookie", Weight: 12.5,
				Signal: model.Signal{
					Type: model.SignalTypeCookie, Source: "http_analyzer", Key: "session",
					Value: "cookie-secret", URL: "https://example.test/final?session=secret", Confidence: 0.8,
				},
			}},
			AmbiguousEvidence: []rules.EvidenceMatch{{
				EvidenceID: "shared-host", Description: "Shared infrastructure host", Weight: 5,
				Signal: model.Signal{
					Type: model.SignalTypeResourceHost, Source: "http_analyzer", Key: "host",
					Value: "shared.example", URL: "https://shared.example/frame?token=secret", Confidence: 0.5,
				},
			}},
			MissingPositiveEvidence: []string{"html-marker"},
			AppliedConflicts:        []scoring.AppliedConflict{{RuleID: "other.product", Penalty: 5}},
		}},
	}

	var output bytes.Buffer
	if err := WriteJSON(&output, Build("1.2.3", result)); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "complete-report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != string(want) {
		t.Errorf("complete JSON contract changed\ngot:\n%s\nwant:\n%s", got, want)
	}
	for _, secret := range []string{"password", "secret", "cookie-secret", "fragment"} {
		if strings.Contains(output.String(), secret) {
			t.Errorf("complete JSON disclosed %q: %s", secret, output.String())
		}
	}
}

func TestWriteTextExplainsDetectionsWithoutSecrets(t *testing.T) {
	t.Parallel()
	report := Build("dev", scanner.Result{
		HTTP: httpanalyzer.Result{RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200},
		Detections: []scoring.Detection{
			{
				RuleID: "detected", Name: "Detected product", Detected: true, Score: 75, Level: scoring.LevelHigh,
				PositiveEvidence: []rules.EvidenceMatch{{EvidenceID: "script", Weight: 75, Signal: model.Signal{
					Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src",
					Value: "https://cdn.test/api.js?token=secret", Confidence: 1,
				}}},
			},
			{RuleID: "missing", Name: "Missing product", Score: 0, Level: scoring.LevelNotDetected, MissingPositiveEvidence: []string{"marker"}},
		},
	})
	var output bytes.Buffer
	if err := WriteText(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Detected product", "75.0", "HIGH", "script", "api.js?redacted", "Missing product", "missing: marker"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output lacks %q: %s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "secret") {
		t.Errorf("text output disclosed a secret: %s", output.String())
	}
}

func TestWritersReturnOutputErrors(t *testing.T) {
	t.Parallel()
	writer := failingWriter{}
	if err := WriteJSON(writer, Report{}); err == nil {
		t.Error("WriteJSON() error = nil")
	}
	if err := WriteText(writer, Report{}); err == nil {
		t.Error("WriteText() error = nil")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
