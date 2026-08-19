package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

func TestBuildMinimizesSecretsAndSanitizesURLs(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://user:password@example.test/start?token=secret#fragment",
		FinalURL:     "https://example.test/final?session=secret",
		StatusCode:   403,
		Redirects: []httpanalyzer.Redirect{{
			From: "https://example.test/start?secret=value", To: "https://example.test/final?key=value", Status: 302,
		}},
		Warnings: []string{"response body was truncated"},
	})
	result.Detections = []scoring.Detection{{
		RuleID: "test.rule", Name: "Test detector", Vendor: "Test", Product: "Widget",
		Detected: true, ConditionMatched: true, MinimumEvidenceMet: true,
		EvidenceScore: 75, Score: 75, Level: scoring.LevelHigh,
		PositiveEvidenceGroups: []scoring.EvidenceGroup{{
			ID: "static_integration", EvidenceIDs: []string{"script", "header", "cookie", "body"},
			SelectedEvidenceID: "script", RawContribution: 105, Contribution: 75,
		}},
		PositiveEvidence: []scoring.ScoredEvidence{
			{Match: rules.EvidenceMatch{EvidenceID: "script", Group: "static_integration", Weight: 75, Signal: model.Signal{
				Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src",
				Value: "https://cdn.test/app.js?api_key=secret#fragment", URL: "https://example.test/?token=secret", Confidence: 1,
			}}, RawContribution: 75, Contribution: 75},
			{Match: rules.EvidenceMatch{EvidenceID: "header", Group: "static_integration", Weight: 10, Signal: model.Signal{
				Type: model.SignalTypeResponseHeader, Source: "http_analyzer", Key: "Authorization",
				Value: "header-secret", Confidence: 1,
			}}, RawContribution: 10},
			{Match: rules.EvidenceMatch{EvidenceID: "cookie", Group: "static_integration", Weight: 10, Signal: model.Signal{
				Type: model.SignalTypeCookie, Source: "http_analyzer", Key: "session",
				Value: "cookie-secret", Confidence: 1,
			}}, RawContribution: 10},
			{Match: rules.EvidenceMatch{EvidenceID: "body", Group: "static_integration", Weight: 10, Signal: model.Signal{
				Type: model.SignalTypePageContent, Source: "http_analyzer", Key: "body",
				Value: "<html>private-body</html>", Confidence: 1,
			}}, RawContribution: 10},
		},
	}}

	report := Build("test-version", result)
	if got, want := report.RequestedURL, "https://example.test/start?redacted"; got != want {
		t.Errorf("RequestedURL = %q, want %q", got, want)
	}
	if got, want := report.FinalURL, "https://example.test/final?redacted"; got == nil || *got != want {
		t.Errorf("FinalURL = %v, want %q", got, want)
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
		if evidence.RawContribution != 10 || evidence.Contribution != 0 {
			t.Errorf("correlated evidence %q contributions = %v/%v, want 10/0", evidence.ID, evidence.RawContribution, evidence.Contribution)
		}
	}
	groups := report.Detections[0].PositiveEvidenceGroups
	if len(groups) != 1 || groups[0].RawContribution != 105 || groups[0].Contribution != 75 {
		t.Errorf("positive evidence groups = %#v, want raw 105 capped to 75", groups)
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
	report := Build("1.2.3", scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	}))
	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"schema_version", "tool_version", "requested_url", "final_url", "http", "analyzers", "detections"} {
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
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL:  "https://user:password@example.test/start?token=secret#fragment",
		FinalURL:      "https://example.test/final?session=secret",
		StatusCode:    403,
		BodyTruncated: true,
		Redirects: []httpanalyzer.Redirect{{
			From: "https://example.test/start?token=secret",
			To:   "https://example.test/final?session=secret", Status: 302,
		}},
		Warnings: []string{"response body was truncated at 2097152 bytes"},
	})
	result.Detections = []scoring.Detection{{
		RuleID: "test.complete", Name: "Complete synthetic detector",
		Category: rules.CategoryCAPTCHAChallenge, Vendor: "Example", Product: "Widget",
		Detected: true, ConditionMatched: true, MinimumEvidenceMet: true,
		EvidenceScore: 82.5, Score: 82.5, Level: scoring.LevelHigh,
		PositiveEvidenceGroups: []scoring.EvidenceGroup{{
			ID: "static_integration", EvidenceIDs: []string{"client-script"},
			SelectedEvidenceID: "client-script", RawContribution: 100, Contribution: 100,
		}},
		PositiveEvidence: []scoring.ScoredEvidence{{
			Match: rules.EvidenceMatch{
				EvidenceID: "client-script", Group: "static_integration",
				Description: "Documented client script", Weight: 100,
				Signal: model.Signal{
					Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src",
					Value: "https://challenges.cloudflare.com/turnstile/v0/api.js?key=secret#fragment",
					URL:   "https://example.test/final?session=secret", Confidence: 1,
				},
			},
			RawContribution: 100, Contribution: 100,
		}},
		NegativeEvidence: []scoring.ScoredEvidence{{
			Match: rules.EvidenceMatch{
				EvidenceID: "conflicting-cookie", Description: "Synthetic conflicting cookie", Weight: 12.5,
				Signal: model.Signal{
					Type: model.SignalTypeCookie, Source: "http_analyzer", Key: "session",
					Value: "cookie-secret", URL: "https://example.test/final?session=secret", Confidence: 0.8,
				},
			},
			RawContribution: -10, Contribution: -10,
		}},
		AmbiguousEvidence: []scoring.ScoredEvidence{{
			Match: rules.EvidenceMatch{
				EvidenceID: "shared-host", Description: "Shared infrastructure host", Weight: 5,
				Signal: model.Signal{
					Type: model.SignalTypeResourceHost, Source: "http_analyzer", Key: "host",
					Value: "shared.example", URL: "https://shared.example/frame?token=secret", Confidence: 0.5,
				},
			},
			RawContribution: -2.5, Contribution: -2.5,
		}},
		MissingPositiveEvidence: []string{"html-marker"},
		AppliedConflicts:        []scoring.AppliedConflict{{RuleID: "other.product", Penalty: 5}},
	}}

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

func TestBuildKeepsPartialEvidenceRawButNotContributing(t *testing.T) {
	t.Parallel()
	report := Build("dev", scanner.Result{Detections: []scoring.Detection{{
		RuleID: "partial", Name: "Partial detector",
		PositiveEvidence: []scoring.ScoredEvidence{{
			Match: rules.EvidenceMatch{
				EvidenceID: "marker", Group: "static_integration", Weight: 30,
				Signal: model.Signal{
					Type: model.SignalTypePageContent, Source: "fixture", Key: "body", Confidence: 1,
				},
			},
			RawContribution: 30,
		}},
		PositiveEvidenceGroups: []scoring.EvidenceGroup{{
			ID: "static_integration", EvidenceIDs: []string{"marker"},
			SelectedEvidenceID: "marker", RawContribution: 30,
		}},
	}}})

	evidence := report.Detections[0].Evidence.Positive[0]
	if evidence.RawContribution != 30 || evidence.Contribution != 0 {
		t.Errorf("partial evidence contributions = %v/%v, want 30/0", evidence.RawContribution, evidence.Contribution)
	}
	group := report.Detections[0].PositiveEvidenceGroups[0]
	if group.RawContribution != 30 || group.Contribution != 0 {
		t.Errorf("partial group contributions = %v/%v, want 30/0", group.RawContribution, group.Contribution)
	}
}

func TestBuildCopiesScoringContributions(t *testing.T) {
	t.Parallel()
	report := Build("dev", scanner.Result{Detections: []scoring.Detection{{
		RuleID: "scored", Name: "Scored detector",
		ConditionMatched: true, MinimumEvidenceMet: true,
		PositiveEvidence: []scoring.ScoredEvidence{{
			Match: rules.EvidenceMatch{
				EvidenceID: "evidence", Group: "channel", Weight: 99,
				Signal: model.Signal{
					Type: model.SignalTypeCookie, Source: "fixture", Key: "cookie", Confidence: 1,
				},
			},
			RawContribution: 17, Contribution: 7,
		}},
		PositiveEvidenceGroups: []scoring.EvidenceGroup{{
			ID: "channel", EvidenceIDs: []string{"evidence"},
			SelectedEvidenceID: "evidence", RawContribution: 17, Contribution: 7,
		}},
	}}})

	evidence := report.Detections[0].Evidence.Positive[0]
	if evidence.RawContribution != 17 || evidence.Contribution != 7 {
		t.Errorf("report recomputed evidence contributions: %#v", evidence)
	}
	group := report.Detections[0].PositiveEvidenceGroups[0]
	if group.RawContribution != 17 || group.Contribution != 7 {
		t.Errorf("report recomputed group contributions: %#v", group)
	}
}

func TestWriteTextExplainsDetectionsWithoutSecrets(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	})
	result.Detections = []scoring.Detection{
		{
			RuleID: "detected", Name: "Detected product", Detected: true,
			ConditionMatched: true, MinimumEvidenceMet: true,
			EvidenceScore: 75, Score: 75, Level: scoring.LevelHigh,
			PositiveEvidenceGroups: []scoring.EvidenceGroup{{
				ID: "static_integration", EvidenceIDs: []string{"script"},
				SelectedEvidenceID: "script", RawContribution: 80, Contribution: 80,
			}},
			PositiveEvidence: []scoring.ScoredEvidence{{
				Match: rules.EvidenceMatch{EvidenceID: "script", Group: "static_integration", Weight: 80, Signal: model.Signal{
					Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src",
					Value: "https://cdn.test/api.js?token=secret", Confidence: 1,
				}},
				RawContribution: 80, Contribution: 80,
			}},
			AppliedConflicts: []scoring.AppliedConflict{{RuleID: "other.product", Penalty: 5}},
		},
		{RuleID: "missing", Name: "Missing product", Score: 0, Level: scoring.LevelNotDetected, MissingPositiveEvidence: []string{"marker"}},
	}
	report := Build("dev", result)
	var output bytes.Buffer
	if err := WriteText(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Detected product", "75.0", "HIGH", "script", "api.js?redacted",
		"group static_integration", "80.0 raw", "conflict other.product: -5.0",
		"Missing product", "missing: marker",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output lacks %q: %s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "secret") {
		t.Errorf("text output disclosed a secret: %s", output.String())
	}
}

func TestBuildReportsPartialAnalyzerCoverageWithoutErrorDetails(t *testing.T) {
	t.Parallel()
	secretError := errors.New("navigation failed for https://example.test/?token=secret")
	result := scanner.Result{Target: analysis.Target{URL: "https://example.test/?token=secret"}, Analyzers: []scanner.AnalyzerResult{
		{
			Observation: analysis.Observation{
				Source: "dns_tls_analyzer", Warnings: []string{"certificate observations are incomplete"},
			},
			Status: scanner.AnalyzerStatusFailed, Err: secretError,
		},
	}}
	report := Build("dev", result)
	if report.RequestedURL != "https://example.test/?redacted" {
		t.Errorf("requested URL = %q, want redacted target fallback", report.RequestedURL)
	}
	if len(report.Analyzers) != 1 || report.Analyzers[0].Status != scanner.AnalyzerStatusFailed ||
		!strings.Contains(report.Analyzers[0].Warnings[0], "incomplete") {
		t.Fatalf("analyzer reports = %#v", report.Analyzers)
	}
	if report.FinalURL != nil || report.HTTP != nil {
		t.Fatalf("unavailable HTTP report = final URL %v, HTTP %#v", report.FinalURL, report.HTTP)
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSON(&jsonOutput, report); err != nil {
		t.Fatal(err)
	}
	var textOutput bytes.Buffer
	if err := WriteText(&textOutput, report); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{"JSON": jsonOutput.String(), "text": textOutput.String()} {
		if !strings.Contains(output, "dns_tls_analyzer") || !strings.Contains(output, "failed") {
			t.Errorf("%s report does not expose incomplete coverage: %s", name, output)
		}
		if strings.Contains(output, "token=secret") {
			t.Errorf("%s report disclosed analyzer error details: %s", name, output)
		}
	}
	for _, expected := range []string{`"final_url": null`, `"http": null`} {
		if !strings.Contains(jsonOutput.String(), expected) {
			t.Errorf("JSON report lacks %q: %s", expected, jsonOutput.String())
		}
	}
	if !strings.Contains(textOutput.String(), "HTTP observation: unavailable") ||
		strings.Contains(textOutput.String(), "HTTP status: 0") || strings.Contains(textOutput.String(), "Final URL:") {
		t.Errorf("text report fabricated HTTP observations: %s", textOutput.String())
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

func scanResultWithHTTP(result httpanalyzer.Result) scanner.Result {
	redirects := make([]analysis.HTTPRedirect, 0, len(result.Redirects))
	for _, redirect := range result.Redirects {
		redirects = append(redirects, analysis.HTTPRedirect{
			From: redirect.From, To: redirect.To, Status: redirect.Status,
		})
	}
	observation := analysis.Observation{
		Source: analysis.SourceHTTP, Signals: append([]model.Signal{}, result.Signals...),
		Warnings: append([]string{}, result.Warnings...),
		Metadata: analysis.Metadata{HTTP: &analysis.HTTPMetadata{
			RequestedURL: result.RequestedURL, FinalURL: result.FinalURL,
			StatusCode: result.StatusCode, Redirects: redirects,
			BodyTruncated: result.BodyTruncated,
		}},
	}
	return scanner.Result{
		Analyzers: []scanner.AnalyzerResult{{
			Observation: observation, Status: scanner.AnalyzerStatusComplete,
		}},
		Signals: append([]model.Signal{}, result.Signals...),
	}
}
