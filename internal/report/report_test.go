package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	if len(report.Pages) != 1 {
		t.Fatalf("pages = %d, want exactly one for a single-page scan", len(report.Pages))
	}
	page := report.Pages[0]
	if got, want := page.RequestedURL, "https://example.test/start?redacted"; got != want {
		t.Errorf("RequestedURL = %q, want %q", got, want)
	}
	if got, want := page.FinalURL, "https://example.test/final?redacted"; got == nil || *got != want {
		t.Errorf("FinalURL = %v, want %q", got, want)
	}
	values := page.Detections[0].Evidence.Positive
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
	groups := page.Detections[0].PositiveEvidenceGroups
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

func TestAutomationDocumentationUsesCurrentReportContract(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	documentPaths := []string{
		"README.md",
		filepath.Join("docs", "installation-and-usage.md"),
	}
	for _, relativePath := range documentPaths {
		data, err := os.ReadFile(filepath.Join(repositoryRoot, relativePath))
		if err != nil {
			t.Fatalf("read %s: %v", relativePath, err)
		}
		content := string(data)
		if strings.Contains(content, ".rule_id") || strings.Contains(content, "{rule_id,") {
			t.Errorf("%s queries the conflict-only rule_id field as a detection identifier", relativePath)
		}
		if !strings.Contains(content, "{id, name, score, level}") {
			t.Errorf("%s does not show the current detection ID field", relativePath)
		}
	}

	guidePath := filepath.Join(repositoryRoot, "docs", "installation-and-usage.md")
	guide, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatal(err)
	}
	guideText := string(guide)
	wants := []string{
		fmt.Sprintf(`if [ "${SCHEMA_VERSION}" -ne %d ]; then`, SchemaVersion),
		`.level == "high" or .level == "very_high"`,
		`\(.id)`,
		`../internal/report/testdata/complete-report.golden.json`,
	}
	for _, want := range wants {
		if !strings.Contains(guideText, want) {
			t.Errorf("installation guide does not contain current report contract fragment %q", want)
		}
	}
}

func TestWriteJSONUsesVersionedDeterministicShape(t *testing.T) {
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
	for _, key := range []string{"schema_version", "tool_version", "pages"} {
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
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(filepath.Join("testdata", "empty-report.golden.json"), output.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
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
	result.Analyzers = append(result.Analyzers,
		scanner.AnalyzerResult{Observation: analysis.Observation{Source: analysis.SourceDNSTLS}, Status: scanner.AnalyzerStatusComplete},
		scanner.AnalyzerResult{Observation: analysis.Observation{
			Source: analysis.SourceBrowser, Warnings: []string{"browser observation was incomplete"},
		}, Status: scanner.AnalyzerStatusPartial},
	)
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
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(filepath.Join("testdata", "complete-report.golden.json"), output.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
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

func TestBuildMinimizesBrowserEvidenceAndCoverage(t *testing.T) {
	t.Parallel()
	result := scanner.Result{
		Target: analysis.Target{URL: "https://example.test/?token=secret"},
		Analyzers: []scanner.AnalyzerResult{{
			Observation: analysis.Observation{
				Source: analysis.SourceBrowser, Warnings: []string{"browser observation was incomplete"},
			},
			Status: scanner.AnalyzerStatusPartial,
		}},
		Detections: []scoring.Detection{{
			RuleID: "browser.fixture", Name: "Browser fixture", Detected: true,
			ConditionMatched: true, MinimumEvidenceMet: true, Score: 100, EvidenceScore: 100,
			PositiveEvidenceGroups: []scoring.EvidenceGroup{{
				ID: "browser_dom", EvidenceIDs: []string{"request", "dom", "cookie"},
				SelectedEvidenceID: "request", RawContribution: 100, Contribution: 100,
			}},
			PositiveEvidence: []scoring.ScoredEvidence{
				{Match: rules.EvidenceMatch{EvidenceID: "request", Group: "browser_dom", Weight: 100, Signal: model.Signal{
					Type: model.SignalTypeNetworkRequest, Source: analysis.SourceBrowser, Key: "GET",
					Value: "https://api.example.test/widget?token=secret#fragment",
					URL:   "https://example.test/?session=secret", Confidence: 1,
				}}, RawContribution: 100, Contribution: 100},
				{Match: rules.EvidenceMatch{EvidenceID: "dom", Group: "browser_dom", Weight: 20, Signal: model.Signal{
					Type: model.SignalTypePageContent, Source: analysis.SourceBrowser, Key: "dom",
					Value: "<html>synthetic-secret</html>", Confidence: 1,
				}}, RawContribution: 20},
				{Match: rules.EvidenceMatch{EvidenceID: "cookie", Group: "browser_dom", Weight: 10, Signal: model.Signal{
					Type: model.SignalTypeCookie, Source: analysis.SourceBrowser, Key: "session",
					Value: "synthetic-secret", Confidence: 1,
				}}, RawContribution: 10},
			},
		}},
	}
	report := Build("dev", result)
	if len(report.Pages) != 1 {
		t.Fatalf("pages = %d, want exactly one for a single-page scan", len(report.Pages))
	}
	browserPage := report.Pages[0]
	if len(browserPage.Analyzers) != 1 || browserPage.Analyzers[0].Source != analysis.SourceBrowser ||
		browserPage.Analyzers[0].Status != scanner.AnalyzerStatusPartial {
		t.Fatalf("browser coverage = %#v", browserPage.Analyzers)
	}
	evidence := browserPage.Detections[0].Evidence.Positive
	if evidence[0].Value != "https://api.example.test/widget?redacted" ||
		evidence[0].URL != "https://example.test/?redacted" || evidence[1].Value != "" || evidence[2].Value != "" {
		t.Fatalf("browser evidence was not minimized: %#v", evidence)
	}
	var first, second bytes.Buffer
	if err := WriteJSON(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, report); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Error("browser report serialization is not deterministic")
	}
	for _, secret := range []string{"synthetic-secret", "token=secret", "session=secret", "fragment"} {
		if strings.Contains(first.String(), secret) {
			t.Errorf("browser report disclosed %q: %s", secret, first.String())
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

	evidence := report.Pages[0].Detections[0].Evidence.Positive[0]
	if evidence.RawContribution != 30 || evidence.Contribution != 0 {
		t.Errorf("partial evidence contributions = %v/%v, want 30/0", evidence.RawContribution, evidence.Contribution)
	}
	group := report.Pages[0].Detections[0].PositiveEvidenceGroups[0]
	if group.RawContribution != 30 || group.Contribution != 0 {
		t.Errorf("partial group contributions = %v/%v, want 30/0", group.RawContribution, group.Contribution)
	}
}

func TestSafeValueExposesSanitizedDNSTLSProperties(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		signal model.Signal
		want   string
	}{
		{signal: model.Signal{Type: model.SignalTypeDNSRecord, Value: "edge.example.net"}, want: "edge.example.net"},
		{signal: model.Signal{Type: model.SignalTypeDNSRecord, Value: "edge.example.net\nspoofed"}, want: ""},
		{signal: model.Signal{Type: model.SignalTypeTLSProperty, Value: "TLS 1.3\r"}, want: ""},
	} {
		if got := safeValue(testCase.signal); got != testCase.want {
			t.Errorf("safeValue(%#v) = %q, want %q", testCase.signal, got, testCase.want)
		}
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

	evidence := report.Pages[0].Detections[0].Evidence.Positive[0]
	if evidence.RawContribution != 17 || evidence.Contribution != 7 {
		t.Errorf("report recomputed evidence contributions: %#v", evidence)
	}
	group := report.Pages[0].Detections[0].PositiveEvidenceGroups[0]
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
	hostileErrorText := "parser failed for https://user:password@attacker.invalid/private?token=report-secret#fragment" +
		"\x1b[31m\n\x00raw-html=<script>steal()</script>" + strings.Repeat("x", 32<<10)
	secretError := errors.New(hostileErrorText)
	controlledWarning := "HTML observation was incomplete"
	result := scanner.Result{Target: analysis.Target{URL: "https://example.test/?token=secret"}, Analyzers: []scanner.AnalyzerResult{
		{
			Observation: analysis.Observation{
				Source: analysis.SourceHTTP, Warnings: []string{controlledWarning},
			},
			Status: scanner.AnalyzerStatusFailed, Err: secretError,
		},
	}}
	report := Build("dev", result)
	if len(report.Pages) != 1 {
		t.Fatalf("pages = %d, want exactly one for a single-page scan", len(report.Pages))
	}
	coveragePage := report.Pages[0]
	if coveragePage.RequestedURL != "https://example.test/?redacted" {
		t.Errorf("requested URL = %q, want redacted target fallback", coveragePage.RequestedURL)
	}
	if len(coveragePage.Analyzers) != 1 || coveragePage.Analyzers[0].Status != scanner.AnalyzerStatusFailed ||
		!slices.Equal(coveragePage.Analyzers[0].Warnings, []string{controlledWarning}) {
		t.Fatalf("analyzer reports = %#v", coveragePage.Analyzers)
	}
	if coveragePage.FinalURL != nil || coveragePage.HTTP != nil {
		t.Fatalf("unavailable HTTP report = final URL %v, HTTP %#v", coveragePage.FinalURL, coveragePage.HTTP)
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSON(&jsonOutput, report); err != nil {
		t.Fatal(err)
	}
	var textOutput bytes.Buffer
	if err := WriteText(&textOutput, report); err != nil {
		t.Fatal(err)
	}
	var styledOutput bytes.Buffer
	if err := WriteStyled(&styledOutput, report); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{
		"JSON": jsonOutput.String(), "text": textOutput.String(), "styled": stripANSI(styledOutput.String()),
	} {
		if !strings.Contains(output, analysis.SourceHTTP) || !strings.Contains(output, "failed") ||
			!strings.Contains(output, controlledWarning) {
			t.Errorf("%s report does not expose incomplete coverage: %s", name, output)
		}
		for _, attackerText := range []string{
			"attacker.invalid", "user:password", "report-secret", "raw-html", "steal()",
			"\x1b", "\x00", `\u001b`, `\u0000`, strings.Repeat("x", 1024),
		} {
			if strings.Contains(output, attackerText) {
				t.Errorf("%s report disclosed analyzer error text %q", name, attackerText)
			}
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

func TestBuildReportsInsufficientRuleCoverageWithoutCallingItNotDetected(t *testing.T) {
	t.Parallel()
	result := scanner.Result{
		Detections: []scoring.Detection{{
			RuleID: "browser.only", Name: "Browser-only product", Level: scoring.LevelNotDetected,
		}},
		Coverage: []scanner.DetectionCoverage{{
			RuleID: "browser.only", Status: scanner.DetectionStatusInsufficientCoverage,
			RequiredSources: []string{analysis.SourceBrowser}, IncompleteSources: []string{analysis.SourceBrowser},
		}},
	}
	built := Build("dev", result)
	if got := built.Pages[0].Detections[0]; got.Status != scanner.DetectionStatusInsufficientCoverage ||
		!slices.Equal(got.IncompleteSources, []string{analysis.SourceBrowser}) || got.Detected {
		t.Fatalf("detection coverage = %#v", got)
	}
	var output bytes.Buffer
	if err := WriteText(&output, built); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "Insufficient coverage:\n  Browser-only product  missing browser_analyzer") {
		t.Fatalf("text did not distinguish insufficient coverage:\n%s", text)
	}
	if strings.Contains(text, "Not detected:\n  Browser-only product") {
		t.Fatalf("text presented incomplete rule as not detected:\n%s", text)
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

func TestBuildExposesBoundedNetworkDiagnostics(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	})
	result.Analyzers = append(result.Analyzers, scanner.AnalyzerResult{
		Observation: analysis.Observation{
			Source: analysis.SourceBrowser,
			Metadata: analysis.Metadata{Network: &analysis.NetworkMetadata{
				FinalURL:       "https://example.test/?session=secret",
				RequestCount:   3,
				ResponseCount:  2,
				WireBytesTotal: 1934,
				POSTEndpoints:  []string{"https://api.example.test/submit?token=secret"},
				Protocols:      []analysis.NetworkNameCount{{Name: "h2", Count: 3}},
				StatusClasses:  []analysis.NetworkNameCount{{Name: "2xx", Count: 1}, {Name: "4xx", Count: 1}},
				Hosts:          []analysis.NetworkHostTraffic{{Host: "api.example.test", Requests: 2, ReusedRequests: 1}},
				QueueTiming:    analysis.NetworkTimingStats{P50Ms: 2, P95Ms: 30, MaxMs: 40},
				TTFBTiming:     analysis.NetworkTimingStats{P50Ms: 80, P95Ms: 200, MaxMs: 210},
				Truncated:      true,
				Transactions: []analysis.NetworkTransaction{
					{Method: "POST", URL: "https://api.example.test/submit?token=secret", Status: 403,
						Protocol: "h2", ConnectionReused: true, WireBytes: 734,
						QueueMs: 2, TTFBMs: 80, TotalMs: 150},
				},
			}},
		},
		Status: scanner.AnalyzerStatusComplete,
	})

	report := Build("test-version", result)
	if len(report.Pages) != 1 {
		t.Fatalf("pages = %d, want exactly one for a single-page scan", len(report.Pages))
	}
	network := report.Pages[0].Network
	if network == nil {
		t.Fatal("Network = nil, want a network section")
	}
	if got, want := network.FinalURL, "https://example.test/?redacted"; got != want {
		t.Errorf("Network.FinalURL = %q, want %q", got, want)
	}
	if got, want := network.POSTEndpoints[0], "https://api.example.test/submit?redacted"; got != want {
		t.Errorf("POSTEndpoints[0] = %q, want %q", got, want)
	}
	transaction := network.Transactions[0]
	if transaction.Method != "POST" || transaction.Status != 403 || !transaction.ConnectionReused ||
		transaction.WireBytes != 734 || transaction.QueueMs != 2 || transaction.TotalMs != 150 {
		t.Errorf("transaction = %#v, want bounded waterfall row", transaction)
	}

	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "secret") {
		t.Errorf("JSON network section disclosed a query secret: %s", output.String())
	}
	var text bytes.Buffer
	if err := WriteText(&text, report); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"Network:", "POST endpoints", "Queue (ms)", "p95=200", "reused)"} {
		if !strings.Contains(text.String(), fragment) {
			t.Errorf("text report missing %q:\n%s", fragment, text.String())
		}
	}
	if !strings.Contains(text.String(), "... 2 more") && !strings.Contains(text.String(), "truncated by capture limits") {
		t.Errorf("text report should show truncation or more-rows markers:\n%s", text.String())
	}
}

func TestWriteTextOmitsNetworkSectionWithoutMetadata(t *testing.T) {
	t.Parallel()
	var text bytes.Buffer
	if err := WriteText(&text, Build("1.2.3", scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", StatusCode: 200,
	}))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), "Network:") {
		t.Errorf("text report contains an empty network section:\n%s", text.String())
	}
}

func TestBuildPagesAggregatesSummaryAndFailedPages(t *testing.T) {
	t.Parallel()
	first := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://a.test/", FinalURL: "https://a.test/", StatusCode: 200,
	})
	first.Detections = []scoring.Detection{
		{RuleID: "vendor.one", Name: "Vendor One", Category: rules.CategoryCDNReverseProxy, Vendor: "Vendor",
			Detected: true, Score: 80, Level: scoring.LevelHigh},
		{RuleID: "vendor.two", Name: "Vendor Two", Category: rules.CategoryBotManagement, Vendor: "Vendor",
			Score: 10, Level: scoring.LevelLow},
	}
	second := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://b.test/", FinalURL: "https://b.test/", StatusCode: 200,
	})
	second.Detections = []scoring.Detection{
		{RuleID: "vendor.one", Name: "Vendor One", Category: rules.CategoryCDNReverseProxy, Vendor: "Vendor",
			Score: 90, Level: scoring.LevelVeryHigh},
		{RuleID: "vendor.two", Name: "Vendor Two", Category: rules.CategoryBotManagement, Vendor: "Vendor",
			Detected: true, Score: 60, Level: scoring.LevelMedium},
	}
	failed := scanner.PageResult{URL: "https://broken.test/", Err: errors.New("connection refused")}

	report := BuildPages("test-version", []scanner.PageResult{
		{URL: "https://a.test/", Result: first},
		{URL: "https://b.test/", Result: second},
		failed,
	})
	if len(report.Pages) != 3 {
		t.Fatalf("pages = %d, want 3", len(report.Pages))
	}
	if !report.Pages[2].Failed || report.Pages[2].RequestedURL != "https://broken.test/" {
		t.Errorf("failed page = %#v, want requested URL with failed flag", report.Pages[2])
	}
	if report.Summary == nil {
		t.Fatal("Summary = nil, want an aggregate for a multi-page scan")
	}
	if report.Summary.PageCount != 3 || report.Summary.FailedPages != 1 {
		t.Errorf("summary counts = %d/%d, want 3 pages, 1 failed", report.Summary.PageCount, report.Summary.FailedPages)
	}
	if len(report.Summary.Detections) != 2 {
		t.Fatalf("summary detections = %d, want 2 rules", len(report.Summary.Detections))
	}
	one, two := report.Summary.Detections[0], report.Summary.Detections[1]
	if one.ID != "vendor.one" || one.DetectedPages != 1 || one.MaxScore != 90 || one.MaxLevel != scoring.LevelVeryHigh {
		t.Errorf("vendor.one summary = %#v, want 1 detected page with max score 90", one)
	}
	if two.ID != "vendor.two" || two.DetectedPages != 1 || two.MaxScore != 60 || two.MaxLevel != scoring.LevelMedium {
		t.Errorf("vendor.two summary = %#v, want 1 detected page with max score 60", two)
	}

	var output bytes.Buffer
	if err := WriteText(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"Page 1 of 3", "Page 3 of 3", "Page scan: failed", "Summary across 3 pages"} {
		if !strings.Contains(output.String(), fragment) {
			t.Errorf("multi-page text report missing %q:\n%s", fragment, output.String())
		}
	}

	single := BuildPages("test-version", []scanner.PageResult{{URL: "https://a.test/", Result: first}})
	if single.Summary != nil {
		t.Errorf("single-page summary = %#v, want none", single.Summary)
	}
}
