package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

func TestWriteStyledExplainsDetectionsWithoutSecrets(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/login",
		StatusCode: 403, BodyTruncated: true,
		Redirects: []httpanalyzer.Redirect{{
			From: "https://example.test/", To: "https://example.test/login", Status: 302,
		}},
		Warnings: []string{"response body was truncated"},
	})
	result.Detections = []scoring.Detection{
		{
			RuleID: "detected", Name: "Detected product", Detected: true,
			ConditionMatched: true, MinimumEvidenceMet: true,
			EvidenceScore: 95, Score: 95, Level: scoring.LevelVeryHigh,
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
			NegativeEvidence: []scoring.ScoredEvidence{{
				Match: rules.EvidenceMatch{EvidenceID: "absent-marker", Weight: 10, Signal: model.Signal{
					Type: model.SignalTypePageContent, Source: "http_analyzer", Key: "body", Confidence: 1,
				}},
				RawContribution: -10, Contribution: -10,
			}},
			AppliedConflicts: []scoring.AppliedConflict{{RuleID: "other.product", Penalty: 5}},
		},
		{RuleID: "missing", Name: "Missing product", Score: 0, Level: scoring.LevelNotDetected, MissingPositiveEvidence: []string{"marker"}},
	}
	result.Coverage = []scanner.DetectionCoverage{{
		RuleID: "browser.only", Status: scanner.DetectionStatusInsufficientCoverage,
		IncompleteSources: []string{analysis.SourceBrowser},
	}}
	result.Detections = append(result.Detections, scoring.Detection{
		RuleID: "browser.only", Name: "Browser-only product", Level: scoring.LevelNotDetected,
	})
	built := Build("dev", result)

	var output bytes.Buffer
	if err := WriteStyled(&output, built); err != nil {
		t.Fatal(err)
	}
	// Styling may wrap any token in escape sequences depending on the active
	// color profile, so content assertions run on the stripped text.
	styled := stripANSI(output.String())
	for _, expected := range []string{
		"Hemera scan report",
		"Target", "https://example.test/",
		"Final URL", "https://example.test/login",
		"Status", "403", "body truncated",
		"Redirect", "302",
		"1 detected · 1 not detected · 1 inconclusive",
		"✔ Detections", "Detected product", "[VERY HIGH]", "score 95.0",
		"+ script", "api.js?redacted",
		"= group static_integration", "80.0 raw",
		"- absent-marker",
		"! conflict other.product",
		"Not detected", "Missing product", "missing: marker",
		"Insufficient coverage", "Browser-only product", "missing browser_analyzer",
		"Warnings", "response body was truncated",
	} {
		if !strings.Contains(styled, expected) {
			t.Errorf("styled output lacks %q:\n%s", expected, styled)
		}
	}
	if strings.Contains(styled, "secret") {
		t.Errorf("styled output disclosed a secret: %s", styled)
	}
}

func TestWriteStyledRendersEmptySectionsAndBadges(t *testing.T) {
	t.Parallel()
	result := scanResultWithHTTP(httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
	})
	result.Detections = []scoring.Detection{
		{Name: "Medium product", Score: 60, Level: scoring.LevelMedium},
		{Name: "Low product", Score: 30, Level: scoring.LevelLow},
	}
	built := Build("dev", result)

	var output bytes.Buffer
	if err := WriteStyled(&output, built); err != nil {
		t.Fatal(err)
	}
	styled := stripANSI(output.String())
	for _, expected := range []string{"[MEDIUM]", "[LOW]", "(none)"} {
		if !strings.Contains(styled, expected) {
			t.Errorf("styled output lacks %q:\n%s", expected, styled)
		}
	}
	if hasPhantomPaddingLine(output.String()) {
		t.Errorf("styled output contains padded empty lines:\n%q", output.String())
	}
}

// hasPhantomPaddingLine reports whether the output contains a line that is
// entirely escape codes and spaces, the artifact of rendering strings that
// embed newlines through lipgloss.
func hasPhantomPaddingLine(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		trimmed := stripANSI(line)
		if trimmed != "" && strings.TrimSpace(trimmed) == "" {
			return true
		}
	}
	return false
}

func stripANSI(text string) string {
	var b strings.Builder
	inEscape := false
	for _, r := range text {
		switch {
		case inEscape:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
		case r == '\x1b':
			inEscape = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestWriteStyledReportsPartialAnalyzerCoverage(t *testing.T) {
	t.Parallel()
	result := scanner.Result{Analyzers: []scanner.AnalyzerResult{{
		Observation: analysis.Observation{
			Source: "dns_tls_analyzer", Warnings: []string{"certificate observations are incomplete"},
		},
		Status: scanner.AnalyzerStatusFailed,
	}}}
	built := Build("dev", result)

	var output bytes.Buffer
	if err := WriteStyled(&output, built); err != nil {
		t.Fatal(err)
	}
	styled := stripANSI(output.String())
	for _, expected := range []string{
		"HTTP", "observation unavailable",
		"Analyzer coverage", "dns_tls_analyzer", "failed", "certificate observations are incomplete",
	} {
		if !strings.Contains(styled, expected) {
			t.Errorf("styled output lacks %q:\n%s", expected, styled)
		}
	}
}

func TestWriteStyledReturnsOutputErrors(t *testing.T) {
	t.Parallel()
	if err := WriteStyled(failingWriter{}, Report{}); err == nil {
		t.Error("WriteStyled() error = nil")
	}
}
