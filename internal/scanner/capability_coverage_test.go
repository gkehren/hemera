package scanner

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

// truncatedContentRuleSet contains one decisive page_content predicate
// constrained to the HTTP analyzer and one unconstrained script predicate,
// mirroring static challenge detectors that match bounded body evidence.
func truncatedContentRuleSet() rules.RuleSet {
	contentMarker := "challenge-marker"
	scriptKey := "https://static.example.test/challenge.js"
	return rules.RuleSet{
		SchemaVersion: rules.CurrentSchemaVersion,
		Rules: []rules.Rule{
			{
				ID: "http.content", Name: "HTTP Content", Category: rules.CategoryThirdPartySecurity,
				Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 75,
				Match: rules.Condition{Signal: &rules.Evidence{
					ID: "content", Group: "content", Type: model.SignalTypePageContent,
					Source: &rules.TextPattern{Exact: &[]string{analysis.SourceHTTP}[0]},
					Value:  &rules.TextPattern{Contains: &contentMarker}, Weight: 75,
				}},
			},
			{
				ID: "unconstrained.script", Name: "Unconstrained Script", Category: rules.CategoryThirdPartySecurity,
				Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 75,
				Match: rules.Condition{Signal: &rules.Evidence{
					ID: "script", Group: "script", Type: model.SignalTypeScriptURL,
					Key: &rules.TextPattern{Exact: &scriptKey}, Weight: 75,
				}},
			},
		},
	}
}

func statusByRule(coverage []DetectionCoverage) map[string]DetectionStatus {
	statuses := make(map[string]DetectionStatus, len(coverage))
	for _, entry := range coverage {
		statuses[entry.RuleID] = entry.Status
	}
	return statuses
}

func incompleteByRule(coverage []DetectionCoverage) map[string][]string {
	incomplete := make(map[string][]string, len(coverage))
	for _, entry := range coverage {
		incomplete[entry.RuleID] = entry.IncompleteSources
	}
	return incomplete
}

func TestScanCapabilityIncompleteWithNilErrorIsInsufficientCoverage(t *testing.T) {
	t.Parallel()
	// Regression: an analyzer that returns nil must not imply that every
	// detector-relevant capability is complete. The HTTP stub reports success
	// while declaring its bounded page_content channel incomplete, so the
	// content predicate cannot be conclusively negative.
	truncated := analysis.Observation{
		Source: analysis.SourceHTTP,
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityIncomplete},
		},
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: analysis.SourceHTTP, observation: truncated}},
		},
		RuleSet: truncatedContentRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Analyzers[0].Status; got != AnalyzerStatusComplete {
		t.Fatalf("analyzer status = %q, want complete", got)
	}
	statuses := statusByRule(result.Coverage)
	if got := statuses["http.content"]; got != DetectionStatusInsufficientCoverage {
		t.Errorf("http.content status = %s, want insufficient_coverage", got)
	}
	if got := incompleteByRule(result.Coverage)["http.content"]; !slices.Equal(got, []string{analysis.SourceHTTP}) {
		t.Errorf("http.content incomplete = %v, want [http_analyzer]", got)
	}
}

func TestScanTruncatedBodyBeforeDecisiveStaticMarker(t *testing.T) {
	t.Parallel()
	// The decisive static script was never observed because resource
	// extraction stopped before reaching it. A conclusive negative is forbidden.
	bounded := analysis.Observation{
		Source: analysis.SourceHTTP,
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypeRedirect, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeNetworkResponse, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeResponseHeader, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeCookie, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeScriptURL, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeIframeURL, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeResourceHost, Status: analysis.CapabilityIncomplete},
		},
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: analysis.SourceHTTP, observation: bounded}},
		},
		RuleSet: truncatedContentRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	statuses := statusByRule(result.Coverage)
	if got := statuses["unconstrained.script"]; got != DetectionStatusInsufficientCoverage {
		t.Errorf("unconstrained.script status = %s, want insufficient_coverage", got)
	}
	if got := statuses["http.content"]; got != DetectionStatusInsufficientCoverage {
		t.Errorf("http.content status = %s, want insufficient_coverage", got)
	}
}

func TestScanUnrelatedIncompleteCapabilityDoesNotDowngrade(t *testing.T) {
	t.Parallel()
	headerKey := "x-complete-header"
	ruleSet := rules.RuleSet{
		SchemaVersion: rules.CurrentSchemaVersion,
		Rules: []rules.Rule{{
			ID: "header.only", Name: "Header Only", Category: rules.CategoryThirdPartySecurity,
			Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 75,
			Match: rules.Condition{Signal: &rules.Evidence{
				ID: "header", Group: "header", Type: model.SignalTypeResponseHeader,
				Key: &rules.TextPattern{Exact: &headerKey}, Weight: 75,
			}},
		}},
	}
	// Browser scripts were truncated, but this rule depends only on complete
	// HTTP response headers, so absence stays conclusive.
	httpComplete := analysis.Observation{
		Source: analysis.SourceHTTP,
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypeResponseHeader, Status: analysis.CapabilityComplete},
		},
	}
	browserScriptsTruncated := analysis.Observation{
		Source: analysis.SourceBrowser,
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypeScriptURL, Status: analysis.CapabilityIncomplete},
		},
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: analysis.SourceHTTP, observation: httpComplete}, FailurePolicy: FailurePolicyContinue},
			{Analyzer: analyzerStub{source: analysis.SourceBrowser, observation: browserScriptsTruncated}, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	statuses := statusByRule(result.Coverage)
	if got := statuses["header.only"]; got != DetectionStatusNotDetected {
		t.Errorf("header.only status = %s, want not_detected", got)
	}
}

func TestScanIncompleteCapabilityWithDecisiveRetainedEvidenceDetects(t *testing.T) {
	t.Parallel()
	contentMarker := "challenge-marker"
	observed := []model.Signal{{
		Type: model.SignalTypePageContent, Source: analysis.SourceHTTP,
		Key: "body", Value: "prefix " + contentMarker + " suffix", Confidence: 1,
	}}
	truncatedButDecisive := analysis.Observation{
		Source:   analysis.SourceHTTP,
		Signals:  observed,
		Warnings: []string{"response body was truncated at 2048 bytes"},
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityIncomplete},
		},
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: analysis.SourceHTTP, observation: truncatedButDecisive}},
		},
		RuleSet: truncatedContentRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Detections) != 2 {
		t.Fatalf("detections = %#v, want two rule results", result.Detections)
	}
	if !result.Detections[0].Detected {
		t.Fatalf("detection %#v, want detected despite incomplete capability", result.Detections[0])
	}
	statuses := statusByRule(result.Coverage)
	if got := statuses["http.content"]; got != DetectionStatusDetected {
		t.Errorf("http.content status = %s, want detected despite incomplete capability", got)
	}
}

func TestScanDeclaredCompleteCapabilitiesWithoutEvidenceAreConclusive(t *testing.T) {
	t.Parallel()
	completeHTTP := analysis.Observation{
		Source: analysis.SourceHTTP,
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypeRedirect, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeNetworkResponse, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeResponseHeader, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeCookie, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeScriptURL, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeIframeURL, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeResourceHost, Status: analysis.CapabilityComplete},
		},
	}
	completeBrowser := analysis.Observation{
		Source: analysis.SourceBrowser,
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypeNetworkRequest, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeNetworkResponse, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeDOMSelector, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeJSGlobal, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeScriptURL, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeIframeURL, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeCookie, Status: analysis.CapabilityComplete},
		},
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: analysis.SourceHTTP, observation: completeHTTP}, FailurePolicy: FailurePolicyContinue},
			{Analyzer: analyzerStub{source: analysis.SourceBrowser, observation: completeBrowser}, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: truncatedContentRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	for _, cov := range result.Coverage {
		if cov.Status != DetectionStatusNotDetected {
			t.Errorf("rule %q status = %s, want conclusive not_detected", cov.RuleID, cov.Status)
		}
		if len(cov.IncompleteSources) != 0 {
			t.Errorf("rule %q incomplete sources = %#v, want empty", cov.RuleID, cov.IncompleteSources)
		}
	}
}

func TestScanBrowserChannelTruncationScopesToRelevantRules(t *testing.T) {
	t.Parallel()
	domKey := "#captcha-container"
	ruleSet := rules.RuleSet{
		SchemaVersion: rules.CurrentSchemaVersion,
		Rules: []rules.Rule{
			{
				ID: "dom.rule", Name: "DOM Rule", Category: rules.CategoryThirdPartySecurity,
				Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 75,
				Match: rules.Condition{Signal: &rules.Evidence{
					ID: "dom", Group: "dom", Type: model.SignalTypeDOMSelector,
					Key: &rules.TextPattern{Exact: &domKey}, Weight: 75,
				}},
			},
			{
				ID: "request.rule", Name: "Request Rule", Category: rules.CategoryThirdPartySecurity,
				Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 75,
				Match: rules.Condition{Signal: &rules.Evidence{
					ID: "request", Group: "request", Type: model.SignalTypeNetworkRequest,
					Value: &rules.TextPattern{Prefix: &[]string{"https://telemetry.example.test/"}[0]}, Weight: 75,
				}},
			},
		},
	}
	// DOM capture was truncated while requests completed cleanly.
	browserPartialDOM := analysis.Observation{
		Source: analysis.SourceBrowser,
		Capabilities: []analysis.CapabilityCoverage{
			{SignalType: model.SignalTypeNetworkRequest, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypeNetworkResponse, Status: analysis.CapabilityComplete},
			{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeDOMSelector, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeJSGlobal, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeScriptURL, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeIframeURL, Status: analysis.CapabilityIncomplete},
			{SignalType: model.SignalTypeCookie, Status: analysis.CapabilityComplete},
		},
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: analysis.SourceBrowser, observation: browserPartialDOM}},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	statuses := statusByRule(result.Coverage)
	if got := statuses["dom.rule"]; got != DetectionStatusInsufficientCoverage {
		t.Errorf("dom.rule status = %s, want insufficient_coverage", got)
	}
	// The request channel completed independently of the DOM truncation.
	if got := statuses["request.rule"]; got != DetectionStatusNotDetected {
		t.Errorf("request.rule status = %s, want conclusive not_detected", got)
	}
}

func TestScanRejectsInvalidCapabilityDeclarations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		capabilities []analysis.CapabilityCoverage
	}{
		{
			name:         "unsupported status",
			capabilities: []analysis.CapabilityCoverage{{SignalType: model.SignalTypePageContent, Status: "unknown"}},
		},
		{
			name:         "invalid signal type",
			capabilities: []analysis.CapabilityCoverage{{SignalType: "bogus", Status: analysis.CapabilityComplete}},
		},
		{
			name: "duplicate declaration",
			capabilities: []analysis.CapabilityCoverage{
				{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityComplete},
				{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityIncomplete},
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			engine, err := New(Config{
				Analyzers: []AnalyzerConfig{{
					Analyzer: analyzerStub{source: analysis.SourceHTTP, observation: analysis.Observation{
						Source:       analysis.SourceHTTP,
						Capabilities: testCase.capabilities,
					}},
				}},
				RuleSet: truncatedContentRuleSet(),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = engine.Scan(context.Background(), "https://example.test/")
			if !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("Scan() error = %v, want ErrInvalidObservation", err)
			}
		})
	}
}

func TestBuildCapabilityCompleterPrefersDeclarationsOverFallback(t *testing.T) {
	t.Parallel()
	analyzers := []AnalyzerResult{
		{
			Status: AnalyzerStatusComplete,
			Observation: analysis.Observation{
				Source: analysis.SourceHTTP,
				Capabilities: []analysis.CapabilityCoverage{
					{SignalType: model.SignalTypePageContent, Status: analysis.CapabilityIncomplete},
				},
			},
		},
		{
			Status:      AnalyzerStatusFailed,
			Observation: analysis.Observation{Source: analysis.SourceBrowser},
		},
	}
	completer := buildCapabilityCompleter(analyzers)

	tests := []struct {
		name       string
		source     string
		signalType model.SignalType
		want       bool
	}{
		{
			name:       "declared incomplete wins over complete execution status",
			source:     analysis.SourceHTTP,
			signalType: model.SignalTypePageContent,
			want:       false,
		},
		{
			name:       "undeclared capability falls back to complete execution status",
			source:     analysis.SourceHTTP,
			signalType: model.SignalTypeResponseHeader,
			want:       true,
		},
		{
			name:       "undeclared capability falls back to failed execution status",
			source:     analysis.SourceBrowser,
			signalType: model.SignalTypeDOMSelector,
			want:       false,
		},
		{
			name:       "unknown source is never complete",
			source:     "mystery",
			signalType: model.SignalTypeCookie,
			want:       false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := completer(tt.source, tt.signalType); got != tt.want {
				t.Fatalf("completer(%q, %q) = %t, want %t", tt.source, tt.signalType, got, tt.want)
			}
		})
	}
}
