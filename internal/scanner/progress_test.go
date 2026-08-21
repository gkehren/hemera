package scanner

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/pkg/model"
)

func TestScanEmitsProgressEventsInAnalyzerOrder(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	first := analyzerStub{source: "first", observation: analysis.Observation{Source: "first"}}
	second := analyzerStub{source: "second", observation: analysis.Observation{Source: "second"}}
	var events []ScanEvent
	scanner, err := New(Config{
		Progress: func(event ScanEvent) {
			events = append(events, event)
		},
		Analyzers: []AnalyzerConfig{
			{Analyzer: first, FailurePolicy: FailurePolicyAbort},
			{Analyzer: second, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := scanner.Scan(context.Background(), "https://example.test/"); err != nil {
		t.Fatal(err)
	}

	want := []ScanEvent{
		{Source: "first", Kind: ScanEventStarted},
		{Source: "first", Kind: ScanEventFinished, Status: AnalyzerStatusComplete},
		{Source: "second", Kind: ScanEventStarted},
		{Source: "second", Kind: ScanEventFinished, Status: AnalyzerStatusComplete},
	}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestScanEmitsFailedEventForContinuedAnalyzerError(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	analyzerErr := errors.New("dns lookup failed")
	failing := analyzerStub{source: "failing", observation: analysis.Observation{Source: "failing"}, err: analyzerErr}
	healthy := analyzerStub{source: "healthy", observation: analysis.Observation{Source: "healthy"}}
	var events []ScanEvent
	scanner, err := New(Config{
		Progress: func(event ScanEvent) {
			events = append(events, event)
		},
		Analyzers: []AnalyzerConfig{
			{Analyzer: failing, FailurePolicy: FailurePolicyContinue},
			{Analyzer: healthy, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := scanner.Scan(context.Background(), "https://example.test/"); err != nil {
		t.Fatal(err)
	}

	want := []ScanEvent{
		{Source: "failing", Kind: ScanEventStarted},
		{Source: "failing", Kind: ScanEventFinished, Status: AnalyzerStatusFailed},
		{Source: "healthy", Kind: ScanEventStarted},
		{Source: "healthy", Kind: ScanEventFinished, Status: AnalyzerStatusComplete},
	}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

// TestScanEmitsPartialStatusForUsefulObservationWithError covers the review
// requirement: an analyzer that returns useful signals plus a non-fatal error
// must report the canonical partial status, not a complete failure.
func TestScanEmitsPartialStatusForUsefulObservationWithError(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	analyzerErr := errors.New("partial capture budget exceeded")
	partial := analyzerStub{
		source: "partial",
		observation: analysis.Observation{
			Source: "partial",
			Signals: []model.Signal{{
				Type: model.SignalTypeScriptURL, Source: "partial",
				Key: "script", Value: "https://cdn.test/a.js", Confidence: 1,
			}},
		},
		err: analyzerErr,
	}
	var events []ScanEvent
	scanner, err := New(Config{
		Progress: func(event ScanEvent) {
			events = append(events, event)
		},
		Analyzers: []AnalyzerConfig{
			{Analyzer: partial, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Analyzers) != 1 || result.Analyzers[0].Status != AnalyzerStatusPartial {
		t.Fatalf("analyzer status = %#v, want partial", result.Analyzers)
	}

	want := []ScanEvent{
		{Source: "partial", Kind: ScanEventStarted},
		{Source: "partial", Kind: ScanEventFinished, Status: AnalyzerStatusPartial},
	}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestScanEmitsFailedEventWhenAbortPolicyStopsScan(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	analyzerErr := errors.New("connection refused")
	fatal := analyzerStub{source: "fatal", observation: analysis.Observation{Source: "fatal"}, err: analyzerErr}
	unreached := analyzerStub{source: "unreached"}
	var events []ScanEvent
	scanner, err := New(Config{
		Progress: func(event ScanEvent) {
			events = append(events, event)
		},
		Analyzers: []AnalyzerConfig{
			{Analyzer: fatal, FailurePolicy: FailurePolicyAbort},
			{Analyzer: unreached, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := scanner.Scan(context.Background(), "https://example.test/"); err == nil {
		t.Fatal("Scan() error = nil, want analyzer failure")
	}

	want := []ScanEvent{
		{Source: "fatal", Kind: ScanEventStarted},
		{Source: "fatal", Kind: ScanEventFinished, Status: AnalyzerStatusFailed},
	}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestSourcesReturnsConfiguredOrder(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	var events []ScanEvent
	scanner, err := New(Config{
		Progress: func(event ScanEvent) {
			events = append(events, event)
		},
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: "alpha"}, FailurePolicy: FailurePolicyContinue},
			{Analyzer: analyzerStub{source: "beta"}, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := scanner.Sources()
	want := []string{"alpha", "beta"}
	if !slices.Equal(got, want) {
		t.Fatalf("Sources() = %#v, want %#v", got, want)
	}
}

func TestScanEventKindString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind ScanEventKind
		want string
	}{
		{ScanEventStarted, "started"},
		{ScanEventFinished, "finished"},
		{ScanEventKind(99), "unknown(99)"},
	}
	for _, testCase := range tests {
		if got := testCase.kind.String(); got != testCase.want {
			t.Errorf("String() = %q, want %q", got, testCase.want)
		}
	}
}
