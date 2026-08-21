package scanner

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/detectors"
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
		{Source: "first", Kind: ScanEventCompleted},
		{Source: "second", Kind: ScanEventStarted},
		{Source: "second", Kind: ScanEventCompleted},
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
		{Source: "failing", Kind: ScanEventFailed, Err: analyzerErr},
		{Source: "healthy", Kind: ScanEventStarted},
		{Source: "healthy", Kind: ScanEventCompleted},
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
		{Source: "fatal", Kind: ScanEventFailed, Err: analyzerErr},
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
		{ScanEventCompleted, "completed"},
		{ScanEventFailed, "failed"},
		{ScanEventKind(99), "unknown(99)"},
	}
	for _, testCase := range tests {
		if got := testCase.kind.String(); got != testCase.want {
			t.Errorf("String() = %q, want %q", got, testCase.want)
		}
	}
}
