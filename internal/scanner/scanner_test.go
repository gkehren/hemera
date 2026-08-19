package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

type fixtureResolver func(context.Context, string, string) ([]netip.Addr, error)

func (f fixtureResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type analyzerStub struct {
	source      string
	observation analysis.Observation
	err         error
	observe     func(context.Context, analysis.Target) (analysis.Observation, error)
}

func (s analyzerStub) Source() string {
	return s.source
}

func (s analyzerStub) Observe(ctx context.Context, target analysis.Target) (analysis.Observation, error) {
	if s.observe != nil {
		return s.observe(ctx, target)
	}
	return s.observation, s.err
}

type secondaryAnalyzerStub struct {
	source  string
	observe func(context.Context, analysis.Target) (analysis.Observation, error)
}

func (s secondaryAnalyzerStub) Source() string {
	return s.source
}

func (s secondaryAnalyzerStub) Observe(ctx context.Context, target analysis.Target) (analysis.Observation, error) {
	return s.observe(ctx, target)
}

func TestNewValidatesDependencies(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		config Config
	}{
		{name: "no analyzers", config: Config{RuleSet: ruleSet}},
		{name: "nil analyzer", config: Config{Analyzers: []AnalyzerConfig{{}}, RuleSet: ruleSet}},
		{name: "typed nil analyzer", config: Config{Analyzers: []AnalyzerConfig{{
			Analyzer: (*analyzerStub)(nil),
		}}, RuleSet: ruleSet}},
		{name: "invalid policy", config: Config{Analyzers: []AnalyzerConfig{{
			Analyzer: analyzerStub{source: "first"}, FailurePolicy: 99,
		}}, RuleSet: ruleSet}},
		{name: "blank source", config: Config{Analyzers: []AnalyzerConfig{{
			Analyzer: analyzerStub{source: " "},
		}}, RuleSet: ruleSet}},
		{name: "source whitespace", config: Config{Analyzers: []AnalyzerConfig{{
			Analyzer: analyzerStub{source: " first "},
		}}, RuleSet: ruleSet}},
		{name: "duplicate source", config: Config{Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: "duplicate"}},
			{Analyzer: analyzerStub{source: "duplicate"}},
		}, RuleSet: ruleSet}},
		{name: "invalid rules", config: Config{Analyzers: []AnalyzerConfig{{
			Analyzer: analyzerStub{source: "first"},
		}}}},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(testCase.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestScanAggregatesAnalyzersInConfiguredOrder(t *testing.T) {
	t.Parallel()
	ruleSet := multiSourceRuleSet()
	var calls []string
	var callsMu sync.Mutex
	makeObserve := func(source string, signal model.Signal, warning string) func(context.Context, analysis.Target) (analysis.Observation, error) {
		return func(_ context.Context, target analysis.Target) (analysis.Observation, error) {
			if target.URL != "https://example.test/" {
				t.Errorf("target URL = %q", target.URL)
			}
			callsMu.Lock()
			calls = append(calls, source)
			callsMu.Unlock()
			return analysis.Observation{
				Source: source, Signals: []model.Signal{signal}, Warnings: []string{warning},
			}, nil
		}
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: "static", observe: makeObserve("static", model.Signal{
				Type: model.SignalTypeScriptURL, Source: "static", Key: "script", Confidence: 1,
			}, "static warning")}},
			{Analyzer: secondaryAnalyzerStub{source: "dynamic", observe: makeObserve("dynamic", model.Signal{
				Type: model.SignalTypeNetworkRequest, Source: "dynamic", Key: "request", Confidence: 1,
			}, "dynamic warning")}},
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
	if !slices.Equal(calls, []string{"static", "dynamic"}) {
		t.Errorf("analyzer calls = %v, want configured order", calls)
	}
	if result.Target.URL != "https://example.test/" {
		t.Errorf("result target = %#v", result.Target)
	}
	if len(result.Signals) != 2 || result.Signals[0].Source != "static" || result.Signals[1].Source != "dynamic" {
		t.Errorf("aggregate signals = %#v, want analyzer order", result.Signals)
	}
	if len(result.Analyzers) != 2 || result.Analyzers[0].Observation.Warnings[0] != "static warning" ||
		result.Analyzers[1].Observation.Warnings[0] != "dynamic warning" {
		t.Errorf("analyzer outcomes = %#v", result.Analyzers)
	}
	if len(result.Detections) != 1 || !result.Detections[0].Detected || result.Detections[0].Score != 100 {
		t.Errorf("detections = %#v", result.Detections)
	}
}

func TestScanAppliesFatalAndPartialFailurePolicies(t *testing.T) {
	t.Parallel()
	ruleSet := multiSourceRuleSet()
	localErr := errors.New("supplemental analyzer failed")
	var finalCalls atomic.Int32
	partial := analysis.Observation{Source: "partial", Signals: []model.Signal{{
		Type: model.SignalTypeScriptURL, Source: "partial", Key: "script", Confidence: 1,
	}}, Warnings: []string{"only static observations were available"}}

	t.Run("continue with partial observation", func(t *testing.T) {
		engine, err := New(Config{Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: "partial", observation: partial, err: localErr}, FailurePolicy: FailurePolicyContinue},
			{Analyzer: analyzerStub{source: "complete", observe: func(context.Context, analysis.Target) (analysis.Observation, error) {
				finalCalls.Add(1)
				return analysis.Observation{Source: "complete", Signals: []model.Signal{{
					Type: model.SignalTypeNetworkRequest, Source: "complete", Key: "request", Confidence: 1,
				}}}, nil
			}}},
		}, RuleSet: ruleSet})
		if err != nil {
			t.Fatal(err)
		}
		result, err := engine.Scan(context.Background(), "https://example.test/")
		if err != nil {
			t.Fatal(err)
		}
		if finalCalls.Load() != 1 || len(result.Signals) != 2 || !result.Detections[0].Detected {
			t.Fatalf("partial scan result = %#v", result)
		}
		outcome := result.Analyzers[0]
		if outcome.Status != AnalyzerStatusPartial || !errors.Is(outcome.Err, localErr) ||
			!slices.Equal(outcome.Observation.Warnings, partial.Warnings) {
			t.Errorf("partial outcome = %#v", outcome)
		}
	})

	t.Run("continue after total failure", func(t *testing.T) {
		engine, err := New(Config{Analyzers: []AnalyzerConfig{{
			Analyzer:      analyzerStub{source: "failed", observation: analysis.Observation{Source: "failed"}, err: localErr},
			FailurePolicy: FailurePolicyContinue,
		}}, RuleSet: ruleSet})
		if err != nil {
			t.Fatal(err)
		}
		result, err := engine.Scan(context.Background(), "https://example.test/")
		if err != nil {
			t.Fatal(err)
		}
		if result.Analyzers[0].Status != AnalyzerStatusFailed || !errors.Is(result.Analyzers[0].Err, localErr) {
			t.Errorf("failed outcome = %#v", result.Analyzers[0])
		}
	})

	t.Run("abort", func(t *testing.T) {
		var laterCalls atomic.Int32
		engine, err := New(Config{Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: "fatal", observation: analysis.Observation{Source: "fatal"}, err: localErr}},
			{Analyzer: analyzerStub{source: "later", observe: func(context.Context, analysis.Target) (analysis.Observation, error) {
				laterCalls.Add(1)
				return analysis.Observation{Source: "later"}, nil
			}}},
		}, RuleSet: ruleSet})
		if err != nil {
			t.Fatal(err)
		}
		_, err = engine.Scan(context.Background(), "https://example.test/")
		if !errors.Is(err, localErr) {
			t.Fatalf("Scan() error = %v, want analyzer error", err)
		}
		if laterCalls.Load() != 0 {
			t.Errorf("later analyzer calls = %d, want zero after fatal error", laterCalls.Load())
		}
	})
	if finalCalls.Load() != 1 {
		t.Fatalf("later analyzer calls = %d, want one partial-policy call only", finalCalls.Load())
	}
}

func TestScanTreatsCancellationAndInvalidOutputAsFatal(t *testing.T) {
	t.Parallel()
	ruleSet := multiSourceRuleSet()

	t.Run("caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		localErr := errors.New("cleanup failed")
		engine, err := New(Config{Analyzers: []AnalyzerConfig{{
			Analyzer: analyzerStub{source: "canceling", observe: func(context.Context, analysis.Target) (analysis.Observation, error) {
				cancel()
				return analysis.Observation{Source: "canceling"}, localErr
			}}, FailurePolicy: FailurePolicyContinue,
		}}, RuleSet: ruleSet})
		if err != nil {
			t.Fatal(err)
		}
		_, err = engine.Scan(ctx, "https://example.test/")
		if !errors.Is(err, context.Canceled) || !errors.Is(err, localErr) {
			t.Fatalf("Scan() error = %v, want cancellation and analyzer error", err)
		}
	})

	t.Run("caller cancellation after successful analyzer return", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		engine, err := New(Config{Analyzers: []AnalyzerConfig{{
			Analyzer: analyzerStub{source: "canceling", observe: func(context.Context, analysis.Target) (analysis.Observation, error) {
				cancel()
				return analysis.Observation{Source: "canceling"}, nil
			}}, FailurePolicy: FailurePolicyContinue,
		}}, RuleSet: ruleSet})
		if err != nil {
			t.Fatal(err)
		}
		_, err = engine.Scan(ctx, "https://example.test/")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Scan() error = %v, want cancellation", err)
		}
	})

	for _, testCase := range []struct {
		name        string
		observation analysis.Observation
	}{
		{name: "source mismatch", observation: analysis.Observation{Source: "other"}},
		{name: "invalid signal", observation: analysis.Observation{Source: "invalid", Signals: []model.Signal{{
			Type: model.SignalTypeScriptURL, Source: "invalid", Confidence: 1,
		}}}},
		{name: "signal source mismatch", observation: analysis.Observation{Source: "invalid", Signals: []model.Signal{{
			Type: model.SignalTypeScriptURL, Source: "other", Key: "src", Confidence: 1,
		}}}},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			engine, err := New(Config{Analyzers: []AnalyzerConfig{{
				Analyzer:      analyzerStub{source: "invalid", observation: testCase.observation},
				FailurePolicy: FailurePolicyContinue,
			}}, RuleSet: ruleSet})
			if err != nil {
				t.Fatal(err)
			}
			_, err = engine.Scan(context.Background(), "https://example.test/")
			if !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("Scan() error = %v, want ErrInvalidObservation", err)
			}
		})
	}

	t.Run("duplicate HTTP metadata", func(t *testing.T) {
		httpMetadata := func(source string) analysis.Observation {
			return analysis.Observation{
				Source: source,
				Metadata: analysis.Metadata{HTTP: &analysis.HTTPMetadata{
					RequestedURL: "https://example.test/", FinalURL: "https://example.test/",
				}},
			}
		}
		engine, err := New(Config{Analyzers: []AnalyzerConfig{
			{Analyzer: analyzerStub{source: "first", observation: httpMetadata("first")}},
			{Analyzer: analyzerStub{source: "second", observation: httpMetadata("second")}},
		}, RuleSet: ruleSet})
		if err != nil {
			t.Fatal(err)
		}
		_, err = engine.Scan(context.Background(), "https://example.test/")
		if !errors.Is(err, ErrInvalidObservation) {
			t.Fatalf("Scan() error = %v, want duplicate metadata rejection", err)
		}
	})
}

func multiSourceRuleSet() rules.RuleSet {
	staticKey := "script"
	dynamicKey := "request"
	return rules.RuleSet{SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{{
		ID: "multi.source", Name: "Multi-source detector", Category: rules.CategoryThirdPartySecurity,
		Vendor: "Fixture", MinimumEvidence: 2, MinimumScore: 100,
		Match: rules.Condition{All: []rules.Condition{
			{Signal: &rules.Evidence{ID: "static", Group: "static", Type: model.SignalTypeScriptURL,
				Key: &rules.TextPattern{Exact: &staticKey}, Weight: 50}},
			{Signal: &rules.Evidence{ID: "dynamic", Group: "dynamic", Type: model.SignalTypeNetworkRequest,
				Key: &rules.TextPattern{Exact: &dynamicKey}, Weight: 50}},
		}},
	}}}
}

func TestFixtureBackedDetectorFamilies(t *testing.T) {
	t.Parallel()
	type fixtureCase struct {
		Name     string              `json:"name"`
		Fixture  string              `json:"fixture"`
		Detected []string            `json:"detected"`
		Scores   map[string]float64  `json:"scores"`
		Levels   map[string]string   `json:"levels"`
		Evidence map[string][]string `json:"evidence"`
	}
	manifest, err := os.ReadFile(filepath.Join("testdata", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []fixtureCase
	if err := json.Unmarshal(manifest, &cases); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			body, err := os.ReadFile(filepath.Join("testdata", testCase.Fixture))
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/" {
					t.Errorf("unexpected subresource request %q", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(body)
			}))
			defer server.Close()

			local, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			config := httpanalyzer.DefaultConfig()
			config.Resolver = fixtureResolver(func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			})
			config.Dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, local.Host)
			}
			analyzer, err := httpanalyzer.New(config)
			if err != nil {
				t.Fatal(err)
			}
			ruleSet, err := detectors.Load()
			if err != nil {
				t.Fatal(err)
			}
			engine, err := New(Config{
				Analyzers: []AnalyzerConfig{{Analyzer: analyzer}},
				RuleSet:   ruleSet,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := engine.Scan(context.Background(), "http://fixture.example/")
			if err != nil {
				t.Fatal(err)
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("HTTP requests = %d, want exactly one navigation", got)
			}
			if len(result.Analyzers) != 1 || result.Analyzers[0].Observation.Metadata.HTTP == nil {
				t.Fatalf("HTTP analyzer outcome = %#v", result.Analyzers)
			}
			if got := result.Analyzers[0].Observation.Metadata.HTTP.StatusCode; got != http.StatusOK {
				t.Errorf("HTTP status = %d, want %d", got, http.StatusOK)
			}
			for i, signal := range result.Signals {
				if err := signal.Validate(); err != nil {
					t.Errorf("HTTP signal %d is invalid: %v", i, err)
				}
				if signal.Type != model.SignalTypePageContent &&
					strings.Contains(signal.Value+signal.URL, "synthetic-site-key") {
					t.Errorf("HTTP signal %d retained a synthetic secret outside internal page content: %#v", i, signal)
				}
			}

			var detected []string
			for _, detection := range result.Detections {
				if detection.Detected {
					detected = append(detected, detection.RuleID)
				}
				if want, ok := testCase.Scores[detection.RuleID]; !ok {
					t.Errorf("unexpected detector %q", detection.RuleID)
				} else if detection.Score != want {
					t.Errorf("detector %q score = %v, want %v", detection.RuleID, detection.Score, want)
				}
				if want, ok := testCase.Levels[detection.RuleID]; !ok {
					t.Errorf("missing expected level for detector %q", detection.RuleID)
				} else if string(detection.Level) != want {
					t.Errorf("detector %q level = %q, want %q", detection.RuleID, detection.Level, want)
				}
				ids := make([]string, 0, len(detection.PositiveEvidence))
				for _, evidence := range detection.PositiveEvidence {
					ids = append(ids, evidence.Match.EvidenceID)
					if err := evidence.Match.Signal.Validate(); err != nil {
						t.Errorf("detector %q evidence %q has invalid signal: %v", detection.RuleID, evidence.Match.EvidenceID, err)
					}
				}
				if want, ok := testCase.Evidence[detection.RuleID]; !ok {
					t.Errorf("missing expected evidence for detector %q", detection.RuleID)
				} else if !slices.Equal(ids, want) {
					t.Errorf("detector %q evidence IDs = %v, want %v", detection.RuleID, ids, want)
				}
			}
			if !slices.Equal(detected, testCase.Detected) {
				t.Errorf("detected rules = %v, want %v", detected, testCase.Detected)
			}
		})
	}
}
