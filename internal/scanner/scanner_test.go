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
	"sync/atomic"
	"testing"

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
	result httpanalyzer.Result
	err    error
}

func (s analyzerStub) Analyze(context.Context, string) (httpanalyzer.Result, error) {
	return s.result, s.err
}

func TestNewValidatesDependencies(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, rules.RuleSet{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(nil) error = %v, want ErrInvalidConfig", err)
	}
	if _, err := New(analyzerStub{}, rules.RuleSet{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(invalid rules) error = %v, want ErrInvalidConfig", err)
	}
}

func TestScanEvaluatesAnalyzerSignals(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(analyzerStub{result: httpanalyzer.Result{
		RequestedURL: "https://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
		Signals: []model.Signal{{
			Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: "src",
			Value: "https://challenges.cloudflare.com/turnstile/v0/api.js", Confidence: 1,
		}},
	}}, ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Detections) != 2 || !result.Detections[0].Detected || result.Detections[1].Detected {
		t.Errorf("detections = %#v", result.Detections)
	}
}

func TestScanPreservesAnalyzerFailure(t *testing.T) {
	t.Parallel()
	want := errors.New("analyzer failed")
	ruleSet, _ := detectors.Load()
	engine, err := New(analyzerStub{err: want}, ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Scan(context.Background(), "https://example.test/")
	if !errors.Is(err, want) {
		t.Fatalf("Scan() error = %v, want analyzer error", err)
	}
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
			engine, err := New(analyzer, ruleSet)
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
			for i, signal := range result.HTTP.Signals {
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
