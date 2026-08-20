package detectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/scoring"
)

type accuracyCase struct {
	Name     string              `json:"name"`
	Fixture  string              `json:"fixture"`
	Status   int                 `json:"status"`
	Headers  map[string]string   `json:"headers"`
	Detected []string            `json:"detected"`
	Scores   map[string]float64  `json:"scores"`
	Levels   map[string]string   `json:"levels"`
	Evidence map[string][]string `json:"evidence"`
}

type ruleMetrics struct {
	TP int
	FP int
	TN int
	FN int
}

func (m ruleMetrics) Precision() float64 {
	if m.TP+m.FP == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(m.TP+m.FP)
}

func (m ruleMetrics) Recall() float64 {
	if m.TP+m.FN == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(m.TP+m.FN)
}

func (m ruleMetrics) FPR() float64 {
	if m.FP+m.TN == 0 {
		return 0.0
	}
	return float64(m.FP) / float64(m.FP+m.TN)
}

func (m ruleMetrics) FNR() float64 {
	if m.FN+m.TP == 0 {
		return 0.0
	}
	return float64(m.FN) / float64(m.FN+m.TP)
}

type fixtureResolver func(context.Context, string, string) ([]netip.Addr, error)

func (f fixtureResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestDetectorCorpusAccuracyAndRegressionMetrics(t *testing.T) {
	t.Parallel()

	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join("..", "scanner", "testdata", "cases.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read %s: %v", manifestPath, err)
	}

	var cases []accuracyCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("unmarshal %s: %v", manifestPath, err)
	}

	if len(cases) < 20 {
		t.Fatalf("regression corpus size = %d, want >= 20", len(cases))
	}

	metricsByRule := make(map[string]*ruleMetrics)
	for _, rule := range ruleSet.Rules {
		metricsByRule[rule.ID] = &ruleMetrics{}
	}

	for _, tc := range cases {
		tc := tc
		fixturePath := filepath.Join("..", "scanner", "testdata", tc.Fixture)
		body, err := os.ReadFile(fixturePath)
		if err != nil {
			t.Fatalf("read fixture %s: %v", fixturePath, err)
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			for k, v := range tc.Headers {
				w.Header().Set(k, v)
			}
			status := tc.Status
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}))

		local, err := url.Parse(server.URL)
		if err != nil {
			server.Close()
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
			server.Close()
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		observation, err := analyzer.Analyze(ctx, "http://fixture.example/")
		cancel()
		server.Close()

		if err != nil {
			t.Fatalf("analyze %s (%s): %v", tc.Name, tc.Fixture, err)
		}

		detections, err := scoring.Evaluate(ruleSet, observation.Signals)
		if err != nil {
			t.Fatalf("evaluate %s: %v", tc.Name, err)
		}

		detectedMap := make(map[string]bool)
		for _, d := range detections {
			if d.Detected {
				detectedMap[d.RuleID] = true
			}
		}

		for _, rule := range ruleSet.Rules {
			wantDetected := slices.Contains(tc.Detected, rule.ID)
			gotDetected := detectedMap[rule.ID]
			m := metricsByRule[rule.ID]

			switch {
			case wantDetected && gotDetected:
				m.TP++
			case !wantDetected && gotDetected:
				m.FP++
				t.Errorf("[%s] False Positive for %q: expected not detected, but got detected", tc.Name, rule.ID)
			case !wantDetected && !gotDetected:
				m.TN++
			case wantDetected && !gotDetected:
				m.FN++
				t.Errorf("[%s] False Negative for %q: expected detected, but got not detected", tc.Name, rule.ID)
			}
		}
	}

	var (
		totalTP int
		totalFP int
		totalTN int
		totalFN int
	)

	t.Log("=== SYNTHETIC DETECTOR REGRESSION BENCHMARK ===")
	t.Log("// Note: These metrics measure the versioned synthetic regression corpus baseline only and are not estimates of real-world precision/recall.")
	t.Log(fmt.Sprintf("%-30s | %4s | %4s | %4s | %4s | %8s | %8s | %7s | %7s",
		"Rule ID", "TP", "FP", "TN", "FN", "Prec", "Recall", "FPR", "FNR"))
	t.Log(strings.Repeat("-", 100))

	for _, rule := range ruleSet.Rules {
		m := metricsByRule[rule.ID]
		totalTP += m.TP
		totalFP += m.FP
		totalTN += m.TN
		totalFN += m.FN

		t.Log(fmt.Sprintf("%-30s | %4d | %4d | %4d | %4d | %7.1f%% | %7.1f%% | %6.1f%% | %6.1f%%",
			rule.ID, m.TP, m.FP, m.TN, m.FN,
			m.Precision()*100, m.Recall()*100, m.FPR()*100, m.FNR()*100))

		if m.FP > 0 {
			t.Errorf("rule %q has %d false positives in synthetic regression corpus (FPR = %.2f%%)", rule.ID, m.FP, m.FPR()*100)
		}
		if m.FN > 0 {
			t.Errorf("rule %q has %d false negatives in synthetic regression corpus (FNR = %.2f%%)", rule.ID, m.FN, m.FNR()*100)
		}
		if m.TP == 0 {
			t.Errorf("rule %q has no true positive coverage in synthetic regression corpus", rule.ID)
		}
	}

	overallFPR := 0.0
	if totalFP+totalTN > 0 {
		overallFPR = float64(totalFP) / float64(totalFP+totalTN)
	}
	overallFNR := 0.0
	if totalFN+totalTP > 0 {
		overallFNR = float64(totalFN) / float64(totalFN+totalTP)
	}

	t.Log(strings.Repeat("-", 100))
	t.Log(fmt.Sprintf("OVERALL SYNTHETIC CORPUS METRICS: Total Cases=%d, TP=%d, FP=%d, TN=%d, FN=%d, Overall FPR=%.2f%%, Overall FNR=%.2f%%",
		len(cases), totalTP, totalFP, totalTN, totalFN, overallFPR*100, overallFNR*100))

	if totalFP > 0 {
		t.Fatalf("Synthetic corpus regression failure: %d total false positives detected", totalFP)
	}
	if totalFN > 0 {
		t.Fatalf("Synthetic corpus regression failure: %d total false negatives detected", totalFN)
	}
}
