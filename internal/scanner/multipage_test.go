package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

func multiPageRuleSet() rules.RuleSet {
	source := analysis.SourceBrowser
	return rules.RuleSet{SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{{
		ID: "multi.page.fixture", Name: "Multi page fixture", Category: rules.CategoryThirdPartySecurity,
		Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 50,
		Match: rules.Condition{Signal: &rules.Evidence{
			ID: "page-cookie", Group: "page_cookie", Type: model.SignalTypeCookie,
			Source: &rules.TextPattern{Exact: &source}, Key: exactPattern("page_marker"), Weight: 75,
		}},
	}}}
}

func newMultiPageEngine(t *testing.T, observe func(context.Context, analysis.Target) (analysis.Observation, error)) *Scanner {
	t.Helper()
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{{
			Analyzer:      analyzerStub{source: analysis.SourceBrowser, observe: observe},
			FailurePolicy: FailurePolicyContinue,
		}},
		RuleSet: multiPageRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func matchingPageObservation(marker string) analysis.Observation {
	return analysis.Observation{Source: analysis.SourceBrowser, Signals: []model.Signal{{
		Type: model.SignalTypeCookie, Source: analysis.SourceBrowser, Key: "page_marker",
		Value: marker, URL: "https://example.test/", Confidence: 1,
	}}}
}

func TestScanPagesRunsEveryPageSequentially(t *testing.T) {
	t.Parallel()
	var visited []string
	engine := newMultiPageEngine(t, func(_ context.Context, target analysis.Target) (analysis.Observation, error) {
		visited = append(visited, target.URL)
		return matchingPageObservation(target.URL), nil
	})
	targets := []string{"https://a.test/", "https://b.test/", "https://c.test/"}
	multi, err := engine.ScanPages(context.Background(), targets)
	if err != nil {
		t.Fatal(err)
	}
	for index, page := range multi.Pages {
		if page.Err != nil {
			t.Fatalf("page %d (%s) failed: %v", index, page.URL, page.Err)
		}
		if page.Result.Target.URL != targets[index] {
			t.Errorf("page %d target = %q, want %q", index, page.Result.Target.URL, targets[index])
		}
		if len(page.Result.Detections) == 0 {
			t.Errorf("page %d produced no detections", index)
		}
	}
	if len(visited) != len(targets) {
		t.Errorf("visited %d pages, want %d", len(visited), len(targets))
	}
}

func TestScanPagesContinuesAfterPageFailure(t *testing.T) {
	t.Parallel()
	// Only an abort-policy failure (the HTTP analyzer boundary) fails a page.
	// Continue-policy analyzer failures stay inside the page result.
	httpStub := analyzerStub{source: analysis.SourceHTTP, observe: func(_ context.Context, target analysis.Target) (analysis.Observation, error) {
		if target.URL == "https://broken.test/" {
			return analysis.Observation{Source: analysis.SourceHTTP}, errors.New("connection refused")
		}
		return analysis.Observation{Source: analysis.SourceHTTP}, nil
	}}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: httpStub, FailurePolicy: FailurePolicyAbort},
			{Analyzer: analyzerStub{source: analysis.SourceBrowser, observe: func(_ context.Context, target analysis.Target) (analysis.Observation, error) {
				return matchingPageObservation(target.URL), nil
			}}, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: multiPageRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	multi, err := engine.ScanPages(context.Background(), []string{"https://a.test/", "https://broken.test/", "https://c.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if multi.FailedPages() != 1 {
		t.Fatalf("failed pages = %d, want 1", multi.FailedPages())
	}
	broken := multi.Pages[1]
	if broken.Err == nil {
		t.Fatal("broken page reported no error")
	}
	if broken.Result.Target.URL != "" {
		t.Errorf("broken page leaked a partial result target %q", broken.Result.Target.URL)
	}
	for _, index := range []int{0, 2} {
		if multi.Pages[index].Err != nil {
			t.Errorf("page %d unexpectedly failed: %v", index, multi.Pages[index].Err)
		}
	}
}

func TestScanPagesRejectsOversizedAndEmptyRequests(t *testing.T) {
	t.Parallel()
	engine := newMultiPageEngine(t, func(_ context.Context, target analysis.Target) (analysis.Observation, error) {
		return matchingPageObservation(target.URL), nil
	})
	if _, err := engine.ScanPages(context.Background(), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty page list error = %v, want ErrInvalidConfig", err)
	}
	oversized := make([]string, MaxPages+1)
	for index := range oversized {
		oversized[index] = "https://example.test/" + string(rune('a'+index%26))
	}
	if _, err := engine.ScanPages(context.Background(), oversized); !errors.Is(err, ErrPageLimit) {
		t.Errorf("oversized page list error = %v, want ErrPageLimit", err)
	}
	atLimit := oversized[:MaxPages]
	multi, err := engine.ScanPages(context.Background(), atLimit)
	if err != nil {
		t.Fatalf("page-list ceiling scan failed: %v", err)
	}
	if len(multi.Pages) != MaxPages {
		t.Errorf("pages = %d, want %d", len(multi.Pages), MaxPages)
	}
}

func TestScanPagesStopsOnCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	engine := newMultiPageEngine(t, func(ctx context.Context, target analysis.Target) (analysis.Observation, error) {
		if target.URL == "https://stop.test/" {
			cancel()
		}
		return matchingPageObservation(target.URL), nil
	})
	multi, err := engine.ScanPages(ctx, []string{"https://stop.test/", "https://never.test/"})
	if err == nil {
		t.Fatal("ScanPages() error = nil, want cancellation")
	}
	if len(multi.Pages) != 1 {
		t.Errorf("pages = %d, want only the completed page", len(multi.Pages))
	}
}
