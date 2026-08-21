package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

// boundedHTTPRuleSet mirrors static challenge detectors whose decisive
// evidence is a page-content marker or a script URL observed by the bounded
// HTTP analyzer.
func boundedHTTPRuleSet() rules.RuleSet {
	contentMarker := "decisive-challenge-marker"
	scriptKey := "http://example.test/challenge-late.js"
	return rules.RuleSet{
		SchemaVersion: rules.CurrentSchemaVersion,
		Rules: []rules.Rule{
			{
				ID: "fixture.content", Name: "Fixture Content", Category: rules.CategoryThirdPartySecurity,
				Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 75,
				Match: rules.Condition{Signal: &rules.Evidence{
					ID: "content", Group: "content", Type: model.SignalTypePageContent,
					Value: &rules.TextPattern{Contains: &contentMarker}, Weight: 75,
				}},
			},
			{
				ID: "fixture.script", Name: "Fixture Script", Category: rules.CategoryThirdPartySecurity,
				Vendor: "Fixture", MinimumEvidence: 1, MinimumScore: 75,
				Match: rules.Condition{Signal: &rules.Evidence{
					ID: "script", Group: "script", Type: model.SignalTypeScriptURL,
					Key: &rules.TextPattern{Exact: &scriptKey}, Weight: 75,
				}},
			},
		},
	}
}

func localHTTPAnalyzer(t *testing.T, serverURL string, change func(*httpanalyzer.Config)) (*httpanalyzer.Analyzer, string) {
	t.Helper()
	local, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	config := httpanalyzer.DefaultConfig()
	config.Resolver = fixtureResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		// Resolve to a public address so destination validation passes while
		// the pinned dialer keeps traffic on the local test server.
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	config.Dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, local.Host)
	}
	if change != nil {
		change(&config)
	}
	analyzer, err := httpanalyzer.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer, "http://example.test/"
}

func TestRealHTTPBodyTruncatedBeforeDecisiveMarkerIsInsufficientCoverage(t *testing.T) {
	t.Parallel()
	padding := strings.Repeat("x", 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// The decisive marker sits far beyond the configured body ceiling.
		fmt.Fprintf(w, "<html><body>%s</body></html>", padding+"<!-- decisive-challenge-marker -->")
	}))
	defer server.Close()

	httpAnalyzer, targetURL := localHTTPAnalyzer(t, server.URL, func(config *httpanalyzer.Config) {
		config.MaxBodyBytes = 1024
	})
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort}},
		RuleSet:   boundedHTTPRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), targetURL)
	if err != nil {
		t.Fatal(err)
	}

	statuses := statusByRule(result.Coverage)
	incomplete := incompleteByRule(result.Coverage)
	if got := statuses["fixture.content"]; got != DetectionStatusInsufficientCoverage {
		t.Errorf("fixture.content status = %s, want insufficient_coverage", got)
	}
	if got := incomplete["fixture.content"]; !slices.Equal(got, []string{analysis.SourceBrowser, analysis.SourceHTTP}) {
		t.Errorf("fixture.content incomplete = %v, want [browser_analyzer http_analyzer]", got)
	}
	for _, detection := range result.Detections {
		if detection.RuleID == "fixture.content" && detection.Detected {
			t.Error("marker beyond truncation point was matched; bounded prefix leaked evidence")
		}
	}
}

func TestRealHTTPResourceLimitBeforeDecisiveScriptIsInsufficientCoverage(t *testing.T) {
	t.Parallel()
	var body strings.Builder
	body.WriteString("<html><body>")
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&body, `<script src="/early-%d.js"></script>`, i)
	}
	body.WriteString(`<script src="/challenge-late.js"></script></body></html>`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body.String()))
	}))
	defer server.Close()

	httpAnalyzer, targetURL := localHTTPAnalyzer(t, server.URL, func(config *httpanalyzer.Config) {
		config.MaxHTMLResources = 3
	})
	// A complete browser observation keeps browser-capable predicates
	// conclusive while the HTTP resource ceiling scopes uncertainty to the
	// script channel alone.
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
			{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
			{Analyzer: analyzerStub{source: analysis.SourceBrowser, observation: completeBrowser}, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: boundedHTTPRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), targetURL)
	if err != nil {
		t.Fatal(err)
	}

	statuses := statusByRule(result.Coverage)
	if got := statuses["fixture.script"]; got != DetectionStatusInsufficientCoverage {
		t.Errorf("fixture.script status = %s, want insufficient_coverage after resource ceiling", got)
	}
	// The page content channel completed independently of resource extraction.
	if got := statuses["fixture.content"]; got != DetectionStatusNotDetected {
		t.Errorf("fixture.content status = %s, want conclusive not_detected", got)
	}
}
