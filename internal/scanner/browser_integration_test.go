//go:build browser_integration

package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/browser"
	"github.com/gkehren/hemera/internal/dnstls"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

func TestHTTPDNSTLSAndBrowserProduceOneDeterministicDetection(t *testing.T) {
	fixtureHTML, err := os.ReadFile("testdata/browser-aggregation.html")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = writer.Write(fixtureHTML)
	}))
	defer server.Close()

	localURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := fixtureResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	dialer := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, localURL.Host)
	}

	httpConfig := httpanalyzer.DefaultConfig()
	httpConfig.Resolver = resolver
	httpConfig.Dialer = dialer
	httpAnalyzer, err := httpanalyzer.New(httpConfig)
	if err != nil {
		t.Fatal(err)
	}
	dnsAnalyzer, err := dnstls.New(dnstls.Config{
		LookupTimeout: time.Second,
		Resolver:      &integrationCNAMEResolver{canonical: "edge.fixture.example."},
	})
	if err != nil {
		t.Fatal(err)
	}
	browserConfig := browser.DefaultConfig()
	browserPath, explicitBrowser := integrationBrowserPath(t)
	browserConfig.ExecutablePath = browserPath
	browserConfig.Resolver = resolver
	browserConfig.Dialer = dialer
	browserAnalyzer, err := browser.NewAnalyzer(browserConfig)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
			{Analyzer: dnsAnalyzer, FailurePolicy: FailurePolicyContinue},
			{Analyzer: browserAnalyzer, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: browserIntegrationRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, port, err := net.SplitHostPort(localURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "http://fixture.example:"+port+"/")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Analyzers) != 3 {
		t.Fatalf("analyzers = %#v", result.Analyzers)
	}
	if result.Analyzers[2].Status == AnalyzerStatusFailed && !explicitBrowser {
		t.Skipf("sandboxed Chromium is unavailable: %v", result.Analyzers[2].Err)
	}
	wantSources := []string{analysis.SourceHTTP, analysis.SourceDNSTLS, analysis.SourceBrowser}
	gotSources := make([]string, len(result.Analyzers))
	for index, analyzer := range result.Analyzers {
		gotSources[index] = analyzer.Observation.Source
		if analyzer.Status != AnalyzerStatusComplete {
			t.Fatalf("analyzer %q status = %s, warnings=%#v error=%v",
				gotSources[index], analyzer.Status, analyzer.Observation.Warnings, analyzer.Err)
		}
	}
	if !slices.Equal(gotSources, wantSources) {
		t.Fatalf("analyzer order = %v, want %v", gotSources, wantSources)
	}
	if len(result.Detections) != 2 || !result.Detections[0].Detected || !result.Detections[1].Detected {
		t.Fatalf("detections = %#v", result.Detections)
	}
	if len(result.Detections[0].PositiveEvidenceGroups) != 3 {
		t.Errorf("combined evidence groups = %#v", result.Detections[0].PositiveEvidenceGroups)
	}
	if evidence := result.Detections[1].PositiveEvidence; len(evidence) != 1 ||
		evidence[0].Match.Signal.Source != analysis.SourceBrowser {
		t.Errorf("browser-only evidence = %#v", evidence)
	}
}

func integrationBrowserPath(t *testing.T) (string, bool) {
	t.Helper()
	if path := os.Getenv("HEMERA_CHROMIUM_PATH"); path != "" {
		return path, true
	}
	for _, candidate := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, false
		}
	}
	t.Skip("no local Chromium or Chrome executable found")
	return "", false
}

func browserIntegrationRuleSet() rules.RuleSet {
	statusKey, statusValue := "status", "200"
	cnameKey, cnameValue := "cname", "edge.fixture.example"
	domKey, domMarker := "dom", "browser-only-marker"
	return rules.RuleSet{SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{
		{
			ID: "fixture.combined-browser", Name: "Combined browser fixture",
			Category: rules.CategoryThirdPartySecurity, Vendor: "Fixture",
			MinimumEvidence: 3, MinimumScore: 100,
			Match: rules.Condition{All: []rules.Condition{
				{Signal: &rules.Evidence{ID: "http", Group: "http", Type: model.SignalTypeNetworkResponse,
					Source: exactPattern(analysis.SourceHTTP), Key: exactPattern(statusKey), Value: exactPattern(statusValue), Weight: 30}},
				{Signal: &rules.Evidence{ID: "dns", Group: "dns", Type: model.SignalTypeDNSRecord,
					Source: exactPattern(analysis.SourceDNSTLS), Key: exactPattern(cnameKey), Value: exactPattern(cnameValue), Weight: 30}},
				{Signal: &rules.Evidence{ID: "browser", Group: "browser_dom", Type: model.SignalTypePageContent,
					Source: exactPattern(analysis.SourceBrowser), Key: exactPattern(domKey),
					Value: &rules.TextPattern{Contains: &domMarker}, Weight: 40}},
			}},
		},
		{
			ID: "fixture.browser-only", Name: "Browser-only fixture",
			Category: rules.CategoryThirdPartySecurity, Vendor: "Fixture",
			MinimumEvidence: 1, MinimumScore: 75,
			Match: rules.Condition{Signal: &rules.Evidence{
				ID: "browser-marker", Group: "browser_dom", Type: model.SignalTypePageContent,
				Source: exactPattern(analysis.SourceBrowser), Key: exactPattern(domKey),
				Value: &rules.TextPattern{Contains: &domMarker}, Weight: 75,
			}},
		},
	}}
}
