package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/dnstls"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

type integrationCNAMEResolver struct {
	canonical string
	calls     atomic.Int32
}

func (r *integrationCNAMEResolver) LookupCNAME(context.Context, string) (string, error) {
	r.calls.Add(1)
	return r.canonical, nil
}

func TestHTTPAndDNSTLSShareOneHandshakeAndScoreIndependentEvidence(t *testing.T) {
	t.Parallel()
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	local, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	httpConfig := httpanalyzer.DefaultConfig()
	httpConfig.RootCAs = roots
	httpConfig.Resolver = fixtureResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	httpConfig.Dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, local.Host)
	}
	httpAnalyzer, err := httpanalyzer.New(httpConfig)
	if err != nil {
		t.Fatal(err)
	}
	cnameResolver := &integrationCNAMEResolver{canonical: "edge.example.net."}
	dnsTLSAnalyzer, err := dnstls.New(dnstls.Config{LookupTimeout: time.Second, Resolver: cnameResolver})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
			{Analyzer: dnsTLSAnalyzer, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: dnsTLSRuleSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 1 {
		t.Errorf("TLS connections = %d, want one reused handshake", connections.Load())
	}
	if cnameResolver.calls.Load() != 1 {
		t.Errorf("CNAME lookups = %d, want one", cnameResolver.calls.Load())
	}
	if len(result.Analyzers) != 2 || result.Analyzers[1].Observation.Source != analysis.SourceDNSTLS ||
		result.Analyzers[1].Status != AnalyzerStatusComplete {
		t.Fatalf("analyzer results = %#v", result.Analyzers)
	}
	if len(result.Detections) != 2 {
		t.Fatalf("detections = %#v", result.Detections)
	}
	if detection := result.Detections[0]; !detection.Detected || detection.Score != 100 ||
		len(detection.PositiveEvidenceGroups) != 3 {
		t.Errorf("combined detection = %#v", detection)
	}
	if detection := result.Detections[1]; detection.Detected || detection.Score != 30 {
		t.Errorf("DNS-only product detection = %#v, want supporting score below threshold", detection)
	}
}

func TestForbiddenHTTPResolutionStopsDNSTLSAnalyzer(t *testing.T) {
	t.Parallel()
	var dialCalls atomic.Int32
	httpConfig := httpanalyzer.DefaultConfig()
	httpConfig.Resolver = fixtureResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	})
	httpConfig.Dialer = func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("unexpected dial")
	}
	httpAnalyzer, err := httpanalyzer.New(httpConfig)
	if err != nil {
		t.Fatal(err)
	}
	cnameResolver := &integrationCNAMEResolver{canonical: "edge.example.net."}
	dnsTLSAnalyzer, err := dnstls.New(dnstls.Config{LookupTimeout: time.Second, Resolver: cnameResolver})
	if err != nil {
		t.Fatal(err)
	}
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{{Analyzer: httpAnalyzer}, {Analyzer: dnsTLSAnalyzer, FailurePolicy: FailurePolicyContinue}},
		RuleSet:   ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Scan(context.Background(), "https://example.test/")
	if !errors.Is(err, httpanalyzer.ErrInitialTarget) {
		t.Fatalf("Scan() error = %v, want forbidden initial target", err)
	}
	if dialCalls.Load() != 0 || cnameResolver.calls.Load() != 0 {
		t.Errorf("dial/CNAME calls = %d/%d, want no activity after forbidden resolution", dialCalls.Load(), cnameResolver.calls.Load())
	}
}

func dnsTLSRuleSet() rules.RuleSet {
	statusKey, statusValue := "status", "200"
	cnameKey, cnameValue := "cname", "edge.example.net"
	versionKey, versionValue := "version", "TLS 1.3"
	return rules.RuleSet{SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{
		{
			ID: "fixture.combined", Name: "Combined fixture", Category: rules.CategoryThirdPartySecurity,
			Vendor: "Fixture", MinimumEvidence: 3, MinimumScore: 100,
			Match: rules.Condition{All: []rules.Condition{
				{Signal: &rules.Evidence{ID: "http-status", Group: "http", Type: model.SignalTypeNetworkResponse,
					Source: exactPattern(analysis.SourceHTTP), Key: exactPattern(statusKey), Value: exactPattern(statusValue), Weight: 40}},
				{Signal: &rules.Evidence{ID: "dns-cname", Group: "dns", Type: model.SignalTypeDNSRecord,
					Source: exactPattern(analysis.SourceDNSTLS), Key: exactPattern(cnameKey), Value: exactPattern(cnameValue), Weight: 30}},
				{Signal: &rules.Evidence{ID: "tls-version", Group: "tls", Type: model.SignalTypeTLSProperty,
					Source: exactPattern(analysis.SourceDNSTLS), Key: exactPattern(versionKey), Value: exactPattern(versionValue), Weight: 30}},
			}},
		},
		{
			ID: "fixture.product", Name: "Product fixture", Category: rules.CategoryBotManagement,
			Vendor: "Fixture", Product: "Product", MinimumEvidence: 1, MinimumScore: 75,
			Match: rules.Condition{Signal: &rules.Evidence{
				ID: "weak-infrastructure", Group: "dns", Type: model.SignalTypeDNSRecord,
				Key: exactPattern(cnameKey), Value: exactPattern(cnameValue), Weight: 30,
			}},
		},
	}}
}

func exactPattern(value string) *rules.TextPattern {
	return &rules.TextPattern{Exact: &value}
}
