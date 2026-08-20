package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/dnstls"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

func targetWithPriorHTTP(tlsMeta *analysis.TLSMetadata, finalURL string) analysis.Target {
	return analysis.Target{
		URL: finalURL,
		Prior: []analysis.Observation{
			{
				Source: analysis.SourceHTTP,
				Metadata: analysis.Metadata{
					HTTP: &analysis.HTTPMetadata{
						FinalURL: finalURL,
						TLS:      tlsMeta,
					},
				},
			},
		},
	}
}

func TestDNSTLSAnalyzerBuiltInDetections(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Cloudflare DNS and TLS supporting evidence alone remains under threshold", func(t *testing.T) {
		t.Parallel()
		cnameResolver := &integrationCNAMEResolver{canonical: "example.cdn.cloudflare.net."}
		analyzer, err := dnstls.New(dnstls.Config{
			LookupTimeout: time.Second,
			Resolver:      cnameResolver,
		})
		if err != nil {
			t.Fatal(err)
		}

		target := targetWithPriorHTTP(&analysis.TLSMetadata{
			Version:           tls.VersionTLS13,
			CertificateIssuer: "Cloudflare Inc ECC CA-3",
		}, "https://example.com/")

		obs, err := analyzer.Observe(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}

		detections, err := scoring.Evaluate(ruleSet, obs.Signals)
		if err != nil {
			t.Fatal(err)
		}

		for _, d := range detections {
			if d.RuleID == "cloudflare.proxy" {
				if d.Score != 50 {
					t.Errorf("cloudflare.proxy score = %v, want 50 (30 DNS + 20 TLS)", d.Score)
				}
				if d.Detected {
					t.Errorf("cloudflare.proxy detected = true from supporting DNS+TLS alone, want false")
				}
			}
		}
	})

	t.Run("Akamai Edge decisive CNAME triggers detection via DNSTLS analyzer", func(t *testing.T) {
		t.Parallel()
		cnameResolver := &integrationCNAMEResolver{canonical: "e1234.dscg.akamaiedge.net."}
		analyzer, err := dnstls.New(dnstls.Config{
			LookupTimeout: time.Second,
			Resolver:      cnameResolver,
		})
		if err != nil {
			t.Fatal(err)
		}

		target := targetWithPriorHTTP(&analysis.TLSMetadata{
			Version:           tls.VersionTLS13,
			CertificateIssuer: "Akamai Subordinate CA",
		}, "https://example.com/")

		obs, err := analyzer.Observe(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}

		detections, err := scoring.Evaluate(ruleSet, obs.Signals)
		if err != nil {
			t.Fatal(err)
		}

		var akamai *scoring.Detection
		for _, d := range detections {
			if d.RuleID == "akamai.edge" {
				akamai = &d
				break
			}
		}

		if akamai == nil {
			t.Fatal("akamai.edge detection missing")
		}
		if !akamai.Detected {
			t.Errorf("akamai.edge not detected from decisive CNAME: score = %v", akamai.Score)
		}
		if akamai.Score != 95 {
			t.Errorf("akamai.edge score = %v, want 95 (75 CNAME + 20 TLS)", akamai.Score)
		}
	})
}

func TestHTTPAndDNSTLSScannerPipelineBuiltInDetections(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		headers      map[string]string
		cname        string
		wantRuleID   string
		wantScore    float64
		wantDetected bool
		wantLevel    scoring.Level
	}{
		{
			name: "Cloudflare HTTP Server + DNS CNAME correlation",
			headers: map[string]string{
				"Server": "cloudflare",
			},
			cname:        "origin.cdn.cloudflare.net.",
			wantRuleID:   "cloudflare.proxy",
			wantScore:    100,
			wantDetected: true,
			wantLevel:    scoring.LevelVeryHigh,
		},
		{
			name: "Amazon CloudFront HTTP header + DNS CNAME correlation",
			headers: map[string]string{
				"x-amz-cf-id": "sample-transaction-id",
			},
			cname:        "d123456abcdef8.cloudfront.net.",
			wantRuleID:   "aws.cloudfront",
			wantScore:    100,
			wantDetected: true,
			wantLevel:    scoring.LevelVeryHigh,
		},
		{
			name: "Akamai Edge HTTP Server + DNS CNAME correlation",
			headers: map[string]string{
				"Server": "AkamaiGHost",
			},
			cname:        "e1234.dscg.akamaiedge.net.",
			wantRuleID:   "akamai.edge",
			wantScore:    100,
			wantDetected: true,
			wantLevel:    scoring.LevelVeryHigh,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusOK)
			}))
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

			cnameResolver := &integrationCNAMEResolver{canonical: tc.cname}
			dnsTLSAnalyzer, err := dnstls.New(dnstls.Config{LookupTimeout: time.Second, Resolver: cnameResolver})
			if err != nil {
				t.Fatal(err)
			}

			engine, err := New(Config{
				Analyzers: []AnalyzerConfig{
					{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
					{Analyzer: dnsTLSAnalyzer, FailurePolicy: FailurePolicyContinue},
				},
				RuleSet: ruleSet,
			})
			if err != nil {
				t.Fatal(err)
			}

			result, err := engine.Scan(context.Background(), "https://example.com/")
			if err != nil {
				t.Fatal(err)
			}

			var matched *scoring.Detection
			for _, d := range result.Detections {
				if d.RuleID == tc.wantRuleID {
					matched = &d
					break
				}
			}

			if matched == nil {
				t.Fatalf("detection for rule %q not found in %#v", tc.wantRuleID, result.Detections)
			}
			if matched.Score != tc.wantScore {
				t.Errorf("rule %q score = %v, want %v", tc.wantRuleID, matched.Score, tc.wantScore)
			}
			if matched.Detected != tc.wantDetected {
				t.Errorf("rule %q detected = %v, want %v", tc.wantRuleID, matched.Detected, tc.wantDetected)
			}
			if matched.Level != tc.wantLevel {
				t.Errorf("rule %q level = %v, want %v", tc.wantRuleID, matched.Level, tc.wantLevel)
			}
		})
	}
}

func TestRequiresDependenciesEnforcementInBuiltInRules(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Akamai Bot Manager requires akamai.edge", func(t *testing.T) {
		t.Parallel()
		// Sensor script and cookie present, but NO Akamai Edge signals
		signalsWithoutEdge := []model.Signal{
			{
				Type:       model.SignalTypeScriptURL,
				Source:     analysis.SourceHTTP,
				Key:        "src",
				Value:      "https://example.com/akam/13/sensor.js",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeCookie,
				Source:     analysis.SourceHTTP,
				Key:        "_abck",
				Value:      "sample-abck",
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, signalsWithoutEdge)
		if err != nil {
			t.Fatal(err)
		}

		for _, d := range detections {
			if d.RuleID == "akamai.bot_manager" {
				if d.Detected {
					t.Errorf("akamai.bot_manager should not be detected without akamai.edge prerequisite")
				}
				if d.Score != 0 {
					t.Errorf("akamai.bot_manager score = %v, want 0 when prerequisite unmet", d.Score)
				}
			}
		}

		// Add Akamai Edge decisive signal
		signalsWithEdge := append(signalsWithoutEdge, model.Signal{
			Type:       model.SignalTypeResponseHeader,
			Source:     analysis.SourceHTTP,
			Key:        "Server",
			Value:      "AkamaiGHost",
			Confidence: 1.0,
		})

		detectionsWithEdge, err := scoring.Evaluate(ruleSet, signalsWithEdge)
		if err != nil {
			t.Fatal(err)
		}

		var bm *scoring.Detection
		for _, d := range detectionsWithEdge {
			if d.RuleID == "akamai.bot_manager" {
				bm = &d
				break
			}
		}

		if bm == nil || !bm.Detected || bm.Score != 100 {
			t.Fatalf("akamai.bot_manager failed detection with prerequisite satisfied: %#v", bm)
		}
	})

	t.Run("Cloudflare Challenge Page requires cloudflare.proxy", func(t *testing.T) {
		t.Parallel()
		signalsWithoutProxy := []model.Signal{
			{
				Type:       model.SignalTypeResponseHeader,
				Source:     analysis.SourceHTTP,
				Key:        "cf-mitigated",
				Value:      "challenge",
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, signalsWithoutProxy)
		if err != nil {
			t.Fatal(err)
		}

		for _, d := range detections {
			if d.RuleID == "cloudflare.challenge_page" {
				if d.Detected {
					t.Errorf("cloudflare.challenge_page should not be detected without cloudflare.proxy prerequisite")
				}
				if d.Score != 0 {
					t.Errorf("cloudflare.challenge_page score = %v, want 0 when prerequisite unmet", d.Score)
				}
			}
		}
	})
}
