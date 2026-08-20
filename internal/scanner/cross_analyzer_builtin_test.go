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
	"slices"
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
				if d.Level != scoring.LevelMedium {
					t.Errorf("cloudflare.proxy level = %v, want medium", d.Level)
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
		if akamai.Level != scoring.LevelVeryHigh {
			t.Errorf("akamai.edge level = %v, want very_high", akamai.Level)
		}

		// Verify specific evidence IDs and sources
		var matchedIDs []string
		for _, ev := range akamai.PositiveEvidence {
			matchedIDs = append(matchedIDs, ev.Match.EvidenceID)
			if ev.Match.Signal.Source != analysis.SourceDNSTLS {
				t.Errorf("evidence %q has source %q, want %q", ev.Match.EvidenceID, ev.Match.Signal.Source, analysis.SourceDNSTLS)
			}
		}
		if !slices.Contains(matchedIDs, "akamai-cname") || !slices.Contains(matchedIDs, "akamai-cert-issuer") {
			t.Errorf("akamai.edge matched evidence = %v, want [akamai-cname, akamai-cert-issuer]", matchedIDs)
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
		name            string
		headers         map[string]string
		cname           string
		wantRuleID      string
		wantScore       float64
		wantDetected    bool
		wantLevel       scoring.Level
		wantEvidenceIDs []string
	}{
		{
			name: "Cloudflare HTTP Server + DNS CNAME correlation",
			headers: map[string]string{
				"Server": "cloudflare",
			},
			cname:           "origin.cdn.cloudflare.net.",
			wantRuleID:      "cloudflare.proxy",
			wantScore:       100,
			wantDetected:    true,
			wantLevel:       scoring.LevelVeryHigh,
			wantEvidenceIDs: []string{"cloudflare-server-header", "cloudflare-cname"},
		},
		{
			name: "Amazon CloudFront HTTP header + DNS CNAME correlation",
			headers: map[string]string{
				"x-amz-cf-id": "sample-transaction-id",
			},
			cname:           "d123456abcdef8.cloudfront.net.",
			wantRuleID:      "aws.cloudfront",
			wantScore:       100,
			wantDetected:    true,
			wantLevel:       scoring.LevelVeryHigh,
			wantEvidenceIDs: []string{"aws-cf-id-header", "aws-cf-cname"},
		},
		{
			name: "Akamai Edge HTTP Server + DNS CNAME correlation",
			headers: map[string]string{
				"Server": "AkamaiGHost",
			},
			cname:           "e1234.dscg.akamaiedge.net.",
			wantRuleID:      "akamai.edge",
			wantScore:       100,
			wantDetected:    true,
			wantLevel:       scoring.LevelVeryHigh,
			wantEvidenceIDs: []string{"akamai-ghost-server-header", "akamai-cname"},
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

			var matchedEvidenceIDs []string
			for _, ev := range matched.PositiveEvidence {
				matchedEvidenceIDs = append(matchedEvidenceIDs, ev.Match.EvidenceID)
			}
			for _, wantEID := range tc.wantEvidenceIDs {
				if !slices.Contains(matchedEvidenceIDs, wantEID) {
					t.Errorf("rule %q matched evidence %v does not contain %q", tc.wantRuleID, matchedEvidenceIDs, wantEID)
				}
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

func TestIncompleteCoverageEvaluationWithBuiltInRules(t *testing.T) {
	t.Parallel()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("HTTP only on clean page marks browser-capable rules as insufficient_coverage", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body>Clean Page</body></html>"))
		}))
		defer server.Close()

		local, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		httpConfig := httpanalyzer.DefaultConfig()
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

		engine, err := New(Config{
			Analyzers: []AnalyzerConfig{
				{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
			},
			RuleSet: ruleSet,
		})
		if err != nil {
			t.Fatal(err)
		}

		result, err := engine.Scan(context.Background(), "http://fixture.example/")
		if err != nil {
			t.Fatal(err)
		}

		coverageMap := make(map[string]DetectionCoverage, len(result.Coverage))
		for _, cov := range result.Coverage {
			coverageMap[cov.RuleID] = cov
		}

		// hCaptcha supports browser analyzer; with browser analyzer missing on clean page, status is insufficient_coverage
		if cov, ok := coverageMap["hcaptcha.challenge"]; !ok {
			t.Fatal("hcaptcha.challenge missing from coverage")
		} else if cov.Status != DetectionStatusInsufficientCoverage {
			t.Errorf("hcaptcha.challenge coverage status = %q, want %q", cov.Status, DetectionStatusInsufficientCoverage)
		} else if !slices.Contains(cov.IncompleteSources, analysis.SourceBrowser) {
			t.Errorf("hcaptcha.challenge incomplete sources = %v, want to contain %q", cov.IncompleteSources, analysis.SourceBrowser)
		}

		// Cloudflare Turnstile requires exact: "http_analyzer" in Milestone 1 rules; with HTTP complete, status is not_detected
		if cov, ok := coverageMap["cloudflare.turnstile"]; !ok {
			t.Fatal("cloudflare.turnstile missing from coverage")
		} else if cov.Status != DetectionStatusNotDetected {
			t.Errorf("cloudflare.turnstile coverage status = %q, want %q", cov.Status, DetectionStatusNotDetected)
		}

		// Akamai Bot Manager requires akamai.edge; since akamai.edge has insufficient_coverage (missing dnstls), akamai.bot_manager is also insufficient_coverage
		if cov, ok := coverageMap["akamai.bot_manager"]; !ok {
			t.Fatal("akamai.bot_manager missing from coverage")
		} else if cov.Status != DetectionStatusInsufficientCoverage {
			t.Errorf("akamai.bot_manager coverage status = %q, want %q when prerequisite coverage is incomplete", cov.Status, DetectionStatusInsufficientCoverage)
		} else if !slices.Contains(cov.IncompleteSources, analysis.SourceBrowser) || !slices.Contains(cov.IncompleteSources, analysis.SourceDNSTLS) {
			t.Errorf("akamai.bot_manager incomplete sources = %v, want to contain browser and dnstls", cov.IncompleteSources)
		}
	})

	t.Run("HTTP decisive evidence marks rule as detected regardless of missing secondary analyzers", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		local, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}

		httpConfig := httpanalyzer.DefaultConfig()
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

		engine, err := New(Config{
			Analyzers: []AnalyzerConfig{
				{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
			},
			RuleSet: ruleSet,
		})
		if err != nil {
			t.Fatal(err)
		}

		result, err := engine.Scan(context.Background(), "http://fixture.example/")
		if err != nil {
			t.Fatal(err)
		}

		for _, cov := range result.Coverage {
			if cov.RuleID == "cloudflare.proxy" {
				if cov.Status != DetectionStatusDetected {
					t.Errorf("cloudflare.proxy coverage status = %q, want %q", cov.Status, DetectionStatusDetected)
				}
			}
		}
	})
}
