package detectors

import (
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

func TestMultiSourceObservationChannelMatrix(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("DNS-only channel evaluation", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			ruleID     string
			signal     model.Signal
			wantMinSc  float64
			wantMaxSc  float64
			wantDetect bool
		}{
			{
				ruleID: "cloudflare.proxy",
				signal: model.Signal{
					Type:       model.SignalTypeDNSRecord,
					Source:     analysis.SourceDNSTLS,
					Key:        "cname",
					Value:      "example.cdn.cloudflare.net",
					Confidence: 1.0,
				},
				wantMinSc:  30,
				wantMaxSc:  30,
				wantDetect: false,
			},
			{
				ruleID: "aws.cloudfront",
				signal: model.Signal{
					Type:       model.SignalTypeDNSRecord,
					Source:     analysis.SourceDNSTLS,
					Key:        "cname",
					Value:      "d111111abcdef8.cloudfront.net",
					Confidence: 1.0,
				},
				wantMinSc:  30,
				wantMaxSc:  30,
				wantDetect: false,
			},
			{
				ruleID: "akamai.edge",
				signal: model.Signal{
					Type:       model.SignalTypeDNSRecord,
					Source:     analysis.SourceDNSTLS,
					Key:        "cname",
					Value:      "e1234.dscg.akamaiedge.net",
					Confidence: 1.0,
				},
				wantMinSc:  75,
				wantMaxSc:  75,
				wantDetect: true,
			},
		}

		for _, tc := range tests {
			tc := tc
			t.Run(tc.ruleID, func(t *testing.T) {
				t.Parallel()
				detections, err := scoring.Evaluate(ruleSet, []model.Signal{tc.signal})
				if err != nil {
					t.Fatal(err)
				}
				var found *scoring.Detection
				for _, d := range detections {
					if d.RuleID == tc.ruleID {
						found = &d
						break
					}
				}
				if found == nil {
					t.Fatalf("detection for rule %q not found", tc.ruleID)
				}
				if found.Score < tc.wantMinSc || found.Score > tc.wantMaxSc {
					t.Errorf("rule %q score = %v, want [%v, %v]", tc.ruleID, found.Score, tc.wantMinSc, tc.wantMaxSc)
				}
				if found.Detected != tc.wantDetect {
					t.Errorf("rule %q detected = %v, want %v", tc.ruleID, found.Detected, tc.wantDetect)
				}
			})
		}
	})

	t.Run("TLS-only channel evaluation", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			ruleID     string
			signal     model.Signal
			wantScore  float64
			wantDetect bool
		}{
			{
				ruleID: "cloudflare.proxy",
				signal: model.Signal{
					Type:       model.SignalTypeTLSProperty,
					Source:     analysis.SourceDNSTLS,
					Key:        "certificate_issuer",
					Value:      "Cloudflare Inc ECC CA-3",
					Confidence: 1.0,
				},
				wantScore:  20,
				wantDetect: false,
			},
			{
				ruleID: "aws.cloudfront",
				signal: model.Signal{
					Type:       model.SignalTypeTLSProperty,
					Source:     analysis.SourceDNSTLS,
					Key:        "certificate_issuer",
					Value:      "Amazon RSA 2048 M02",
					Confidence: 1.0,
				},
				wantScore:  20,
				wantDetect: false,
			},
			{
				ruleID: "akamai.edge",
				signal: model.Signal{
					Type:       model.SignalTypeTLSProperty,
					Source:     analysis.SourceDNSTLS,
					Key:        "certificate_issuer",
					Value:      "Akamai Subordinate CA",
					Confidence: 1.0,
				},
				wantScore:  20,
				wantDetect: false,
			},
		}

		for _, tc := range tests {
			tc := tc
			t.Run(tc.ruleID, func(t *testing.T) {
				t.Parallel()
				detections, err := scoring.Evaluate(ruleSet, []model.Signal{tc.signal})
				if err != nil {
					t.Fatal(err)
				}
				var found *scoring.Detection
				for _, d := range detections {
					if d.RuleID == tc.ruleID {
						found = &d
						break
					}
				}
				if found == nil {
					t.Fatalf("detection for rule %q not found", tc.ruleID)
				}
				if found.Score != tc.wantScore {
					t.Errorf("rule %q score = %v, want %v", tc.ruleID, found.Score, tc.wantScore)
				}
				if found.Detected != tc.wantDetect {
					t.Errorf("rule %q detected = %v, want %v", tc.ruleID, found.Detected, tc.wantDetect)
				}
			})
		}
	})

	t.Run("DNS and TLS multi-source aggregation without HTTP", func(t *testing.T) {
		t.Parallel()
		signals := []model.Signal{
			{
				Type:       model.SignalTypeDNSRecord,
				Source:     analysis.SourceDNSTLS,
				Key:        "cname",
				Value:      "site.cdn.cloudflare.net",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeTLSProperty,
				Source:     analysis.SourceDNSTLS,
				Key:        "certificate_issuer",
				Value:      "Cloudflare Inc ECC CA-3",
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, signals)
		if err != nil {
			t.Fatal(err)
		}

		for _, d := range detections {
			if d.RuleID == "cloudflare.proxy" {
				// 30 (DNS) + 20 (TLS) = 50 points (supporting only, < 75)
				if d.Score != 50 {
					t.Errorf("cloudflare.proxy score = %v, want 50", d.Score)
				}
				if d.Detected {
					t.Errorf("cloudflare.proxy should not be detected without decisive evidence")
				}
			}
		}
	})

	t.Run("HTTP + DNS + TLS full correlation", func(t *testing.T) {
		t.Parallel()
		signals := []model.Signal{
			{
				Type:       model.SignalTypeResponseHeader,
				Source:     analysis.SourceHTTP,
				Key:        "Server",
				Value:      "cloudflare",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeDNSRecord,
				Source:     analysis.SourceDNSTLS,
				Key:        "cname",
				Value:      "site.cdn.cloudflare.net",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeTLSProperty,
				Source:     analysis.SourceDNSTLS,
				Key:        "certificate_issuer",
				Value:      "Cloudflare Inc ECC CA-3",
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, signals)
		if err != nil {
			t.Fatal(err)
		}

		for _, d := range detections {
			if d.RuleID == "cloudflare.proxy" {
				// 75 (Server) + 30 (DNS) + 20 (TLS) = capped at 100
				if d.Score != 100 {
					t.Errorf("cloudflare.proxy score = %v, want 100", d.Score)
				}
				if !d.Detected {
					t.Errorf("cloudflare.proxy should be detected")
				}
				if d.Level != scoring.LevelVeryHigh {
					t.Errorf("cloudflare.proxy level = %v, want very_high", d.Level)
				}
			}
		}
	})
}

func TestCrossAnalyzerBrowserRegressions(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Dynamic browser injection for hCaptcha without static HTML tags", func(t *testing.T) {
		t.Parallel()
		// Signals emitted dynamically by Browser analyzer after post-load script injection
		dynamicSignals := []model.Signal{
			{
				Type:       model.SignalTypeScriptURL,
				Source:     analysis.SourceBrowser,
				Key:        "src",
				Value:      "https://js.hcaptcha.com/1/api.js",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypePageContent,
				Source:     analysis.SourceBrowser,
				Key:        "dom",
				Value:      `<div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>`,
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, dynamicSignals)
		if err != nil {
			t.Fatal(err)
		}

		var hcaptcha *scoring.Detection
		for _, d := range detections {
			if d.RuleID == "hcaptcha.challenge" {
				hcaptcha = &d
				break
			}
		}

		if hcaptcha == nil {
			t.Fatal("hcaptcha.challenge detection missing")
		}
		if !hcaptcha.Detected {
			t.Errorf("dynamic hCaptcha script not detected: score = %v", hcaptcha.Score)
		}
		if hcaptcha.Score != 75 {
			t.Errorf("dynamic hCaptcha score = %v, want 75 (group max for static_integration)", hcaptcha.Score)
		}
		if hcaptcha.Level != scoring.LevelHigh {
			t.Errorf("dynamic hCaptcha level = %v, want high", hcaptcha.Level)
		}
	})

	t.Run("Dynamic browser injection for Arkose Labs without static HTML tags", func(t *testing.T) {
		t.Parallel()
		dynamicSignals := []model.Signal{
			{
				Type:       model.SignalTypeScriptURL,
				Source:     analysis.SourceBrowser,
				Key:        "src",
				Value:      "https://client-api.arkoselabs.com/v2/api.js",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeIframeURL,
				Source:     analysis.SourceBrowser,
				Key:        "src",
				Value:      "https://client-api.arkoselabs.com/fc/api/?token=synthetic_token",
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, dynamicSignals)
		if err != nil {
			t.Fatal(err)
		}

		var arkose *scoring.Detection
		for _, d := range detections {
			if d.RuleID == "arkoselabs.matchkey" {
				arkose = &d
				break
			}
		}

		if arkose == nil {
			t.Fatal("arkoselabs.matchkey detection missing")
		}
		if !arkose.Detected {
			t.Errorf("dynamic Arkose Labs script not detected: score = %v", arkose.Score)
		}
		if arkose.Score != 75 {
			t.Errorf("dynamic Arkose Labs score = %v, want 75 (group max for static_integration)", arkose.Score)
		}
		if arkose.Level != scoring.LevelHigh {
			t.Errorf("dynamic Arkose Labs level = %v, want high", arkose.Level)
		}
	})

	t.Run("Browser dynamic iframe and cookie provenance for DataDome", func(t *testing.T) {
		t.Parallel()
		// Signals from Browser analyzer across different groups (iframe: static_integration, cookie: cookies)
		browserSignals := []model.Signal{
			{
				Type:       model.SignalTypeIframeURL,
				Source:     analysis.SourceBrowser,
				Key:        "src",
				Value:      "https://geo.captcha-delivery.com/captcha/?initialCid=AHrlqAAAAAMA",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeCookie,
				Source:     analysis.SourceBrowser,
				Key:        "datadome",
				Value:      "AHrlqAAAAAMAx_example_token",
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, browserSignals)
		if err != nil {
			t.Fatal(err)
		}

		var datadome *scoring.Detection
		for _, d := range detections {
			if d.RuleID == "datadome.bot_protection" {
				datadome = &d
				break
			}
		}

		if datadome == nil {
			t.Fatal("datadome.bot_protection detection missing")
		}
		if !datadome.Detected {
			t.Errorf("datadome.bot_protection not detected: score = %v", datadome.Score)
		}
		if datadome.Score != 100 {
			t.Errorf("datadome score = %v, want 100 (75 iframe + 40 cookie capped at 100)", datadome.Score)
		}
	})

	t.Run("Browser cookie and script provenance for Akamai Bot Manager with HTTP Edge prerequisite", func(t *testing.T) {
		t.Parallel()
		signals := []model.Signal{
			{
				Type:       model.SignalTypeResponseHeader,
				Source:     analysis.SourceHTTP,
				Key:        "Server",
				Value:      "AkamaiGHost",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeScriptURL,
				Source:     analysis.SourceBrowser,
				Key:        "src",
				Value:      "https://example.com/akam/13/sensor.js",
				Confidence: 1.0,
			},
			{
				Type:       model.SignalTypeCookie,
				Source:     analysis.SourceBrowser,
				Key:        "_abck",
				Value:      "synthetic_abck_token~0~YAAQ",
				Confidence: 1.0,
			},
		}

		detections, err := scoring.Evaluate(ruleSet, signals)
		if err != nil {
			t.Fatal(err)
		}

		var bm *scoring.Detection
		for _, d := range detections {
			if d.RuleID == "akamai.bot_manager" {
				bm = &d
				break
			}
		}

		if bm == nil {
			t.Fatal("akamai.bot_manager detection missing")
		}
		if !bm.Detected {
			t.Errorf("akamai.bot_manager not detected: score = %v", bm.Score)
		}
		if bm.Score != 100 {
			t.Errorf("akamai.bot_manager score = %v, want 100", bm.Score)
		}
	})
}
