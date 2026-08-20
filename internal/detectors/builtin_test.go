package detectors

import (
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

func TestLoadBuiltInRules(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ruleSet.Rules) != 12 {
		t.Fatalf("built-in rules = %d, want 12", len(ruleSet.Rules))
	}
	if ruleSet.SchemaVersion != rules.CurrentSchemaVersion {
		t.Errorf("built-in schema version = %d, want %d", ruleSet.SchemaVersion, rules.CurrentSchemaVersion)
	}
	wantIDs := []string{
		"cloudflare.proxy",
		"cloudflare.challenge_page",
		"cloudflare.bot_protection",
		"cloudflare.turnstile",
		"google.recaptcha",
		"aws.cloudfront",
		"aws.waf",
		"datadome.bot_protection",
		"akamai.edge",
		"akamai.bot_manager",
		"hcaptcha.challenge",
		"arkoselabs.matchkey",
	}
	for i, want := range wantIDs {
		if got := ruleSet.Rules[i].ID; got != want {
			t.Errorf("rules[%d].ID = %q, want %q", i, got, want)
		}
	}

	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	ruleSet.Rules[0].Name = "mutated"
	if second.Rules[0].Name == "mutated" {
		t.Error("Load returned shared mutable rule state")
	}
}

func TestBuiltInRulesRemainLimitedToStaticHTTPObservations(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	signal := model.Signal{
		Type: model.SignalTypeScriptURL, Key: "src",
		Value:      "https://challenges.cloudflare.com/turnstile/v0/api.js",
		Confidence: 1,
	}

	findDetection := func(detections []scoring.Detection, id string) scoring.Detection {
		for _, d := range detections {
			if d.RuleID == id {
				return d
			}
		}
		return scoring.Detection{}
	}

	signal.Source = analysis.SourceBrowser
	browserDetections, err := scoring.Evaluate(ruleSet, []model.Signal{signal})
	if err != nil {
		t.Fatal(err)
	}
	turnstileBrowser := findDetection(browserDetections, "cloudflare.turnstile")
	if turnstileBrowser.Detected || turnstileBrowser.Score != 0 {
		t.Errorf("browser-only dynamic evidence changed static Turnstile coverage: %#v", turnstileBrowser)
	}

	signal.Source = analysis.SourceHTTP
	httpDetections, err := scoring.Evaluate(ruleSet, []model.Signal{signal})
	if err != nil {
		t.Fatal(err)
	}
	turnstileHTTP := findDetection(httpDetections, "cloudflare.turnstile")
	if !turnstileHTTP.Detected || turnstileHTTP.Score != 75 {
		t.Errorf("HTTP static evidence detection = %#v", turnstileHTTP)
	}
}

func TestDataDomeSignatureSemantics(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		signal       model.Signal
		wantDetected bool
	}{
		{
			name: "unversioned tags.js",
			signal: model.Signal{
				Type: model.SignalTypeScriptURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://js.datadome.co/tags.js", Confidence: 1,
			},
			wantDetected: true,
		},
		{
			name: "versioned v5.1.13 tags.js",
			signal: model.Signal{
				Type: model.SignalTypeScriptURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://js.datadome.co/v5.1.13/tags.js", Confidence: 1,
			},
			wantDetected: true,
		},
		{
			name: "invalid two-component version rejected",
			signal: model.Signal{
				Type: model.SignalTypeScriptURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://js.datadome.co/v5.1/tags.js", Confidence: 1,
			},
			wantDetected: false,
		},
		{
			name: "invalid four-component version rejected",
			signal: model.Signal{
				Type: model.SignalTypeScriptURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://js.datadome.co/v5.1.13.7/tags.js", Confidence: 1,
			},
			wantDetected: false,
		},
		{
			name: "iframe on ct subdomain",
			signal: model.Signal{
				Type: model.SignalTypeIframeURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://ct.captcha-delivery.com/captcha/?initialCid=abc", Confidence: 1,
			},
			wantDetected: true,
		},
		{
			name: "iframe on geo subdomain",
			signal: model.Signal{
				Type: model.SignalTypeIframeURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://geo.captcha-delivery.com/captcha/?initialCid=abc", Confidence: 1,
			},
			wantDetected: true,
		},
		{
			name: "iframe on apex domain rejected",
			signal: model.Signal{
				Type: model.SignalTypeIframeURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://captcha-delivery.com/captcha/?initialCid=abc", Confidence: 1,
			},
			wantDetected: false,
		},
		{
			name: "iframe on attacker lookalike domain rejected",
			signal: model.Signal{
				Type: model.SignalTypeIframeURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://captcha-delivery.com.attacker.example/captcha/", Confidence: 1,
			},
			wantDetected: false,
		},
		{
			name: "script on ct subdomain",
			signal: model.Signal{
				Type: model.SignalTypeScriptURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://ct.captcha-delivery.com/tags.js", Confidence: 1,
			},
			wantDetected: true,
		},
		{
			name: "script on geo subdomain rejected (ct only)",
			signal: model.Signal{
				Type: model.SignalTypeScriptURL, Source: analysis.SourceHTTP, Key: "src",
				Value: "https://geo.captcha-delivery.com/tags.js", Confidence: 1,
			},
			wantDetected: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			detections, err := scoring.Evaluate(ruleSet, []model.Signal{tc.signal})
			if err != nil {
				t.Fatal(err)
			}
			var isDetected bool
			for _, d := range detections {
				if d.RuleID == "datadome.bot_protection" && d.Detected {
					isDetected = true
				}
			}
			if isDetected != tc.wantDetected {
				t.Errorf("datadome.bot_protection detected = %v, want %v for signal %v", isDetected, tc.wantDetected, tc.signal.Value)
			}
		})
	}
}

func TestAkamaiSessionInfoAndReferenceErrorDoNotAttributeWAF(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	signals := []model.Signal{
		{
			Type: model.SignalTypeResponseHeader, Source: analysis.SourceHTTP,
			Key: "Server", Value: "AkamaiGHost", Confidence: 1,
		},
		{
			Type: model.SignalTypeResponseHeader, Source: analysis.SourceHTTP,
			Key: "x-akamai-session-info", Value: "name=ORIGIN_ROUTING; value=primary", Confidence: 1,
		},
		{
			Type: model.SignalTypePageContent, Source: analysis.SourceHTTP,
			Key: "dom", Value: "Access Denied You don't have permission to access on this server. Reference #18.12345678", Confidence: 1,
		},
	}

	detections, err := scoring.Evaluate(ruleSet, signals)
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range detections {
		if d.RuleID == "akamai.edge" {
			if !d.Detected {
				t.Error("akamai.edge should be detected from Server header")
			}
		} else if d.Detected {
			t.Errorf("unexpected product detection %q for Akamai edge diagnostics signals", d.RuleID)
		}
	}
}
