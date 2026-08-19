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
	if len(ruleSet.Rules) != 5 {
		t.Fatalf("built-in rules = %d, want 5", len(ruleSet.Rules))
	}
	if ruleSet.SchemaVersion != rules.CurrentSchemaVersion {
		t.Errorf("built-in schema version = %d, want %d", ruleSet.SchemaVersion, rules.CurrentSchemaVersion)
	}
	wantIDs := []string{
		"cloudflare.proxy",
		"cloudflare.waf",
		"cloudflare.bot_management",
		"cloudflare.turnstile",
		"google.recaptcha",
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
