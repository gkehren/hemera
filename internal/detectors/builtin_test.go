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
	if len(ruleSet.Rules) != 2 {
		t.Fatalf("built-in rules = %d, want 2", len(ruleSet.Rules))
	}
	if ruleSet.SchemaVersion != rules.CurrentSchemaVersion {
		t.Errorf("built-in schema version = %d, want %d", ruleSet.SchemaVersion, rules.CurrentSchemaVersion)
	}
	wantIDs := []string{"cloudflare.turnstile", "google.recaptcha"}
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

	signal.Source = analysis.SourceBrowser
	browserDetections, err := scoring.Evaluate(ruleSet, []model.Signal{signal})
	if err != nil {
		t.Fatal(err)
	}
	if browserDetections[0].Detected || browserDetections[0].Score != 0 {
		t.Errorf("browser-only dynamic evidence changed static Turnstile coverage: %#v", browserDetections[0])
	}

	signal.Source = analysis.SourceHTTP
	httpDetections, err := scoring.Evaluate(ruleSet, []model.Signal{signal})
	if err != nil {
		t.Fatal(err)
	}
	if !httpDetections[0].Detected || httpDetections[0].Score != 75 {
		t.Errorf("HTTP static evidence detection = %#v", httpDetections[0])
	}
}
