package detectors

import (
	"testing"

	"github.com/gkehren/hemera/internal/rules"
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
