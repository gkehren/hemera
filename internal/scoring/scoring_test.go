package scoring

import (
	"math"
	"os"
	"reflect"
	"testing"

	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

func TestEvaluateAppliesWeightedEvidencePenaltiesAndDependencies(t *testing.T) {
	t.Parallel()
	ruleSet := loadRuleFixture(t)
	signals := []model.Signal{
		testSignal(model.SignalTypeResponseHeader, "Server", "Acme edge", 1),
		testSignal(model.SignalTypeCookie, "acme_session", "", 0.6),
		testSignal(model.SignalTypeResourceHost, "host", "static.acme.test", 0.9),
		testSignal(model.SignalTypeResponseHeader, "X-Origin-Exposed", "true", 1),
		testSignal(model.SignalTypeResponseHeader, "Via", "generic proxy", 0.5),
		testSignal(model.SignalTypeResponseHeader, "X-Legacy", "true", 1),
		testSignal(model.SignalTypeScriptURL, "src", "https://static.acme.test/v1/challenge.js?redacted", 1),
	}

	detections, err := Evaluate(ruleSet, signals)
	if err != nil {
		t.Fatal(err)
	}
	if len(detections) != 3 {
		t.Fatalf("detections = %#v", detections)
	}
	edge := detections[0]
	if edge.EvidenceScore != 52 || edge.Score != 52 || !edge.Detected || edge.Level != LevelMedium {
		t.Errorf("edge score = %#v, want detected medium at 52", edge)
	}
	if got, want := edge.AppliedConflicts, []AppliedConflict{{RuleID: "legacy.edge", Penalty: 15}}; !reflect.DeepEqual(got, want) {
		t.Errorf("conflicts = %#v, want %#v", got, want)
	}
	if len(edge.PositiveEvidence) != 3 || len(edge.NegativeEvidence) != 1 || len(edge.AmbiguousEvidence) != 1 {
		t.Errorf("edge evidence counts = %d/%d/%d", len(edge.PositiveEvidence), len(edge.NegativeEvidence), len(edge.AmbiguousEvidence))
	}
	legacy := detections[1]
	if legacy.Score != 50 || !legacy.Detected || legacy.Level != LevelMedium {
		t.Errorf("legacy detection = %#v", legacy)
	}
	challenge := detections[2]
	if challenge.Score != 70 || !challenge.Detected || challenge.Level != LevelMedium || len(challenge.MissingDependencies) != 0 {
		t.Errorf("challenge detection = %#v", challenge)
	}
}

func TestEvaluateBlocksProductWhenDependencyIsMissing(t *testing.T) {
	t.Parallel()
	ruleSet := loadRuleFixture(t)
	detections, err := Evaluate(ruleSet, []model.Signal{
		testSignal(model.SignalTypeScriptURL, "src", "https://static.acme.test/v1/challenge.js", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge := detections[2]
	if challenge.EvidenceScore != 70 || challenge.Score != 0 || challenge.Detected || challenge.Level != LevelNotDetected {
		t.Errorf("challenge detection = %#v", challenge)
	}
	if got, want := challenge.MissingDependencies, []string{"acme.edge"}; !reflect.DeepEqual(got, want) {
		t.Errorf("missing dependencies = %v, want %v", got, want)
	}
}

func TestEvaluateDoesNotInferProductFromVendorRule(t *testing.T) {
	t.Parallel()
	ruleSet := loadRuleFixture(t)
	detections, err := Evaluate(ruleSet, []model.Signal{
		testSignal(model.SignalTypeResponseHeader, "Server", "Acme edge", 1),
		testSignal(model.SignalTypeCookie, "acme_session", "", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !detections[0].Detected {
		t.Fatalf("vendor rule did not detect: %#v", detections[0])
	}
	if detections[2].ConditionMatched || detections[2].Detected || detections[2].Score != 0 {
		t.Errorf("vendor evidence inferred product: %#v", detections[2])
	}
}

func TestEvaluateIgnoresZeroConfidenceConflictCandidate(t *testing.T) {
	t.Parallel()
	ruleSet := loadRuleFixture(t)
	detections, err := Evaluate(ruleSet, []model.Signal{
		testSignal(model.SignalTypeResponseHeader, "Server", "Acme edge", 1),
		testSignal(model.SignalTypeCookie, "acme_session", "", 1),
		testSignal(model.SignalTypeResponseHeader, "X-Legacy", "true", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	edge := detections[0]
	if edge.Score != 70 || !edge.Detected {
		t.Errorf("edge detection = %#v, want score 70 without conflict penalty", edge)
	}
	if len(edge.AppliedConflicts) != 0 {
		t.Errorf("zero-confidence conflict was applied: %#v", edge.AppliedConflicts)
	}
	if !detections[1].ConditionMatched || detections[1].EvidenceScore != 0 || detections[1].Detected {
		t.Errorf("zero-confidence candidate = %#v", detections[1])
	}
}

func TestEvaluateClampsScores(t *testing.T) {
	t.Parallel()
	ruleSet := rules.RuleSet{SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{
		scoringRule("upper", 1, 25, rules.Condition{All: []rules.Condition{
			{Signal: scoreEvidence("upper-one", "one", 100)},
			{Signal: scoreEvidence("upper-two", "two", 100)},
		}}),
		scoringRule("lower", 1, 25, rules.Condition{Signal: scoreEvidence("lower-positive", "positive", 10)}),
	}}
	ruleSet.Rules[1].NegativeEvidence = []rules.Evidence{*scoreEvidence("lower-negative", "negative", 100)}
	signals := []model.Signal{
		testSignal(model.SignalTypeCookie, "one", "", 1),
		testSignal(model.SignalTypeCookie, "two", "", 1),
		testSignal(model.SignalTypeCookie, "positive", "", 1),
		testSignal(model.SignalTypeCookie, "negative", "", 1),
	}
	detections, err := Evaluate(ruleSet, signals)
	if err != nil {
		t.Fatal(err)
	}
	if detections[0].Score != 100 || detections[0].Level != LevelVeryHigh {
		t.Errorf("upper score = %#v", detections[0])
	}
	if detections[1].Score != 0 || detections[1].Level != LevelNotDetected {
		t.Errorf("lower score = %#v", detections[1])
	}
}

func TestLevelForScoreBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		score float64
		level Level
	}{
		{-1, LevelNotDetected},
		{0, LevelNotDetected},
		{24.99, LevelNotDetected},
		{25, LevelLow},
		{49.99, LevelLow},
		{50, LevelMedium},
		{74.99, LevelMedium},
		{75, LevelHigh},
		{89.99, LevelHigh},
		{90, LevelVeryHigh},
		{100, LevelVeryHigh},
		{101, LevelVeryHigh},
		{math.NaN(), LevelNotDetected},
	}
	for _, tt := range tests {
		if got := LevelForScore(tt.score); got != tt.level {
			t.Errorf("LevelForScore(%v) = %q, want %q", tt.score, got, tt.level)
		}
	}
}

func TestEvaluateRejectsInvalidSignalsAndRules(t *testing.T) {
	t.Parallel()
	ruleSet := loadRuleFixture(t)
	invalidSignal := testSignal(model.SignalTypeCookie, "key", "", math.NaN())
	if _, err := Evaluate(ruleSet, []model.Signal{invalidSignal}); err == nil {
		t.Error("Evaluate() accepted invalid signal")
	}
	ruleSet.SchemaVersion = 2
	if _, err := Evaluate(ruleSet, nil); err == nil {
		t.Error("Evaluate() accepted invalid rule set")
	}
}

func loadRuleFixture(t *testing.T) rules.RuleSet {
	t.Helper()
	file, err := os.Open("../rules/testdata/valid-rules.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ruleSet, err := rules.DecodeJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	return ruleSet
}

func testSignal(signalType model.SignalType, key, value string, confidence float64) model.Signal {
	return model.Signal{Type: signalType, Source: "fixture", Key: key, Value: value, Confidence: confidence}
}

func scoringRule(id string, minimumEvidence int, minimumScore float64, condition rules.Condition) rules.Rule {
	return rules.Rule{
		ID: id, Name: id, Category: rules.CategoryThirdPartySecurity, Vendor: "Fixture",
		MinimumEvidence: minimumEvidence, MinimumScore: minimumScore, Match: condition,
	}
}

func scoreEvidence(id, key string, weight float64) *rules.Evidence {
	return &rules.Evidence{
		ID: id, Type: model.SignalTypeCookie,
		Key: &rules.TextPattern{Exact: scoreString(key)}, Weight: weight,
	}
}

func scoreString(value string) *string {
	return &value
}
