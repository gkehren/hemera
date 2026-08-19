package scoring

import (
	"math"
	"os"
	"reflect"
	"slices"
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
	if got := len(edge.PositiveEvidenceGroups); got != 3 {
		t.Errorf("edge positive groups = %d, want 3", got)
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

func TestEvaluateCapsCorrelatedEvidenceAndAddsComplementaryGroups(t *testing.T) {
	t.Parallel()
	ruleSet := rules.RuleSet{SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{
		scoringRule("grouped", 1, 75, rules.Condition{Any: []rules.Condition{
			{Signal: groupedScoreEvidence("client-script", "static_integration", model.SignalTypeScriptURL, "script", 75)},
			{Signal: groupedScoreEvidence("html-marker", "static_integration", model.SignalTypePageContent, "marker", 30)},
			{Signal: groupedScoreEvidence("network-request", "browser_network", model.SignalTypeNetworkRequest, "request", 15)},
		}}),
	}}

	staticOnly, err := Evaluate(ruleSet, []model.Signal{
		testSignal(model.SignalTypeScriptURL, "script", "", 1),
		testSignal(model.SignalTypePageContent, "marker", "", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	detection := staticOnly[0]
	if detection.Score != 75 || detection.Level != LevelHigh || !detection.Detected {
		t.Fatalf("correlated static score = %#v, want detected high at 75", detection)
	}
	wantGroup := EvidenceGroup{
		ID: "static_integration", EvidenceIDs: []string{"client-script", "html-marker"},
		SelectedEvidenceID: "client-script", RawContribution: 105, Contribution: 75,
	}
	if got := detection.PositiveEvidenceGroups; len(got) != 1 || !reflect.DeepEqual(got[0], wantGroup) {
		t.Fatalf("static evidence groups = %#v, want %#v", got, wantGroup)
	}
	if got := detection.PositiveEvidence; got[0].RawContribution != 75 || got[0].Contribution != 75 ||
		got[1].RawContribution != 30 || got[1].Contribution != 0 {
		t.Errorf("correlated evidence contributions = %#v", got)
	}

	complementary, err := Evaluate(ruleSet, []model.Signal{
		testSignal(model.SignalTypeNetworkRequest, "request", "", 1),
		testSignal(model.SignalTypePageContent, "marker", "", 1),
		testSignal(model.SignalTypeScriptURL, "script", "", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := complementary[0]; got.Score != 90 || got.Level != LevelVeryHigh || len(got.PositiveEvidenceGroups) != 2 {
		t.Errorf("complementary score = %#v, want very high at 90", got)
	}
}

func TestEvaluateAppliesPenaltiesAfterPositiveGrouping(t *testing.T) {
	t.Parallel()
	rule := scoringRule("penalized", 1, 50, rules.Condition{Any: []rules.Condition{
		{Signal: groupedScoreEvidence("strong", "static_integration", model.SignalTypeCookie, "strong", 75)},
		{Signal: groupedScoreEvidence("duplicate", "static_integration", model.SignalTypeCookie, "duplicate", 30)},
	}})
	rule.NegativeEvidence = []rules.Evidence{*scoreEvidence("negative", "negative", 10)}
	rule.AmbiguousEvidence = []rules.Evidence{*scoreEvidence("ambiguous", "ambiguous", 5)}

	detections, err := Evaluate(rules.RuleSet{
		SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{rule},
	}, []model.Signal{
		testSignal(model.SignalTypeCookie, "strong", "", 1),
		testSignal(model.SignalTypeCookie, "duplicate", "", 1),
		testSignal(model.SignalTypeCookie, "negative", "", 1),
		testSignal(model.SignalTypeCookie, "ambiguous", "", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := detections[0]; got.EvidenceScore != 60 || got.Score != 60 || !got.Detected {
		t.Errorf("penalized grouped score = %#v, want detected at 60", got)
	}
	if got := detections[0].NegativeEvidence[0]; got.RawContribution != -10 || got.Contribution != -10 {
		t.Errorf("negative contribution = %#v, want -10/-10", got)
	}
	if got := detections[0].AmbiguousEvidence[0]; got.RawContribution != -5 || got.Contribution != -5 {
		t.Errorf("ambiguous contribution = %#v, want -5/-5", got)
	}
}

func TestEvaluateKeepsInactiveEvidenceRawButNotContributing(t *testing.T) {
	t.Parallel()
	rule := scoringRule("partial", 2, 50, rules.Condition{Any: []rules.Condition{
		{Signal: groupedScoreEvidence("script", "static_integration", model.SignalTypeScriptURL, "script", 75)},
		{Signal: groupedScoreEvidence("marker", "static_integration", model.SignalTypePageContent, "marker", 30)},
		{Signal: groupedScoreEvidence("request", "browser_network", model.SignalTypeNetworkRequest, "request", 15)},
	}})
	rule.NegativeEvidence = []rules.Evidence{*scoreEvidence("negative", "negative", 10)}

	detections, err := Evaluate(rules.RuleSet{
		SchemaVersion: rules.CurrentSchemaVersion, Rules: []rules.Rule{rule},
	}, []model.Signal{
		testSignal(model.SignalTypeScriptURL, "script", "", 1),
		testSignal(model.SignalTypePageContent, "marker", "", 1),
		testSignal(model.SignalTypeCookie, "negative", "", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	detection := detections[0]
	if !detection.ConditionMatched || detection.MinimumEvidenceMet || detection.EvidenceScore != 0 {
		t.Fatalf("partial detection = %#v", detection)
	}
	if got := detection.PositiveEvidenceGroups[0]; got.RawContribution != 105 || got.Contribution != 0 {
		t.Errorf("inactive group = %#v, want raw 105 and contribution 0", got)
	}
	for _, evidence := range append(detection.PositiveEvidence, detection.NegativeEvidence...) {
		if evidence.RawContribution == 0 || evidence.Contribution != 0 {
			t.Errorf("inactive evidence = %#v, want non-zero raw and zero contribution", evidence)
		}
	}
}

func TestEvaluatePreservesV1AdditiveScoring(t *testing.T) {
	t.Parallel()
	ruleSet := rules.RuleSet{SchemaVersion: 1, Rules: []rules.Rule{
		scoringRule("legacy", 1, 75, rules.Condition{Any: []rules.Condition{
			{Signal: scoreEvidence("script", "script", 75)},
			{Signal: scoreEvidence("marker", "marker", 30)},
		}}),
	}}
	detections, err := Evaluate(ruleSet, []model.Signal{
		testSignal(model.SignalTypeCookie, "script", "", 1),
		testSignal(model.SignalTypeCookie, "marker", "", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := detections[0]; got.Score != 100 || len(got.PositiveEvidenceGroups) != 2 {
		t.Errorf("V1 additive detection = %#v, want score 100 from independent predicates", got)
	}
}

func TestEvaluateIsInvariantToRuleAndSignalOrder(t *testing.T) {
	t.Parallel()
	ruleSet := loadRuleFixture(t)
	signals := []model.Signal{
		testSignal(model.SignalTypeResponseHeader, "Server", "Acme edge", 1),
		testSignal(model.SignalTypeCookie, "acme_session", "", 0.6),
		testSignal(model.SignalTypeResourceHost, "host", "static.acme.test", 0.9),
		testSignal(model.SignalTypeResponseHeader, "X-Legacy", "true", 1),
		testSignal(model.SignalTypeScriptURL, "src", "https://static.acme.test/v1/challenge.js", 1),
	}
	want, err := Evaluate(ruleSet, signals)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(ruleSet.Rules)
	slices.Reverse(signals)
	got, err := Evaluate(ruleSet, signals)
	if err != nil {
		t.Fatal(err)
	}

	type stableResult struct {
		EvidenceScore float64
		Score         float64
		Detected      bool
		Groups        []EvidenceGroup
		Conflicts     []AppliedConflict
		Dependencies  []string
	}
	byID := func(detections []Detection) map[string]stableResult {
		results := make(map[string]stableResult, len(detections))
		for _, detection := range detections {
			results[detection.RuleID] = stableResult{
				EvidenceScore: detection.EvidenceScore, Score: detection.Score,
				Detected: detection.Detected, Groups: detection.PositiveEvidenceGroups,
				Conflicts: detection.AppliedConflicts, Dependencies: detection.MissingDependencies,
			}
		}
		return results
	}
	if !reflect.DeepEqual(byID(got), byID(want)) {
		t.Errorf("order changed results\ngot:  %#v\nwant: %#v", byID(got), byID(want))
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
	ruleSet.SchemaVersion = 3
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

func groupedScoreEvidence(id, group string, signalType model.SignalType, key string, weight float64) *rules.Evidence {
	evidence := scoreEvidence(id, key, weight)
	evidence.Group = group
	evidence.Type = signalType
	return evidence
}

func scoreString(value string) *string {
	return &value
}
