package rules

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

func TestMatchEvaluatesAllAnyAndPenaltyEvidence(t *testing.T) {
	t.Parallel()
	ruleSet := loadFixture(t)
	signals := []model.Signal{
		signal(model.SignalTypeResponseHeader, "Server", "ACME edge", 1),
		signal(model.SignalTypeCookie, "acme_session", "", 0.6),
		signal(model.SignalTypeResourceHost, "host", "static.acme.test", 0.4),
		signal(model.SignalTypeResourceHost, "host", "static.acme.test", 0.9),
		signal(model.SignalTypeResponseHeader, "X-Origin-Exposed", "TRUE", 1),
		signal(model.SignalTypeResponseHeader, "Via", "generic proxy", 0.5),
	}

	results, err := Match(ruleSet, signals)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %#v", results)
	}
	edge := results[0]
	if !edge.Candidate() {
		t.Fatalf("edge match = %#v", edge)
	}
	if got, want := evidenceIDs(edge.PositiveEvidence), []string{"acme-server", "acme-cookie", "acme-resource"}; !reflect.DeepEqual(got, want) {
		t.Errorf("positive evidence = %v, want %v", got, want)
	}
	if got := edge.PositiveEvidence[2].Signal.Confidence; got != 0.9 {
		t.Errorf("resource confidence = %v, want strongest 0.9", got)
	}
	if got, want := evidenceIDs(edge.NegativeEvidence), []string{"origin-exposed"}; !reflect.DeepEqual(got, want) {
		t.Errorf("negative evidence = %v, want %v", got, want)
	}
	if got, want := evidenceIDs(edge.AmbiguousEvidence), []string{"generic-via"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ambiguous evidence = %v, want %v", got, want)
	}
}

func TestMatchExplainsMissingANDAndANYEvidence(t *testing.T) {
	t.Parallel()
	ruleSet := loadFixture(t)
	results, err := Match(ruleSet, []model.Signal{
		signal(model.SignalTypeResponseHeader, "Server", "Acme", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	edge := results[0]
	if edge.ConditionMatched || edge.MinimumEvidenceMet || edge.Candidate() {
		t.Fatalf("edge unexpectedly matched: %#v", edge)
	}
	if got, want := evidenceIDs(edge.PositiveEvidence), []string{"acme-server"}; !reflect.DeepEqual(got, want) {
		t.Errorf("partial positive evidence = %v, want %v", got, want)
	}
	if got, want := edge.MissingPositiveEvidence, []string{"acme-cookie", "acme-resource"}; !reflect.DeepEqual(got, want) {
		t.Errorf("missing evidence = %v, want %v", got, want)
	}
}

func TestMatchANYDoesNotReportUnselectedAlternativesMissing(t *testing.T) {
	t.Parallel()
	ruleSet := loadFixture(t)
	results, err := Match(ruleSet, []model.Signal{
		signal(model.SignalTypeResponseHeader, "Server", "Acme", 1),
		signal(model.SignalTypeCookie, "acme_session", "", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := results[0].MissingPositiveEvidence; len(got) != 0 {
		t.Errorf("missing evidence = %v, want none for satisfied any", got)
	}
}

func TestTextPatternOperations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pattern TextPattern
		value   string
		want    bool
	}{
		{"exact", *exact("value"), "value", true},
		{"exact mismatch", *exact("value"), "Value", false},
		{"contains insensitive", TextPattern{Contains: stringPointer("EDGE"), CaseInsensitive: true}, "acme edge", true},
		{"prefix", TextPattern{Prefix: stringPointer("https://")}, "https://example.test", true},
		{"suffix", TextPattern{Suffix: stringPointer(".js")}, "app.js", true},
		{"regex insensitive", TextPattern{Regex: stringPointer(`^acme-[0-9]+$`), CaseInsensitive: true}, "ACME-42", true},
		{"regex mismatch", TextPattern{Regex: stringPointer(`^acme-[0-9]+$`)}, "other-42", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.pattern.matches(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("matches(%q) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchRejectsInvalidSignals(t *testing.T) {
	t.Parallel()
	invalid := signal(model.SignalTypeResponseHeader, "Server", "Acme", 1)
	invalid.Source = ""
	_, err := Match(validRuleSet(), []model.Signal{invalid})
	if !errors.Is(err, ErrInvalidSignals) {
		t.Fatalf("Match() error = %v, want ErrInvalidSignals", err)
	}
}

func TestCachedSignalReusesCaseFoldedLargeField(t *testing.T) {
	largeValue := strings.Repeat("UPPERCASE", 1<<17)
	cached := cachedSignal{signal: signal(model.SignalTypePageContent, "body", largeValue, 1)}

	first := cached.field(signalFieldValue, true)
	if first != strings.ToLower(largeValue) || !cached.caseFoldedOK[signalFieldValue] {
		t.Fatal("case-folded value was not cached")
	}
	changed := false
	if got := testing.AllocsPerRun(100, func() {
		changed = changed || cached.field(signalFieldValue, true) != first
	}); got != 0 {
		t.Errorf("cached field allocations = %v, want 0", got)
	}
	if changed {
		t.Error("cached value changed")
	}
}

func loadFixture(t *testing.T) RuleSet {
	t.Helper()
	file, err := os.Open("testdata/valid-rules.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ruleSet, err := DecodeJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	return ruleSet
}

func signal(signalType model.SignalType, key, value string, confidence float64) model.Signal {
	return model.Signal{
		Type: signalType, Source: "fixture", Key: key, Value: value, Confidence: confidence,
	}
}

func evidenceIDs(evidence []EvidenceMatch) []string {
	ids := make([]string, 0, len(evidence))
	for _, match := range evidence {
		ids = append(ids, match.EvidenceID)
	}
	return ids
}
