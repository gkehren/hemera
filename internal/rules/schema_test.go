package rules

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

func TestDecodeJSONFixture(t *testing.T) {
	t.Parallel()
	file, err := os.Open("testdata/valid-rules.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	ruleSet, err := DecodeJSON(file)
	if err != nil {
		t.Fatal(err)
	}
	if ruleSet.SchemaVersion != CurrentSchemaVersion || len(ruleSet.Rules) != 3 {
		t.Fatalf("decoded rule set = %#v", ruleSet)
	}
	if got := ruleSet.Rules[2].Requires; len(got) != 1 || got[0] != "acme.edge" {
		t.Errorf("product dependencies = %v", got)
	}
	if got := ruleSet.Rules[0].Match.All[0].Signal.Group; got != "response_headers" {
		t.Errorf("evidence group = %q, want response_headers", got)
	}
}

func TestDocumentedExampleIsValid(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../docs/detector-rules.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	const opening = "```json\n"
	start := strings.Index(text, opening)
	if start == -1 {
		t.Fatal("documented JSON example is missing")
	}
	start += len(opening)
	end := strings.Index(text[start:], "\n```")
	if end == -1 {
		t.Fatal("documented JSON example is unterminated")
	}
	if _, err := DecodeJSON(strings.NewReader(text[start : start+end])); err != nil {
		t.Fatalf("documented JSON example is invalid: %v", err)
	}
}

func TestDecodeJSONRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		err  error
	}{
		{"malformed", `{`, ErrInvalidSchema},
		{"unknown field", `{"schema_version":1,"rules":[],"extra":true}`, ErrInvalidSchema},
		{"unknown nested field", `{"schema_version":1,"rules":[{"unknown":true}]}`, ErrInvalidSchema},
		{"duplicate field", `{"schema_version":1,"schema_version":1,"rules":[]}`, ErrInvalidSchema},
		{"multiple values", `{"schema_version":1,"rules":[]} {}`, ErrInvalidSchema},
		{"unsupported version", `{"schema_version":3,"rules":[]}`, ErrInvalidSchema},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeJSON(strings.NewReader(tt.data))
			if !errors.Is(err, tt.err) {
				t.Fatalf("DecodeJSON() error = %v, want %v", err, tt.err)
			}
		})
	}
}

func TestDecodeJSONBoundsDocumentSize(t *testing.T) {
	t.Parallel()
	_, err := DecodeJSON(strings.NewReader(strings.Repeat(" ", MaxDocumentBytes+1)))
	if !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("DecodeJSON() error = %v, want ErrDocumentTooLarge", err)
	}
}

func TestRuleSetValidateRejectsInvalidSchema(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*RuleSet)
	}{
		{"schema version", func(s *RuleSet) { s.SchemaVersion = 3 }},
		{"no rules", func(s *RuleSet) { s.Rules = nil }},
		{"duplicate rule id", func(s *RuleSet) { s.Rules = append(s.Rules, s.Rules[0]) }},
		{"invalid rule id", func(s *RuleSet) { s.Rules[0].ID = "Bad ID" }},
		{"missing name", func(s *RuleSet) { s.Rules[0].Name = " " }},
		{"invalid category", func(s *RuleSet) { s.Rules[0].Category = "unknown" }},
		{"missing vendor", func(s *RuleSet) { s.Rules[0].Vendor = "" }},
		{"minimum evidence zero", func(s *RuleSet) { s.Rules[0].MinimumEvidence = 0 }},
		{"minimum evidence too high", func(s *RuleSet) { s.Rules[0].MinimumEvidence = 2 }},
		{"minimum score zero", func(s *RuleSet) { s.Rules[0].MinimumScore = 0 }},
		{"minimum score below detection range", func(s *RuleSet) { s.Rules[0].MinimumScore = 24 }},
		{"minimum score NaN", func(s *RuleSet) { s.Rules[0].MinimumScore = math.NaN() }},
		{"empty condition", func(s *RuleSet) { s.Rules[0].Match = Condition{} }},
		{"multiple condition kinds", func(s *RuleSet) { s.Rules[0].Match.All = []Condition{s.Rules[0].Match} }},
		{"empty all", func(s *RuleSet) { s.Rules[0].Match = Condition{All: []Condition{}} }},
		{"condition too deep", func(s *RuleSet) {
			condition := s.Rules[0].Match
			for range maxConditionDepth {
				condition = Condition{All: []Condition{condition}}
			}
			s.Rules[0].Match = condition
		}},
		{"invalid evidence id", func(s *RuleSet) { s.Rules[0].Match.Signal.ID = "Bad ID" }},
		{"invalid evidence group", func(s *RuleSet) { s.Rules[0].Match.Signal.Group = "Bad Group" }},
		{"invalid signal type", func(s *RuleSet) { s.Rules[0].Match.Signal.Type = "unknown" }},
		{"zero weight", func(s *RuleSet) { s.Rules[0].Match.Signal.Weight = 0 }},
		{"NaN weight", func(s *RuleSet) { s.Rules[0].Match.Signal.Weight = math.NaN() }},
		{"no signal field", func(s *RuleSet) { s.Rules[0].Match.Signal.Key = nil }},
		{"empty pattern", func(s *RuleSet) { s.Rules[0].Match.Signal.Key = exact("") }},
		{"multiple pattern operations", func(s *RuleSet) {
			s.Rules[0].Match.Signal.Key = &TextPattern{Exact: stringPointer("Server"), Contains: stringPointer("Acme")}
		}},
		{"invalid regex", func(s *RuleSet) { s.Rules[0].Match.Signal.Key = regex("[") }},
		{"duplicate evidence id", func(s *RuleSet) {
			s.Rules[0].NegativeEvidence = []Evidence{*s.Rules[0].Match.Signal}
		}},
		{"group on negative evidence", func(s *RuleSet) {
			evidence := *s.Rules[0].Match.Signal
			evidence.ID = "negative"
			evidence.Group = "headers"
			s.Rules[0].NegativeEvidence = []Evidence{evidence}
		}},
		{"unknown dependency", func(s *RuleSet) { s.Rules[0].Requires = []string{"missing"} }},
		{"self dependency", func(s *RuleSet) { s.Rules[0].Requires = []string{s.Rules[0].ID} }},
		{"duplicate dependency", func(s *RuleSet) {
			s.Rules = append(s.Rules, secondRule("dependency"))
			s.Rules[0].Requires = []string{"dependency", "dependency"}
		}},
		{"dependency cycle", func(s *RuleSet) {
			s.Rules = append(s.Rules, secondRule("dependency"))
			s.Rules[0].Requires = []string{"dependency"}
			s.Rules[1].Requires = []string{s.Rules[0].ID}
		}},
		{"unknown conflict", func(s *RuleSet) {
			s.Rules[0].Conflicts = []Conflict{{RuleID: "missing", Penalty: 10}}
		}},
		{"self conflict", func(s *RuleSet) {
			s.Rules[0].Conflicts = []Conflict{{RuleID: s.Rules[0].ID, Penalty: 10}}
		}},
		{"zero conflict penalty", func(s *RuleSet) {
			s.Rules = append(s.Rules, secondRule("other"))
			s.Rules[0].Conflicts = []Conflict{{RuleID: "other", Penalty: 0}}
		}},
		{"duplicate conflict", func(s *RuleSet) {
			s.Rules = append(s.Rules, secondRule("other"))
			s.Rules[0].Conflicts = []Conflict{{RuleID: "other", Penalty: 10}, {RuleID: "other", Penalty: 20}}
		}},
		{"dependency conflict contradiction", func(s *RuleSet) {
			s.Rules = append(s.Rules, secondRule("other"))
			s.Rules[0].Requires = []string{"other"}
			s.Rules[0].Conflicts = []Conflict{{RuleID: "other", Penalty: 10}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ruleSet := validRuleSet()
			tt.change(&ruleSet)
			if err := ruleSet.Validate(); !errors.Is(err, ErrInvalidSchema) {
				t.Fatalf("Validate() error = %v, want ErrInvalidSchema", err)
			}
		})
	}
}

func TestRuleSetValidatePreservesStrictV1Rules(t *testing.T) {
	t.Parallel()
	ruleSet := validRuleSet()
	ruleSet.SchemaVersion = schemaVersionV1
	data, err := json.Marshal(ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeJSON(strings.NewReader(string(data))); err != nil {
		t.Fatalf("DecodeJSON() rejected a V1 rule: %v", err)
	}

	ruleSet.Rules[0].Match.Signal.Group = "response_headers"
	data, err = json.Marshal(ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeJSON(strings.NewReader(string(data))); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("DecodeJSON() V1 group error = %v, want ErrInvalidSchema", err)
	}
}

func TestCategoryValid(t *testing.T) {
	t.Parallel()
	for _, category := range []Category{
		CategoryCDNReverseProxy, CategoryWAF, CategoryBotManagement,
		CategoryCAPTCHAChallenge, CategoryClientFingerprinting, CategoryThirdPartySecurity,
	} {
		if !category.Valid() {
			t.Errorf("Category(%q).Valid() = false", category)
		}
	}
	if Category("unknown").Valid() {
		t.Error("unknown category is valid")
	}
}

func validRuleSet() RuleSet {
	return RuleSet{SchemaVersion: CurrentSchemaVersion, Rules: []Rule{{
		ID: "acme.edge", Name: "Acme Edge", Category: CategoryCDNReverseProxy, Vendor: "Acme",
		MinimumEvidence: 1, MinimumScore: 50,
		Match: Condition{Signal: &Evidence{
			ID: "server", Type: model.SignalTypeResponseHeader, Key: exact("Server"), Weight: 60,
		}},
	}}}
}

func secondRule(id string) Rule {
	rule := validRuleSet().Rules[0]
	rule.ID = id
	rule.Name = id
	rule.Match.Signal.ID = id + "-evidence"
	return rule
}

func stringPointer(value string) *string {
	return &value
}

func exact(value string) *TextPattern {
	return &TextPattern{Exact: stringPointer(value)}
}

func regex(value string) *TextPattern {
	return &TextPattern{Regex: stringPointer(value)}
}
