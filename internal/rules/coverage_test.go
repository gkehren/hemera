package rules

import (
	"reflect"
	"slices"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

func TestRequiredSourcesFollowsConditionBranchesAndDependencies(t *testing.T) {
	t.Parallel()
	httpSource := "http_analyzer"
	browserSource := "browser_analyzer"
	ruleSet := RuleSet{SchemaVersion: CurrentSchemaVersion, Rules: []Rule{
		{
			ID: "dependency", Match: Condition{Signal: &Evidence{
				Type: model.SignalTypeCookie, Source: &TextPattern{Exact: &browserSource},
			}},
		},
		{
			ID: "fixture", Requires: []string{"dependency"},
			Match: Condition{All: []Condition{
				{Signal: &Evidence{Type: model.SignalTypeScriptURL, Source: &TextPattern{Exact: &httpSource}}},
				{Any: []Condition{
					{Signal: &Evidence{Type: model.SignalTypeCookie, Source: &TextPattern{Exact: &browserSource}}},
					{Signal: &Evidence{Type: model.SignalTypeCookie, Source: &TextPattern{Exact: &httpSource}}},
				}},
			}},
		},
	}}
	got := RequiredSources(ruleSet.Rules[1], ruleSet)
	want := []string{"browser_analyzer", "http_analyzer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredSources() = %#v, want %#v", got, want)
	}

	withoutDependency := ruleSet.Rules[1]
	withoutDependency.Requires = nil
	if got := RequiredSources(withoutDependency, ruleSet); !reflect.DeepEqual(got, []string{"http_analyzer"}) {
		t.Fatalf("alternative source intersection = %#v, want HTTP only", got)
	}
}

func TestCapableSources(t *testing.T) {
	t.Parallel()
	customSource := "custom_analyzer"
	tests := []struct {
		name     string
		evidence Evidence
		want     []string
	}{
		{
			name:     "exact source specified",
			evidence: Evidence{Type: model.SignalTypeScriptURL, Source: &TextPattern{Exact: &customSource}},
			want:     []string{"custom_analyzer"},
		},
		{
			name:     "unconstrained response header",
			evidence: Evidence{Type: model.SignalTypeResponseHeader},
			want:     []string{"http_analyzer"},
		},
		{
			name:     "unconstrained script URL",
			evidence: Evidence{Type: model.SignalTypeScriptURL},
			want:     []string{"browser_analyzer", "http_analyzer"},
		},
		{
			name:     "unconstrained cookie",
			evidence: Evidence{Type: model.SignalTypeCookie},
			want:     []string{"browser_analyzer", "http_analyzer"},
		},
		{
			name:     "unconstrained DOM selector",
			evidence: Evidence{Type: model.SignalTypeDOMSelector},
			want:     []string{"browser_analyzer"},
		},
		{
			name:     "unconstrained DNS record",
			evidence: Evidence{Type: model.SignalTypeDNSRecord},
			want:     []string{"dns_tls_analyzer"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CapableSources(tt.evidence)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("CapableSources() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestEvaluateConditionCoverage(t *testing.T) {
	t.Parallel()
	scriptKey := "https://example.com/widget.js"
	headerKey := "x-test-header"
	domKey := "#captcha-container"

	scriptEvidence := &Evidence{
		ID: "script", Group: "script", Type: model.SignalTypeScriptURL,
		Key: &TextPattern{Exact: &scriptKey}, Weight: 75,
	}
	headerEvidence := &Evidence{
		ID: "header", Group: "header", Type: model.SignalTypeResponseHeader,
		Key: &TextPattern{Exact: &headerKey}, Weight: 75,
	}
	domEvidence := &Evidence{
		ID: "dom", Group: "dom", Type: model.SignalTypeDOMSelector,
		Key: &TextPattern{Exact: &domKey}, Weight: 75,
	}

	signalsWithScript := []model.Signal{{
		Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: scriptKey, Confidence: 1,
	}}

	allComplete := map[string]bool{"http_analyzer": true, "browser_analyzer": true, "dns_tls_analyzer": true}
	httpOnlyComplete := map[string]bool{"http_analyzer": true, "browser_analyzer": false, "dns_tls_analyzer": true}

	t.Run("single evidence matched", func(t *testing.T) {
		t.Parallel()
		res, err := EvaluateConditionCoverage(Condition{Signal: scriptEvidence}, signalsWithScript, httpOnlyComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateMatched {
			t.Fatalf("State = %v, want CoverageStateMatched", res.State)
		}
	})

	t.Run("single evidence absent with complete sources", func(t *testing.T) {
		t.Parallel()
		res, err := EvaluateConditionCoverage(Condition{Signal: scriptEvidence}, nil, allComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateNotMatched {
			t.Fatalf("State = %v, want CoverageStateNotMatched", res.State)
		}
	})

	t.Run("single evidence absent with incomplete sources", func(t *testing.T) {
		t.Parallel()
		res, err := EvaluateConditionCoverage(Condition{Signal: scriptEvidence}, nil, httpOnlyComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateUnknown {
			t.Fatalf("State = %v, want CoverageStateUnknown", res.State)
		}
		if !slices.Equal(res.IncompleteSources, []string{"browser_analyzer"}) {
			t.Fatalf("IncompleteSources = %#v, want [browser_analyzer]", res.IncompleteSources)
		}
	})

	t.Run("All short-circuits to NotMatched when one branch is conclusively absent", func(t *testing.T) {
		t.Parallel()
		// All: [header (HTTP-only), dom (Browser-only)]
		// HTTP is complete (header absent -> NotMatched). Browser is failed (dom -> Unknown).
		// Conjunction is conclusively NotMatched!
		cond := Condition{All: []Condition{
			{Signal: headerEvidence},
			{Signal: domEvidence},
		}}
		res, err := EvaluateConditionCoverage(cond, nil, httpOnlyComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateNotMatched {
			t.Fatalf("State = %v, want CoverageStateNotMatched", res.State)
		}
		if len(res.IncompleteSources) != 0 {
			t.Fatalf("IncompleteSources = %#v, want empty on conclusive NotMatched", res.IncompleteSources)
		}
	})

	t.Run("Any evaluates to Unknown when one alternative is absent and another is unknown", func(t *testing.T) {
		t.Parallel()
		// Any: [header (HTTP-only), dom (Browser-only)]
		// HTTP is complete (header absent -> NotMatched). Browser is failed (dom -> Unknown).
		// Disjunction is Unknown!
		cond := Condition{Any: []Condition{
			{Signal: headerEvidence},
			{Signal: domEvidence},
		}}
		res, err := EvaluateConditionCoverage(cond, nil, httpOnlyComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateUnknown {
			t.Fatalf("State = %v, want CoverageStateUnknown", res.State)
		}
		if !slices.Equal(res.IncompleteSources, []string{"browser_analyzer"}) {
			t.Fatalf("IncompleteSources = %#v, want [browser_analyzer]", res.IncompleteSources)
		}
	})

	t.Run("Any evaluates to NotMatched when all alternatives are conclusively absent", func(t *testing.T) {
		t.Parallel()
		cond := Condition{Any: []Condition{
			{Signal: headerEvidence},
			{Signal: domEvidence},
		}}
		res, err := EvaluateConditionCoverage(cond, nil, allComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateNotMatched {
			t.Fatalf("State = %v, want CoverageStateNotMatched", res.State)
		}
	})
}
