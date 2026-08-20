package rules

import (
	"slices"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

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

func TestEvaluateRuleCoverage(t *testing.T) {
	t.Parallel()

	t.Run("observed supporting evidence with unknown decisive evidence is Unknown", func(t *testing.T) {
		t.Parallel()
		rule := Rule{
			ID: "test.rule", MinimumEvidence: 1, MinimumScore: 75,
		}
		cRes := ConditionCoverageResult{
			State:          CoverageStateUnknown,
			CanBeSatisfied: true,
			PotentialEvidence: []PotentialEvidence{
				{ID: "marker", Group: "static", Score: 30, IsUnknown: false},
				{ID: "script", Group: "static", Score: 75, IncompleteSources: []string{"browser_analyzer"}, IsUnknown: true},
			},
			IncompleteSources: []string{"browser_analyzer"},
		}
		state, incomplete := EvaluateRuleCoverage(rule, cRes, false, 0)
		if state != CoverageStateUnknown {
			t.Fatalf("state = %v, want CoverageStateUnknown", state)
		}
		if !slices.Equal(incomplete, []string{"browser_analyzer"}) {
			t.Fatalf("incomplete = %v, want [browser_analyzer]", incomplete)
		}
	})

	t.Run("counter-example: unknown evidence in same group cannot reach higher threshold", func(t *testing.T) {
		t.Parallel()
		// Observed 75 in group_a, unknown 75 in group_a, threshold 90
		rule := Rule{
			ID: "test.rule", MinimumEvidence: 1, MinimumScore: 90,
		}
		cRes := ConditionCoverageResult{
			State:          CoverageStateUnknown,
			CanBeSatisfied: true,
			PotentialEvidence: []PotentialEvidence{
				{ID: "marker_a", Group: "group_a", Score: 75, IsUnknown: false},
				{ID: "marker_b", Group: "group_a", Score: 75, IncompleteSources: []string{"browser_analyzer"}, IsUnknown: true},
			},
			IncompleteSources: []string{"browser_analyzer"},
		}
		state, incomplete := EvaluateRuleCoverage(rule, cRes, false, 0)
		if state != CoverageStateNotMatched {
			t.Fatalf("state = %v, want CoverageStateNotMatched", state)
		}
		if len(incomplete) != 0 {
			t.Fatalf("incomplete = %v, want empty on NotMatched", incomplete)
		}
	})

	t.Run("minimum_evidence 2 with one matched group and one unknown group is Unknown", func(t *testing.T) {
		t.Parallel()
		rule := Rule{
			ID: "test.rule", MinimumEvidence: 2, MinimumScore: 100,
		}
		cRes := ConditionCoverageResult{
			State:          CoverageStateUnknown,
			CanBeSatisfied: true,
			PotentialEvidence: []PotentialEvidence{
				{ID: "g1_e", Group: "g1", Score: 50, IsUnknown: false},
				{ID: "g2_e", Group: "g2", Score: 50, IncompleteSources: []string{"browser_analyzer"}, IsUnknown: true},
			},
			IncompleteSources: []string{"browser_analyzer"},
		}
		state, incomplete := EvaluateRuleCoverage(rule, cRes, false, 0)
		if state != CoverageStateUnknown {
			t.Fatalf("state = %v, want CoverageStateUnknown", state)
		}
		if !slices.Equal(incomplete, []string{"browser_analyzer"}) {
			t.Fatalf("incomplete = %v, want [browser_analyzer]", incomplete)
		}
	})

	t.Run("minimum_evidence 2 with all evidence in one group is NotMatched", func(t *testing.T) {
		t.Parallel()
		rule := Rule{
			ID: "test.rule", MinimumEvidence: 2, MinimumScore: 50,
		}
		cRes := ConditionCoverageResult{
			State:          CoverageStateUnknown,
			CanBeSatisfied: true,
			PotentialEvidence: []PotentialEvidence{
				{ID: "g1_e1", Group: "g1", Score: 75, IsUnknown: false},
				{ID: "g1_e2", Group: "g1", Score: 75, IncompleteSources: []string{"browser_analyzer"}, IsUnknown: true},
			},
			IncompleteSources: []string{"browser_analyzer"},
		}
		state, incomplete := EvaluateRuleCoverage(rule, cRes, false, 0)
		if state != CoverageStateNotMatched {
			t.Fatalf("state = %v, want CoverageStateNotMatched", state)
		}
		if len(incomplete) != 0 {
			t.Fatalf("incomplete = %v, want empty on NotMatched", incomplete)
		}
	})
}
