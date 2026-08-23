package rules

import (
	"slices"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

func TestCapableSources(t *testing.T) {
	t.Parallel()
	registry, err := DefaultCapabilityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	customSource := "custom_analyzer"
	browserSource := "browser_analyzer"
	uppercaseHTTPSource := "HTTP_ANALYZER"
	tests := []struct {
		name     string
		evidence Evidence
		want     []string
	}{
		{
			name:     "unsupported exact source omitted",
			evidence: Evidence{Type: model.SignalTypeScriptURL, Source: &TextPattern{Exact: &customSource}},
			want:     nil,
		},
		{
			name:     "supported exact source",
			evidence: Evidence{Type: model.SignalTypeScriptURL, Source: &TextPattern{Exact: &browserSource}},
			want:     []string{"browser_analyzer"},
		},
		{
			name: "case insensitive exact source",
			evidence: Evidence{Type: model.SignalTypeResponseHeader, Source: &TextPattern{
				Exact: &uppercaseHTTPSource, CaseInsensitive: true,
			}},
			want: []string{"http_analyzer"},
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
			name:     "unconstrained unsupported DOM selector",
			evidence: Evidence{Type: model.SignalTypeDOMSelector},
			want:     nil,
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
			got := registry.CapableSources(tt.evidence)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("CapableSources() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestEvaluateConditionCoverage(t *testing.T) {
	t.Parallel()
	capabilities, err := DefaultCapabilityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	scriptKey := "https://example.com/widget.js"
	headerKey := "x-test-header"
	requestKey := "GET"

	scriptEvidence := &Evidence{
		ID: "script", Group: "script", Type: model.SignalTypeScriptURL,
		Key: &TextPattern{Exact: &scriptKey}, Weight: 75,
	}
	headerEvidence := &Evidence{
		ID: "header", Group: "header", Type: model.SignalTypeResponseHeader,
		Key: &TextPattern{Exact: &headerKey}, Weight: 75,
	}
	browserEvidence := &Evidence{
		ID: "request", Group: "request", Type: model.SignalTypeNetworkRequest,
		Key: &TextPattern{Exact: &requestKey}, Weight: 75,
	}

	signalsWithScript := []model.Signal{{
		Type: model.SignalTypeScriptURL, Source: "http_analyzer", Key: scriptKey, Confidence: 1,
	}}

	allComplete := CapabilityCompleter(func(string, model.SignalType) bool { return true })
	httpOnlyComplete := CapabilityCompleter(func(source string, _ model.SignalType) bool {
		return source != "browser_analyzer"
	})

	t.Run("single evidence matched", func(t *testing.T) {
		t.Parallel()
		res, err := EvaluateConditionCoverage(Condition{Signal: scriptEvidence}, signalsWithScript, capabilities, httpOnlyComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateMatched {
			t.Fatalf("State = %v, want CoverageStateMatched", res.State)
		}
	})

	t.Run("single evidence absent with complete sources", func(t *testing.T) {
		t.Parallel()
		res, err := EvaluateConditionCoverage(Condition{Signal: scriptEvidence}, nil, capabilities, allComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateNotMatched {
			t.Fatalf("State = %v, want CoverageStateNotMatched", res.State)
		}
	})

	t.Run("single evidence absent with incomplete sources", func(t *testing.T) {
		t.Parallel()
		res, err := EvaluateConditionCoverage(Condition{Signal: scriptEvidence}, nil, capabilities, httpOnlyComplete)
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
			{Signal: browserEvidence},
		}}
		res, err := EvaluateConditionCoverage(cond, nil, capabilities, httpOnlyComplete)
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
			{Signal: browserEvidence},
		}}
		res, err := EvaluateConditionCoverage(cond, nil, capabilities, httpOnlyComplete)
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
			{Signal: browserEvidence},
		}}
		res, err := EvaluateConditionCoverage(cond, nil, capabilities, allComplete)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateNotMatched {
			t.Fatalf("State = %v, want CoverageStateNotMatched", res.State)
		}
	})

	t.Run("capability completeness is scoped to the predicate signal type", func(t *testing.T) {
		t.Parallel()
		// The browser analyzer completed its page_content channel but its
		// script channel was truncated. A page_content predicate is then
		// conclusively negative while a script predicate stays unknown.
		contentKey := "challenge-marker"
		contentEvidence := &Evidence{
			ID: "content", Group: "content", Type: model.SignalTypePageContent,
			Value: &TextPattern{Contains: &contentKey}, Weight: 75,
		}
		completer := CapabilityCompleter(func(source string, signalType model.SignalType) bool {
			if source != "browser_analyzer" {
				return true
			}
			return signalType != model.SignalTypeScriptURL
		})
		res, err := EvaluateConditionCoverage(Condition{Signal: contentEvidence}, nil, capabilities, completer)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateNotMatched {
			t.Fatalf("page_content State = %v, want CoverageStateNotMatched", res.State)
		}
		scriptRes, err := EvaluateConditionCoverage(Condition{Signal: scriptEvidence}, nil, capabilities, completer)
		if err != nil {
			t.Fatal(err)
		}
		if scriptRes.State != CoverageStateUnknown {
			t.Fatalf("script_url State = %v, want CoverageStateUnknown", scriptRes.State)
		}
	})

	t.Run("explicit source constraint consults that source's capability", func(t *testing.T) {
		t.Parallel()
		browserSource := "browser_analyzer"
		browserScriptEvidence := &Evidence{
			ID: "browser-script", Group: "script", Type: model.SignalTypeScriptURL,
			Source: &TextPattern{Exact: &browserSource},
			Key:    &TextPattern{Exact: &scriptKey}, Weight: 75,
		}
		completer := CapabilityCompleter(func(source string, signalType model.SignalType) bool {
			return source == "http_analyzer" && signalType == model.SignalTypeScriptURL
		})
		res, err := EvaluateConditionCoverage(Condition{Signal: browserScriptEvidence}, nil, capabilities, completer)
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

	t.Run("incomplete unrelated capability does not affect other predicates", func(t *testing.T) {
		t.Parallel()
		// HTTP page_content was truncated, but this header predicate does not
		// depend on that capability and must stay conclusive.
		completer := CapabilityCompleter(func(source string, signalType model.SignalType) bool {
			return !(source == "http_analyzer" && signalType == model.SignalTypePageContent)
		})
		res, err := EvaluateConditionCoverage(Condition{Signal: headerEvidence}, nil, capabilities, completer)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != CoverageStateNotMatched {
			t.Fatalf("State = %v, want CoverageStateNotMatched", res.State)
		}
		if len(res.IncompleteSources) != 0 {
			t.Fatalf("IncompleteSources = %#v, want empty", res.IncompleteSources)
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
