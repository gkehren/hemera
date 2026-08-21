package rules

import (
	"fmt"
	"sort"

	"github.com/gkehren/hemera/pkg/model"
)

// defaultCapableSources maps normalized signal types to the standard observation
// sources capable of producing them.
var defaultCapableSources = map[model.SignalType][]string{
	model.SignalTypeResponseHeader:  {"http_analyzer"},
	model.SignalTypeCookie:          {"browser_analyzer", "http_analyzer"},
	model.SignalTypeScriptURL:       {"browser_analyzer", "http_analyzer"},
	model.SignalTypeNetworkRequest:  {"browser_analyzer"},
	model.SignalTypeNetworkResponse: {"browser_analyzer", "http_analyzer"},
	model.SignalTypeDOMSelector:     {"browser_analyzer"},
	model.SignalTypeIframeURL:       {"browser_analyzer", "http_analyzer"},
	model.SignalTypeJSGlobal:        {"browser_analyzer"},
	model.SignalTypeDNSRecord:       {"dns_tls_analyzer"},
	model.SignalTypeTLSProperty:     {"dns_tls_analyzer"},
	model.SignalTypeRedirect:        {"http_analyzer"},
	model.SignalTypePageContent:     {"browser_analyzer", "http_analyzer"},
	model.SignalTypeResourceHost:    {"browser_analyzer", "http_analyzer"},
}

// CapableSources returns the observation sources that can produce evidence matching
// the given evidence predicate. If the predicate specifies an exact or patterned
// source constraint, the returned sources are filtered accordingly.
func CapableSources(evidence Evidence) []string {
	if evidence.Source != nil && evidence.Source.Exact != nil {
		return []string{*evidence.Source.Exact}
	}
	candidates, ok := defaultCapableSources[evidence.Type]
	if !ok {
		if evidence.Source != nil && evidence.Source.Exact != nil {
			return []string{*evidence.Source.Exact}
		}
		return nil
	}
	if evidence.Source == nil {
		result := make([]string, len(candidates))
		copy(result, candidates)
		sort.Strings(result)
		return result
	}
	var filtered []string
	for _, candidate := range candidates {
		if matched, err := evidence.Source.matches(candidate); err == nil && matched {
			filtered = append(filtered, candidate)
		}
	}
	sort.Strings(filtered)
	return filtered
}

// CoverageState represents the tri-state outcome of condition evaluation under
// incomplete analyzer observations.
type CoverageState int

const (
	// CoverageStateNotMatched indicates the condition or rule was conclusively evaluated
	// as negative by complete observation channels.
	CoverageStateNotMatched CoverageState = iota
	// CoverageStateMatched indicates the condition or rule was satisfied by observed evidence.
	CoverageStateMatched
	// CoverageStateUnknown indicates the condition or rule could not be conclusively
	// evaluated as negative because one or more capable observation channels were incomplete.
	CoverageStateUnknown
)

// PotentialEvidence records an actual or potential evidence item from a condition branch.
type PotentialEvidence struct {
	ID                string
	Group             string
	Score             float64
	IncompleteSources []string
	IsUnknown         bool
}

// ConditionCoverageResult describes the tri-state result and potential evidence of a condition.
type ConditionCoverageResult struct {
	State             CoverageState
	CanBeSatisfied    bool
	PotentialEvidence []PotentialEvidence
	IncompleteSources []string
	RequiredSources   []string
}

// CapabilityCompleter reports whether one observation source completely
// observed a normalized signal capability. It operates only on stable source
// identities and shared signal types so rule evaluation stays independent of
// analyzer implementation packages.
//
// A source whose channel did not run to completion reports false for its
// capabilities; absence of matching evidence for such a capability is then
// inconclusive rather than conclusive.
type CapabilityCompleter func(source string, signalType model.SignalType) bool

// EvaluateConditionCoverage evaluates a condition against normalized signals and per-capability
// completion state, returning a tri-state result with potential evidence and required sources.
func EvaluateConditionCoverage(
	condition Condition,
	signals []model.Signal,
	complete CapabilityCompleter,
) (ConditionCoverageResult, error) {
	cached := make([]cachedSignal, len(signals))
	for i, s := range signals {
		cached[i].signal = s
	}
	return evaluateConditionCoverageCached(condition, cached, complete)
}

func evaluateConditionCoverageCached(
	condition Condition,
	signals []cachedSignal,
	complete CapabilityCompleter,
) (ConditionCoverageResult, error) {
	if condition.Signal != nil {
		evidence := *condition.Signal
		capable := CapableSources(evidence)
		match, ok, err := strongestMatch(evidence, signals)
		if err != nil {
			return ConditionCoverageResult{}, err
		}
		if ok {
			score := evidence.Weight * match.Signal.Confidence
			return ConditionCoverageResult{
				State:          CoverageStateMatched,
				CanBeSatisfied: true,
				PotentialEvidence: []PotentialEvidence{{
					ID:        evidence.ID,
					Group:     evidence.Group,
					Score:     score,
					IsUnknown: false,
				}},
				RequiredSources: capable,
			}, nil
		}
		incomplete := make([]string, 0, len(capable))
		for _, src := range capable {
			if !complete(src, evidence.Type) {
				incomplete = append(incomplete, src)
			}
		}
		if len(incomplete) == 0 {
			return ConditionCoverageResult{
				State:           CoverageStateNotMatched,
				CanBeSatisfied:  false,
				RequiredSources: capable,
			}, nil
		}
		dedupIncomplete := deduplicateSorted(incomplete)
		return ConditionCoverageResult{
			State:          CoverageStateUnknown,
			CanBeSatisfied: true,
			PotentialEvidence: []PotentialEvidence{{
				ID:                evidence.ID,
				Group:             evidence.Group,
				Score:             evidence.Weight,
				IncompleteSources: dedupIncomplete,
				IsUnknown:         true,
			}},
			IncompleteSources: dedupIncomplete,
			RequiredSources:   capable,
		}, nil
	}

	children := condition.All
	all := true
	if condition.Any != nil {
		children = condition.Any
		all = false
	}

	if all {
		var potentialEvidence []PotentialEvidence
		var incompleteSources []string
		var requiredSources []string
		hasUnknown := false
		for _, child := range children {
			childRes, err := evaluateConditionCoverageCached(child, signals, complete)
			if err != nil {
				return ConditionCoverageResult{}, err
			}
			requiredSources = append(requiredSources, childRes.RequiredSources...)
			if !childRes.CanBeSatisfied {
				// Short-circuit: false AND anything == false
				return ConditionCoverageResult{
					State:           CoverageStateNotMatched,
					CanBeSatisfied:  false,
					RequiredSources: deduplicateSorted(requiredSources),
				}, nil
			}
			if childRes.State == CoverageStateUnknown {
				hasUnknown = true
				incompleteSources = append(incompleteSources, childRes.IncompleteSources...)
			}
			potentialEvidence = append(potentialEvidence, childRes.PotentialEvidence...)
		}
		state := CoverageStateMatched
		if hasUnknown {
			state = CoverageStateUnknown
		}
		return ConditionCoverageResult{
			State:             state,
			CanBeSatisfied:    true,
			PotentialEvidence: potentialEvidence,
			IncompleteSources: deduplicateSorted(incompleteSources),
			RequiredSources:   deduplicateSorted(requiredSources),
		}, nil
	}

	// Any (OR)
	var potentialEvidence []PotentialEvidence
	var incompleteSources []string
	var requiredSources []string
	hasMatched := false
	hasUnknown := false
	atLeastOneSatisfiable := false

	for _, child := range children {
		childRes, err := evaluateConditionCoverageCached(child, signals, complete)
		if err != nil {
			return ConditionCoverageResult{}, err
		}
		requiredSources = append(requiredSources, childRes.RequiredSources...)
		if childRes.CanBeSatisfied {
			atLeastOneSatisfiable = true
			if childRes.State == CoverageStateMatched {
				hasMatched = true
			}
			if childRes.State == CoverageStateUnknown {
				hasUnknown = true
			}
			potentialEvidence = append(potentialEvidence, childRes.PotentialEvidence...)
			incompleteSources = append(incompleteSources, childRes.IncompleteSources...)
		}
	}

	if !atLeastOneSatisfiable {
		return ConditionCoverageResult{
			State:           CoverageStateNotMatched,
			CanBeSatisfied:  false,
			RequiredSources: deduplicateSorted(requiredSources),
		}, nil
	}

	state := CoverageStateMatched
	if hasUnknown || !hasMatched {
		state = CoverageStateUnknown
	}
	return ConditionCoverageResult{
		State:             state,
		CanBeSatisfied:    true,
		PotentialEvidence: potentialEvidence,
		IncompleteSources: deduplicateSorted(incompleteSources),
		RequiredSources:   deduplicateSorted(requiredSources),
	}, nil
}

// EvaluateRuleCoverage determines the coverage state and incomplete sources for a rule
// taking into account the condition tree, correlation groups, minimum evidence, and minimum score.
func EvaluateRuleCoverage(
	rule Rule,
	cRes ConditionCoverageResult,
	detected bool,
	observedPenalties float64,
) (CoverageState, []string) {
	if detected {
		return CoverageStateMatched, nil
	}
	if !cRes.CanBeSatisfied {
		return CoverageStateNotMatched, nil
	}

	type groupSummary struct {
		maxScore          float64
		incompleteSources []string
	}
	groups := make(map[string]*groupSummary)
	for i, pe := range cRes.PotentialEvidence {
		groupKey := pe.Group
		if groupKey == "" {
			groupKey = fmt.Sprintf("__independent_%d", i)
		}
		g, ok := groups[groupKey]
		if !ok {
			g = &groupSummary{}
			groups[groupKey] = g
		}
		if pe.Score > g.maxScore {
			g.maxScore = pe.Score
		}
		if pe.IsUnknown {
			g.incompleteSources = append(g.incompleteSources, pe.IncompleteSources...)
		}
	}

	upperBoundScore := 0.0
	var allIncomplete []string
	for _, g := range groups {
		upperBoundScore += g.maxScore
		allIncomplete = append(allIncomplete, g.incompleteSources...)
	}
	upperBoundScore -= observedPenalties
	if upperBoundScore < 0 {
		upperBoundScore = 0
	}
	if upperBoundScore > 100 {
		upperBoundScore = 100
	}
	upperBoundGroups := len(groups)

	canReachThreshold := (upperBoundScore >= rule.MinimumScore) && (upperBoundGroups >= rule.MinimumEvidence)
	if !canReachThreshold {
		return CoverageStateNotMatched, nil
	}

	return CoverageStateUnknown, deduplicateSorted(allIncomplete)
}

func deduplicateSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	sort.Strings(items)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if len(result) == 0 || result[len(result)-1] != item {
			result = append(result, item)
		}
	}
	return result
}
