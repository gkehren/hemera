package rules

import (
	"sort"

	"github.com/gkehren/hemera/pkg/model"
)

// DefaultCapableSources maps normalized signal types to the standard observation
// sources capable of producing them.
var DefaultCapableSources = map[model.SignalType][]string{
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
	candidates, ok := DefaultCapableSources[evidence.Type]
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
	// CoverageStateNotMatched indicates the condition was conclusively evaluated
	// as negative by complete observation channels.
	CoverageStateNotMatched CoverageState = iota
	// CoverageStateMatched indicates the condition was satisfied by observed evidence.
	CoverageStateMatched
	// CoverageStateUnknown indicates the condition could not be conclusively
	// evaluated as negative because one or more capable observation channels were incomplete.
	CoverageStateUnknown
)

// ConditionCoverageResult describes the tri-state result of evaluating a condition.
type ConditionCoverageResult struct {
	State             CoverageState
	MatchedEvidence   []EvidenceMatch
	IncompleteSources []string
	RequiredSources   []string
}

// EvaluateConditionCoverage evaluates a condition against normalized signals and complete
// source statuses, returning a tri-state result with incomplete and required sources.
func EvaluateConditionCoverage(
	condition Condition,
	signals []model.Signal,
	completeSources map[string]bool,
) (ConditionCoverageResult, error) {
	cached := make([]cachedSignal, len(signals))
	for i, s := range signals {
		cached[i].signal = s
	}
	return evaluateConditionCoverageCached(condition, cached, completeSources)
}

func evaluateConditionCoverageCached(
	condition Condition,
	signals []cachedSignal,
	completeSources map[string]bool,
) (ConditionCoverageResult, error) {
	if condition.Signal != nil {
		evidence := *condition.Signal
		capable := CapableSources(evidence)
		match, ok, err := strongestMatch(evidence, signals)
		if err != nil {
			return ConditionCoverageResult{}, err
		}
		if ok {
			return ConditionCoverageResult{
				State:           CoverageStateMatched,
				MatchedEvidence: []EvidenceMatch{match},
				RequiredSources: capable,
			}, nil
		}
		incomplete := make([]string, 0, len(capable))
		for _, src := range capable {
			if !completeSources[src] {
				incomplete = append(incomplete, src)
			}
		}
		if len(incomplete) == 0 {
			return ConditionCoverageResult{
				State:           CoverageStateNotMatched,
				RequiredSources: capable,
			}, nil
		}
		return ConditionCoverageResult{
			State:             CoverageStateUnknown,
			IncompleteSources: deduplicateSorted(incomplete),
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
		var matchedEvidence []EvidenceMatch
		var incompleteSources []string
		var requiredSources []string
		hasUnknown := false
		for _, child := range children {
			childRes, err := evaluateConditionCoverageCached(child, signals, completeSources)
			if err != nil {
				return ConditionCoverageResult{}, err
			}
			requiredSources = append(requiredSources, childRes.RequiredSources...)
			if childRes.State == CoverageStateNotMatched {
				// Short-circuit: false AND anything == false
				return ConditionCoverageResult{
					State:           CoverageStateNotMatched,
					RequiredSources: deduplicateSorted(requiredSources),
				}, nil
			}
			if childRes.State == CoverageStateUnknown {
				hasUnknown = true
				incompleteSources = append(incompleteSources, childRes.IncompleteSources...)
			}
			matchedEvidence = append(matchedEvidence, childRes.MatchedEvidence...)
		}
		if hasUnknown {
			return ConditionCoverageResult{
				State:             CoverageStateUnknown,
				MatchedEvidence:   matchedEvidence,
				IncompleteSources: deduplicateSorted(incompleteSources),
				RequiredSources:   deduplicateSorted(requiredSources),
			}, nil
		}
		return ConditionCoverageResult{
			State:           CoverageStateMatched,
			MatchedEvidence: matchedEvidence,
			RequiredSources: deduplicateSorted(requiredSources),
		}, nil
	}

	// Any (OR)
	var matchedEvidence []EvidenceMatch
	var incompleteSources []string
	var requiredSources []string
	hasMatched := false
	allNotMatched := true
	for _, child := range children {
		childRes, err := evaluateConditionCoverageCached(child, signals, completeSources)
		if err != nil {
			return ConditionCoverageResult{}, err
		}
		requiredSources = append(requiredSources, childRes.RequiredSources...)
		if childRes.State == CoverageStateMatched {
			hasMatched = true
			matchedEvidence = append(matchedEvidence, childRes.MatchedEvidence...)
		} else if childRes.State == CoverageStateUnknown {
			allNotMatched = false
			incompleteSources = append(incompleteSources, childRes.IncompleteSources...)
		}
	}
	if hasMatched {
		return ConditionCoverageResult{
			State:           CoverageStateMatched,
			MatchedEvidence: matchedEvidence,
			RequiredSources: deduplicateSorted(requiredSources),
		}, nil
	}
	if allNotMatched {
		return ConditionCoverageResult{
			State:           CoverageStateNotMatched,
			RequiredSources: deduplicateSorted(requiredSources),
		}, nil
	}
	return ConditionCoverageResult{
		State:             CoverageStateUnknown,
		IncompleteSources: deduplicateSorted(incompleteSources),
		RequiredSources:   deduplicateSorted(requiredSources),
	}, nil
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
