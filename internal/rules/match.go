package rules

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gkehren/hemera/pkg/model"
)

var (
	// ErrInvalidSignals identifies input that violates the normalized signal model.
	ErrInvalidSignals = errors.New("invalid signals for rule matching")
)

// EvidenceMatch ties one rule predicate to the strongest matching observation.
type EvidenceMatch struct {
	EvidenceID  string
	Group       string
	Description string
	Weight      float64
	Signal      model.Signal
}

// MatchResult contains explainable matching state for one rule.
type MatchResult struct {
	RuleID                  string
	ConditionMatched        bool
	MinimumEvidenceMet      bool
	PositiveEvidence        []EvidenceMatch
	NegativeEvidence        []EvidenceMatch
	AmbiguousEvidence       []EvidenceMatch
	MissingPositiveEvidence []string
}

// Candidate reports whether the positive condition and evidence minimum match.
func (m MatchResult) Candidate() bool {
	return m.ConditionMatched && m.MinimumEvidenceMet
}

// Match evaluates every rule against normalized signals in document order.
func Match(ruleSet RuleSet, signals []model.Signal) ([]MatchResult, error) {
	if err := ruleSet.Validate(); err != nil {
		return nil, err
	}
	for i, signal := range signals {
		if err := signal.Validate(); err != nil {
			return nil, fmt.Errorf("%w: signals[%d]: %v", ErrInvalidSignals, i, err)
		}
	}
	cachedSignals := make([]cachedSignal, len(signals))
	for i, signal := range signals {
		cachedSignals[i].signal = signal
	}

	results := make([]MatchResult, 0, len(ruleSet.Rules))
	for _, rule := range ruleSet.Rules {
		outcome, err := evaluateCondition(rule.Match, cachedSignals)
		if err != nil {
			return nil, fmt.Errorf("match rule %q: %w", rule.ID, err)
		}
		negative, err := matchEvidenceList(rule.NegativeEvidence, cachedSignals)
		if err != nil {
			return nil, fmt.Errorf("match negative evidence for rule %q: %w", rule.ID, err)
		}
		ambiguous, err := matchEvidenceList(rule.AmbiguousEvidence, cachedSignals)
		if err != nil {
			return nil, fmt.Errorf("match ambiguous evidence for rule %q: %w", rule.ID, err)
		}
		results = append(results, MatchResult{
			RuleID:                  rule.ID,
			ConditionMatched:        outcome.matched,
			MinimumEvidenceMet:      countEvidenceGroups(outcome.evidence) >= rule.MinimumEvidence,
			PositiveEvidence:        outcome.evidence,
			NegativeEvidence:        negative,
			AmbiguousEvidence:       ambiguous,
			MissingPositiveEvidence: outcome.missing,
		})
	}
	return results, nil
}

type conditionOutcome struct {
	matched  bool
	evidence []EvidenceMatch
	missing  []string
}

func evaluateCondition(condition Condition, signals []cachedSignal) (conditionOutcome, error) {
	if condition.Signal != nil {
		matched, ok, err := strongestMatch(*condition.Signal, signals)
		if err != nil {
			return conditionOutcome{}, err
		}
		if !ok {
			return conditionOutcome{missing: []string{condition.Signal.ID}}, nil
		}
		return conditionOutcome{matched: true, evidence: []EvidenceMatch{matched}}, nil
	}

	children := condition.All
	all := true
	if condition.Any != nil {
		children = condition.Any
		all = false
	}
	if all {
		outcome := conditionOutcome{matched: true}
		for _, child := range children {
			childOutcome, err := evaluateCondition(child, signals)
			if err != nil {
				return conditionOutcome{}, err
			}
			outcome.matched = outcome.matched && childOutcome.matched
			outcome.evidence = append(outcome.evidence, childOutcome.evidence...)
			outcome.missing = append(outcome.missing, childOutcome.missing...)
		}
		return outcome, nil
	}

	matched := conditionOutcome{}
	partial := conditionOutcome{}
	for _, child := range children {
		childOutcome, err := evaluateCondition(child, signals)
		if err != nil {
			return conditionOutcome{}, err
		}
		if childOutcome.matched {
			matched.matched = true
			matched.evidence = append(matched.evidence, childOutcome.evidence...)
			continue
		}
		partial.evidence = append(partial.evidence, childOutcome.evidence...)
		partial.missing = append(partial.missing, childOutcome.missing...)
	}
	if matched.matched {
		return matched, nil
	}
	return partial, nil
}

func matchEvidenceList(evidence []Evidence, signals []cachedSignal) ([]EvidenceMatch, error) {
	matches := make([]EvidenceMatch, 0, len(evidence))
	for _, predicate := range evidence {
		matched, ok, err := strongestMatch(predicate, signals)
		if err != nil {
			return nil, err
		}
		if ok {
			matches = append(matches, matched)
		}
	}
	return matches, nil
}

func strongestMatch(evidence Evidence, signals []cachedSignal) (EvidenceMatch, bool, error) {
	prepared, err := prepareEvidence(evidence)
	if err != nil {
		return EvidenceMatch{}, false, err
	}
	best := -1
	for i := range signals {
		if prepared.matches(&signals[i]) && (best == -1 || strongerSignal(signals[i].signal, signals[best].signal)) {
			best = i
		}
	}
	if best == -1 {
		return EvidenceMatch{}, false, nil
	}
	return EvidenceMatch{
		EvidenceID:  evidence.ID,
		Group:       evidenceGroup(evidence),
		Description: evidence.Description,
		Weight:      evidence.Weight,
		Signal:      signals[best].signal,
	}, true, nil
}

func strongerSignal(candidate, current model.Signal) bool {
	if candidate.Confidence != current.Confidence {
		return candidate.Confidence > current.Confidence
	}
	candidateFields := [...]string{string(candidate.Type), candidate.Source, candidate.Key, candidate.Value, candidate.URL}
	currentFields := [...]string{string(current.Type), current.Source, current.Key, current.Value, current.URL}
	for i := range candidateFields {
		if candidateFields[i] != currentFields[i] {
			return candidateFields[i] < currentFields[i]
		}
	}
	return false
}

func countEvidenceGroups(evidence []EvidenceMatch) int {
	groups := make(map[string]struct{}, len(evidence))
	for _, match := range evidence {
		groups[match.Group] = struct{}{}
	}
	return len(groups)
}

type preparedEvidence struct {
	evidence Evidence
	source   preparedPattern
	key      preparedPattern
	value    preparedPattern
	url      preparedPattern
}

type preparedPattern struct {
	pattern    *TextPattern
	expression *regexp.Regexp
	operand    string
}

const (
	signalFieldSource = iota
	signalFieldKey
	signalFieldValue
	signalFieldURL
	signalFieldCount
)

type cachedSignal struct {
	signal       model.Signal
	caseFolded   [signalFieldCount]string
	caseFoldedOK [signalFieldCount]bool
}

func prepareEvidence(evidence Evidence) (preparedEvidence, error) {
	patterns := []*TextPattern{evidence.Source, evidence.Key, evidence.Value, evidence.URL}
	prepared := make([]preparedPattern, len(patterns))
	for i, pattern := range patterns {
		if pattern == nil {
			continue
		}
		preparedPattern, err := prepareTextPattern(pattern)
		if err != nil {
			return preparedEvidence{}, err
		}
		prepared[i] = preparedPattern
	}
	return preparedEvidence{
		evidence: evidence,
		source:   prepared[0],
		key:      prepared[1],
		value:    prepared[2],
		url:      prepared[3],
	}, nil
}

func (p preparedEvidence) matches(signal *cachedSignal) bool {
	if p.evidence.Type != signal.signal.Type {
		return false
	}
	fields := []struct {
		pattern preparedPattern
		field   int
	}{
		{p.source, signalFieldSource},
		{p.key, signalFieldKey},
		{p.value, signalFieldValue},
		{p.url, signalFieldURL},
	}
	for _, field := range fields {
		if field.pattern.pattern == nil {
			continue
		}
		value := signal.field(field.field, field.pattern.needsCaseFold())
		if !field.pattern.matches(value) {
			return false
		}
	}
	return true
}

func (p preparedPattern) matches(value string) bool {
	if p.expression != nil {
		return p.expression.MatchString(value)
	}
	switch {
	case p.pattern.Exact != nil:
		return value == p.operand
	case p.pattern.Contains != nil:
		return strings.Contains(value, p.operand)
	case p.pattern.Prefix != nil:
		return strings.HasPrefix(value, p.operand)
	case p.pattern.Suffix != nil:
		return strings.HasSuffix(value, p.operand)
	default:
		return false
	}
}

func (p preparedPattern) needsCaseFold() bool {
	return p.expression == nil && p.pattern.CaseInsensitive
}

func prepareTextPattern(pattern *TextPattern) (preparedPattern, error) {
	prepared := preparedPattern{pattern: pattern}
	if pattern.Regex != nil {
		expression, err := compileRegex(*pattern.Regex, pattern.CaseInsensitive)
		if err != nil {
			return preparedPattern{}, err
		}
		prepared.expression = expression
		return prepared, nil
	}
	switch {
	case pattern.Exact != nil:
		prepared.operand = *pattern.Exact
	case pattern.Contains != nil:
		prepared.operand = *pattern.Contains
	case pattern.Prefix != nil:
		prepared.operand = *pattern.Prefix
	case pattern.Suffix != nil:
		prepared.operand = *pattern.Suffix
	default:
		return preparedPattern{}, errors.New("text pattern has no operation")
	}
	if pattern.CaseInsensitive {
		prepared.operand = strings.ToLower(prepared.operand)
	}
	return prepared, nil
}

func (s *cachedSignal) field(field int, caseInsensitive bool) string {
	value := s.rawField(field)
	if !caseInsensitive {
		return value
	}
	if !s.caseFoldedOK[field] {
		s.caseFolded[field] = strings.ToLower(value)
		s.caseFoldedOK[field] = true
	}
	return s.caseFolded[field]
}

func (s *cachedSignal) rawField(field int) string {
	switch field {
	case signalFieldSource:
		return s.signal.Source
	case signalFieldKey:
		return s.signal.Key
	case signalFieldValue:
		return s.signal.Value
	case signalFieldURL:
		return s.signal.URL
	default:
		return ""
	}
}

func (p TextPattern) matches(value string) (bool, error) {
	prepared, err := prepareTextPattern(&p)
	if err != nil {
		return false, err
	}
	if prepared.needsCaseFold() {
		value = strings.ToLower(value)
	}
	return prepared.matches(value), nil
}
