// Package scoring converts matched detector evidence into bounded, explainable
// confidence scores without depending on analyzers or reporters.
package scoring

import (
	"fmt"
	"math"

	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/pkg/model"
)

// Level is the human meaning assigned to a bounded confidence score.
type Level string

const (
	// LevelNotDetected represents scores from 0 through 24.
	LevelNotDetected Level = "not_detected"
	// LevelLow represents scores from 25 through 49.
	LevelLow Level = "low"
	// LevelMedium represents scores from 50 through 74.
	LevelMedium Level = "medium"
	// LevelHigh represents scores from 75 through 89.
	LevelHigh Level = "high"
	// LevelVeryHigh represents scores from 90 through 100.
	LevelVeryHigh Level = "very_high"
)

// AppliedConflict records a cross-rule penalty included in a score.
type AppliedConflict struct {
	RuleID  string
	Penalty float64
}

// ScoredEvidence ties one matched predicate to its raw and effective score
// contributions.
type ScoredEvidence struct {
	Match           rules.EvidenceMatch
	RawContribution float64
	Contribution    float64
}

// EvidenceGroup records how correlated positive evidence was aggregated.
type EvidenceGroup struct {
	ID                 string
	EvidenceIDs        []string
	SelectedEvidenceID string
	RawContribution    float64
	Contribution       float64
}

// Detection contains the score and all evidence needed to explain one rule.
type Detection struct {
	RuleID                  string
	Name                    string
	Category                rules.Category
	Vendor                  string
	Product                 string
	ConditionMatched        bool
	MinimumEvidenceMet      bool
	Detected                bool
	EvidenceScore           float64
	Score                   float64
	Level                   Level
	PositiveEvidence        []ScoredEvidence
	PositiveEvidenceGroups  []EvidenceGroup
	NegativeEvidence        []ScoredEvidence
	AmbiguousEvidence       []ScoredEvidence
	MissingPositiveEvidence []string
	MissingDependencies     []string
	AppliedConflicts        []AppliedConflict
}

// Evaluate matches a validated rule set and calculates one result per rule.
func Evaluate(ruleSet rules.RuleSet, signals []model.Signal) ([]Detection, error) {
	matches, err := rules.Match(ruleSet, signals)
	if err != nil {
		return nil, err
	}
	return scoreMatches(ruleSet, matches)
}

// LevelForScore returns the documented label for a score clamped to 0–100.
func LevelForScore(score float64) Level {
	score = clamp(score)
	switch {
	case score >= 90:
		return LevelVeryHigh
	case score >= 75:
		return LevelHigh
	case score >= 50:
		return LevelMedium
	case score >= 25:
		return LevelLow
	default:
		return LevelNotDetected
	}
}

func scoreMatches(ruleSet rules.RuleSet, matches []rules.MatchResult) ([]Detection, error) {
	if len(matches) != len(ruleSet.Rules) {
		return nil, fmt.Errorf("score matches: got %d results for %d rules", len(matches), len(ruleSet.Rules))
	}
	matchByID := make(map[string]rules.MatchResult, len(matches))
	for _, match := range matches {
		if _, duplicate := matchByID[match.RuleID]; duplicate {
			return nil, fmt.Errorf("score matches: duplicate rule %q", match.RuleID)
		}
		matchByID[match.RuleID] = match
	}
	positiveScores := make(map[string]float64, len(matches))
	positiveGroups := make(map[string][]EvidenceGroup, len(matches))
	positiveEvidence := make(map[string][]ScoredEvidence, len(matches))
	negativeEvidence := make(map[string][]ScoredEvidence, len(matches))
	ambiguousEvidence := make(map[string][]ScoredEvidence, len(matches))
	baseEvidenceScores := make(map[string]float64, len(matches))
	for _, match := range matches {
		active := match.Candidate()
		positiveScore, scoredPositive, groups := scorePositive(match.PositiveEvidence, active)
		negativeScore, scoredNegative := scorePenalties(match.NegativeEvidence, active)
		ambiguousScore, scoredAmbiguous := scorePenalties(match.AmbiguousEvidence, active)
		positiveScores[match.RuleID] = positiveScore
		positiveGroups[match.RuleID] = groups
		positiveEvidence[match.RuleID] = scoredPositive
		negativeEvidence[match.RuleID] = scoredNegative
		ambiguousEvidence[match.RuleID] = scoredAmbiguous
		baseEvidenceScores[match.RuleID] = positiveScore + negativeScore + ambiguousScore
	}

	ruleByID := make(map[string]rules.Rule, len(ruleSet.Rules))
	evidenceScores := make(map[string]float64, len(ruleSet.Rules))
	conflictsByID := make(map[string][]AppliedConflict, len(ruleSet.Rules))
	for _, rule := range ruleSet.Rules {
		ruleByID[rule.ID] = rule
		match, ok := matchByID[rule.ID]
		if !ok {
			return nil, fmt.Errorf("score matches: missing rule %q", rule.ID)
		}
		if !match.Candidate() {
			continue
		}
		score := baseEvidenceScores[rule.ID]
		for _, conflict := range rule.Conflicts {
			other, ok := matchByID[conflict.RuleID]
			if ok && other.Candidate() && positiveScores[conflict.RuleID] > 0 {
				score -= conflict.Penalty
				conflictsByID[rule.ID] = append(conflictsByID[rule.ID], AppliedConflict{
					RuleID: conflict.RuleID, Penalty: conflict.Penalty,
				})
			}
		}
		evidenceScores[rule.ID] = clamp(score)
	}

	eligibleMemo := make(map[string]bool, len(ruleSet.Rules))
	var eligible func(string) bool
	eligible = func(id string) bool {
		if value, ok := eligibleMemo[id]; ok {
			return value
		}
		rule := ruleByID[id]
		match := matchByID[id]
		if !match.Candidate() || evidenceScores[id] < rule.MinimumScore {
			eligibleMemo[id] = false
			return false
		}
		for _, dependency := range rule.Requires {
			if !eligible(dependency) {
				eligibleMemo[id] = false
				return false
			}
		}
		eligibleMemo[id] = true
		return true
	}

	detections := make([]Detection, 0, len(ruleSet.Rules))
	for _, rule := range ruleSet.Rules {
		match := matchByID[rule.ID]
		missingDependencies := make([]string, 0, len(rule.Requires))
		for _, dependency := range rule.Requires {
			if !eligible(dependency) {
				missingDependencies = append(missingDependencies, dependency)
			}
		}
		score := evidenceScores[rule.ID]
		detected := eligible(rule.ID)
		if len(missingDependencies) > 0 {
			score = 0
		}
		detections = append(detections, Detection{
			RuleID:                  rule.ID,
			Name:                    rule.Name,
			Category:                rule.Category,
			Vendor:                  rule.Vendor,
			Product:                 rule.Product,
			ConditionMatched:        match.ConditionMatched,
			MinimumEvidenceMet:      match.MinimumEvidenceMet,
			Detected:                detected,
			EvidenceScore:           evidenceScores[rule.ID],
			Score:                   score,
			Level:                   LevelForScore(score),
			PositiveEvidence:        positiveEvidence[rule.ID],
			PositiveEvidenceGroups:  positiveGroups[rule.ID],
			NegativeEvidence:        negativeEvidence[rule.ID],
			AmbiguousEvidence:       ambiguousEvidence[rule.ID],
			MissingPositiveEvidence: match.MissingPositiveEvidence,
			MissingDependencies:     missingDependencies,
			AppliedConflicts:        conflictsByID[rule.ID],
		})
	}
	return detections, nil
}

func scorePositive(
	evidence []rules.EvidenceMatch,
	active bool,
) (float64, []ScoredEvidence, []EvidenceGroup) {
	scored := make([]ScoredEvidence, len(evidence))
	groups := make([]EvidenceGroup, 0, len(evidence))
	indexes := make(map[string]int, len(evidence))
	selectedIndexes := make([]int, 0, len(evidence))
	maximums := make([]float64, 0, len(evidence))
	for evidenceIndex, match := range evidence {
		rawContribution := match.Weight * match.Signal.Confidence
		scored[evidenceIndex] = ScoredEvidence{
			Match: match, RawContribution: rawContribution,
		}
		index, ok := indexes[match.Group]
		if !ok {
			indexes[match.Group] = len(groups)
			groups = append(groups, EvidenceGroup{
				ID:                 match.Group,
				EvidenceIDs:        []string{match.EvidenceID},
				SelectedEvidenceID: match.EvidenceID,
				RawContribution:    rawContribution,
			})
			selectedIndexes = append(selectedIndexes, evidenceIndex)
			maximums = append(maximums, rawContribution)
			continue
		}
		group := &groups[index]
		group.EvidenceIDs = append(group.EvidenceIDs, match.EvidenceID)
		group.RawContribution += rawContribution
		if rawContribution > maximums[index] {
			group.SelectedEvidenceID = match.EvidenceID
			selectedIndexes[index] = evidenceIndex
			maximums[index] = rawContribution
		}
	}

	total := 0.0
	if active {
		for i := range groups {
			groups[i].Contribution = maximums[i]
			scored[selectedIndexes[i]].Contribution = maximums[i]
			total += maximums[i]
		}
	}
	return total, scored, groups
}

func scorePenalties(evidence []rules.EvidenceMatch, active bool) (float64, []ScoredEvidence) {
	scored := make([]ScoredEvidence, 0, len(evidence))
	total := 0.0
	for _, match := range evidence {
		rawContribution := -match.Weight * match.Signal.Confidence
		contribution := 0.0
		if active {
			contribution = rawContribution
			total += contribution
		}
		scored = append(scored, ScoredEvidence{
			Match: match, RawContribution: rawContribution, Contribution: contribution,
		})
	}
	return total, scored
}

func clamp(score float64) float64 {
	if math.IsNaN(score) {
		return 0
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
