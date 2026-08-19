// Package detectors loads and validates the detector rules shipped with Hemera.
package detectors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gkehren/hemera/internal/rules"
)

var (
	// ErrSupportStandardViolation indicates a rule violates the detector support standard.
	ErrSupportStandardViolation = errors.New("support standard violation")
)

// ValidateSupportStandard verifies that a rule set conforms to Hemera's
// detector family support standard defined in docs/detector-support-standard.md.
func ValidateSupportStandard(ruleSet rules.RuleSet) error {
	if err := ruleSet.Validate(); err != nil {
		return fmt.Errorf("%w: schema validation: %v", ErrSupportStandardViolation, err)
	}
	if len(ruleSet.Rules) == 0 {
		return fmt.Errorf("%w: rule set must not be empty", ErrSupportStandardViolation)
	}

	for i, rule := range ruleSet.Rules {
		if err := validateRuleSupportStandard(rule); err != nil {
			return fmt.Errorf("%w: rule[%d] (%s): %v", ErrSupportStandardViolation, i, rule.ID, err)
		}
	}
	return nil
}

func validateRuleSupportStandard(rule rules.Rule) error {
	// Rule ID must follow <vendor>.<product_or_feature> format.
	dotIndex := strings.Index(rule.ID, ".")
	if dotIndex <= 0 || dotIndex >= len(rule.ID)-1 {
		return fmt.Errorf("id %q must follow <vendor>.<product_or_feature> format", rule.ID)
	}

	if strings.TrimSpace(rule.Description) == "" {
		return errors.New("description is required by the support standard")
	}

	if strings.TrimSpace(rule.Vendor) == "" {
		return errors.New("vendor is required")
	}

	// Product-level categories require an explicit product name.
	switch rule.Category {
	case rules.CategoryCAPTCHAChallenge, rules.CategoryWAF, rules.CategoryBotManagement, rules.CategoryClientFingerprinting:
		if strings.TrimSpace(rule.Product) == "" {
			return fmt.Errorf("product is required for product category %q", rule.Category)
		}
	}

	// Score threshold must be within supported detection range.
	if rule.MinimumScore < 25 || rule.MinimumScore > 100 {
		return fmt.Errorf("minimum_score %v must be between 25 and 100", rule.MinimumScore)
	}
	if rule.MinimumEvidence < 1 {
		return errors.New("minimum_evidence must be at least 1")
	}

	// Inspect condition tree for maximum achievable positive score and valid groups.
	groups := make(map[string]float64)
	collectEvidenceGroups(rule.Match, groups)
	if len(groups) < rule.MinimumEvidence {
		return fmt.Errorf("available evidence groups (%d) is less than minimum_evidence (%d)", len(groups), rule.MinimumEvidence)
	}

	var maxScore float64
	for _, weight := range groups {
		maxScore += weight
	}
	if maxScore < rule.MinimumScore {
		return fmt.Errorf("maximum achievable score (%v) is less than minimum_score (%v)", maxScore, rule.MinimumScore)
	}

	return nil
}

func collectEvidenceGroups(condition rules.Condition, groups map[string]float64) {
	if condition.Signal != nil {
		group := condition.Signal.Group
		if group == "" {
			group = condition.Signal.ID
		}
		if condition.Signal.Weight > groups[group] {
			groups[group] = condition.Signal.Weight
		}
		return
	}
	for _, child := range condition.All {
		collectEvidenceGroups(child, groups)
	}
	for _, child := range condition.Any {
		collectEvidenceGroups(child, groups)
	}
}
