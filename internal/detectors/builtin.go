// Package detectors loads the detector rules shipped with Hemera.
package detectors

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/gkehren/hemera/internal/rules"
)

//go:embed rules.json
var builtinRules []byte

// Load validates and returns a fresh copy of Hemera's built-in rule set.
func Load() (rules.RuleSet, error) {
	ruleSet, err := rules.DecodeJSON(bytes.NewReader(builtinRules))
	if err != nil {
		return rules.RuleSet{}, fmt.Errorf("load built-in detectors: %w", err)
	}
	capabilities, err := rules.DefaultCapabilityRegistry()
	if err != nil {
		return rules.RuleSet{}, fmt.Errorf("load built-in detector capabilities: %w", err)
	}
	if err := rules.ValidateRuleSetCapabilities(ruleSet, capabilities); err != nil {
		return rules.RuleSet{}, fmt.Errorf("load built-in detectors: %w", err)
	}
	return ruleSet, nil
}
