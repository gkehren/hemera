package rules

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/pkg/model"
)

var (
	// ErrInvalidCapabilityRegistry identifies a malformed static producer
	// capability declaration.
	ErrInvalidCapabilityRegistry = errors.New("invalid capability registry")
	// ErrUnsupportedCapability identifies a detector predicate that no
	// registered production source can produce.
	ErrUnsupportedCapability = errors.New("unsupported detector capability")
)

// CapabilityRegistry is an immutable lookup of static normalized-signal
// producer support. It is separate from per-scan capability completeness.
type CapabilityRegistry struct {
	capabilities []analysis.Capability
	byType       map[model.SignalType][]string
	bySource     map[string]map[model.SignalType]struct{}
}

// NewCapabilityRegistry validates and freezes a capability set. Repeating the
// same source/signal pair is harmless so application composition can combine
// the production manifest with configured extension analyzers.
func NewCapabilityRegistry(capabilities []analysis.Capability) (CapabilityRegistry, error) {
	registry := CapabilityRegistry{
		byType:   make(map[model.SignalType][]string),
		bySource: make(map[string]map[model.SignalType]struct{}),
	}
	for index, capability := range capabilities {
		source := strings.TrimSpace(capability.Source)
		if source == "" || source != capability.Source {
			return CapabilityRegistry{}, fmt.Errorf(
				"%w: capabilities[%d] source is empty or contains surrounding whitespace",
				ErrInvalidCapabilityRegistry, index,
			)
		}
		if !capability.SignalType.Valid() {
			return CapabilityRegistry{}, fmt.Errorf(
				"%w: capabilities[%d] has invalid signal type %q",
				ErrInvalidCapabilityRegistry, index, capability.SignalType,
			)
		}
		bySignalType, exists := registry.bySource[source]
		if !exists {
			bySignalType = make(map[model.SignalType]struct{})
			registry.bySource[source] = bySignalType
		}
		if _, duplicate := bySignalType[capability.SignalType]; duplicate {
			continue
		}
		bySignalType[capability.SignalType] = struct{}{}
		registry.capabilities = append(registry.capabilities, capability)
		registry.byType[capability.SignalType] = append(registry.byType[capability.SignalType], source)
	}

	sort.Slice(registry.capabilities, func(i, j int) bool {
		if registry.capabilities[i].Source != registry.capabilities[j].Source {
			return registry.capabilities[i].Source < registry.capabilities[j].Source
		}
		return registry.capabilities[i].SignalType < registry.capabilities[j].SignalType
	})
	for signalType := range registry.byType {
		sort.Strings(registry.byType[signalType])
	}
	return registry, nil
}

// DefaultCapabilityRegistry validates and returns the production capability
// support manifest.
func DefaultCapabilityRegistry() (CapabilityRegistry, error) {
	return NewCapabilityRegistry(analysis.ImplementedCapabilities())
}

// Capabilities returns a copy of the registry's source/signal pairs.
func (r CapabilityRegistry) Capabilities() []analysis.Capability {
	return append([]analysis.Capability{}, r.capabilities...)
}

// Supports reports whether source has a production contract for signalType.
func (r CapabilityRegistry) Supports(source string, signalType model.SignalType) bool {
	_, supported := r.bySource[source][signalType]
	return supported
}

// CapableSources returns the registered sources that can produce evidence
// matching the predicate's signal type and optional source constraint.
func (r CapabilityRegistry) CapableSources(evidence Evidence) []string {
	candidates := r.byType[evidence.Type]
	if evidence.Source == nil {
		return append([]string{}, candidates...)
	}
	var filtered []string
	for _, candidate := range candidates {
		if matched, err := evidence.Source.matches(candidate); err == nil && matched {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

// ValidateRuleSetCapabilities rejects predicates that cannot be produced by
// any registered source. Exact source constraints must name a supported pair;
// source-agnostic and patterned predicates must match at least one producer.
func ValidateRuleSetCapabilities(ruleSet RuleSet, registry CapabilityRegistry) error {
	if err := ruleSet.Validate(); err != nil {
		return err
	}
	if len(registry.capabilities) == 0 {
		return fmt.Errorf("%w: registry is empty", ErrInvalidCapabilityRegistry)
	}
	for ruleIndex, rule := range ruleSet.Rules {
		if err := validateConditionCapabilities(rule.Match, registry, "match"); err != nil {
			return fmt.Errorf("%w: rules[%d] (%s): %v", ErrUnsupportedCapability, ruleIndex, rule.ID, err)
		}
		for index, evidence := range rule.NegativeEvidence {
			if err := validateEvidenceCapability(evidence, registry); err != nil {
				return fmt.Errorf(
					"%w: rules[%d] (%s): negative_evidence[%d]: %v",
					ErrUnsupportedCapability, ruleIndex, rule.ID, index, err,
				)
			}
		}
		for index, evidence := range rule.AmbiguousEvidence {
			if err := validateEvidenceCapability(evidence, registry); err != nil {
				return fmt.Errorf(
					"%w: rules[%d] (%s): ambiguous_evidence[%d]: %v",
					ErrUnsupportedCapability, ruleIndex, rule.ID, index, err,
				)
			}
		}
	}
	return nil
}

func validateConditionCapabilities(condition Condition, registry CapabilityRegistry, path string) error {
	if condition.Signal != nil {
		if err := validateEvidenceCapability(*condition.Signal, registry); err != nil {
			return fmt.Errorf("%s.signal: %v", path, err)
		}
		return nil
	}
	children := condition.All
	field := "all"
	if condition.Any != nil {
		children = condition.Any
		field = "any"
	}
	for index, child := range children {
		if err := validateConditionCapabilities(child, registry, fmt.Sprintf("%s.%s[%d]", path, field, index)); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceCapability(evidence Evidence, registry CapabilityRegistry) error {
	if len(registry.CapableSources(evidence)) > 0 {
		return nil
	}
	if evidence.Source != nil && evidence.Source.Exact != nil {
		return fmt.Errorf("source %q cannot produce signal type %q", *evidence.Source.Exact, evidence.Type)
	}
	if evidence.Source != nil {
		return fmt.Errorf("source constraint matches no producer for signal type %q", evidence.Type)
	}
	return fmt.Errorf("no source can produce signal type %q", evidence.Type)
}
