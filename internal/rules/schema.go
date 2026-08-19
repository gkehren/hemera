// Package rules defines, validates, and evaluates Hemera's data-driven
// detector rules without depending on protocol analyzers or presentation.
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/gkehren/hemera/pkg/model"
)

const (
	// CurrentSchemaVersion is the latest detector rule schema understood by Hemera.
	CurrentSchemaVersion = 2
	schemaVersionV1      = 1
	// MaxDocumentBytes bounds a decoded detector document.
	MaxDocumentBytes   = 1 << 20
	maxRules           = 1000
	maxConditionDepth  = 16
	maxEvidencePerRule = 256
	maxPatternBytes    = 2048
)

var (
	// ErrInvalidSchema identifies a detector document that violates the schema.
	ErrInvalidSchema = errors.New("invalid detector rule schema")
	// ErrDocumentTooLarge identifies a detector document above MaxDocumentBytes.
	ErrDocumentTooLarge = errors.New("detector rule document is too large")

	identifierPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
)

// Category identifies the protection class described by a detector rule.
type Category string

const (
	// CategoryCDNReverseProxy identifies CDN or reverse-proxy infrastructure.
	CategoryCDNReverseProxy Category = "cdn_reverse_proxy"
	// CategoryWAF identifies a web application firewall.
	CategoryWAF Category = "waf"
	// CategoryBotManagement identifies bot-management behavior.
	CategoryBotManagement Category = "bot_management"
	// CategoryCAPTCHAChallenge identifies CAPTCHA or challenge products.
	CategoryCAPTCHAChallenge Category = "captcha_challenge"
	// CategoryClientFingerprinting identifies client-side fingerprinting.
	CategoryClientFingerprinting Category = "client_fingerprinting"
	// CategoryThirdPartySecurity identifies another third-party security service.
	CategoryThirdPartySecurity Category = "third_party_security"
)

var validCategories = map[Category]struct{}{
	CategoryCDNReverseProxy:      {},
	CategoryWAF:                  {},
	CategoryBotManagement:        {},
	CategoryCAPTCHAChallenge:     {},
	CategoryClientFingerprinting: {},
	CategoryThirdPartySecurity:   {},
}

// Valid reports whether the category is supported by the rule schemas.
func (c Category) Valid() bool {
	_, ok := validCategories[c]
	return ok
}

// RuleSet is one versioned detector rule document.
type RuleSet struct {
	SchemaVersion int    `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}

// Rule describes one independently scored vendor or product detection.
type Rule struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Description       string     `json:"description,omitempty"`
	Category          Category   `json:"category"`
	Vendor            string     `json:"vendor"`
	Product           string     `json:"product,omitempty"`
	MinimumEvidence   int        `json:"minimum_evidence"`
	MinimumScore      float64    `json:"minimum_score"`
	Match             Condition  `json:"match"`
	NegativeEvidence  []Evidence `json:"negative_evidence,omitempty"`
	AmbiguousEvidence []Evidence `json:"ambiguous_evidence,omitempty"`
	Requires          []string   `json:"requires,omitempty"`
	Conflicts         []Conflict `json:"conflicts,omitempty"`
}

// Condition is exactly one signal predicate, all group, or any group.
type Condition struct {
	Signal *Evidence   `json:"signal,omitempty"`
	All    []Condition `json:"all,omitempty"`
	Any    []Condition `json:"any,omitempty"`
}

// Evidence matches one normalized signal and assigns it a score weight.
type Evidence struct {
	ID          string           `json:"id"`
	Group       string           `json:"group,omitempty"`
	Description string           `json:"description,omitempty"`
	Type        model.SignalType `json:"type"`
	Source      *TextPattern     `json:"source,omitempty"`
	Key         *TextPattern     `json:"key,omitempty"`
	Value       *TextPattern     `json:"value,omitempty"`
	URL         *TextPattern     `json:"url,omitempty"`
	Weight      float64          `json:"weight"`
}

// TextPattern applies exactly one string comparison operation.
type TextPattern struct {
	Exact           *string `json:"exact,omitempty"`
	Contains        *string `json:"contains,omitempty"`
	Prefix          *string `json:"prefix,omitempty"`
	Suffix          *string `json:"suffix,omitempty"`
	Regex           *string `json:"regex,omitempty"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
}

// Conflict subtracts a fixed penalty when another rule's condition matches.
type Conflict struct {
	RuleID  string  `json:"rule_id"`
	Penalty float64 `json:"penalty"`
}

// DecodeJSON decodes and validates one strict, size-bounded JSON rule document.
func DecodeJSON(reader io.Reader) (RuleSet, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxDocumentBytes+1))
	if err != nil {
		return RuleSet{}, fmt.Errorf("read detector rules: %w", err)
	}
	if len(data) > MaxDocumentBytes {
		return RuleSet{}, ErrDocumentTooLarge
	}
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return RuleSet{}, schemaError("decode JSON: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ruleSet RuleSet
	if err := decoder.Decode(&ruleSet); err != nil {
		return RuleSet{}, fmt.Errorf("%w: decode JSON: %v", ErrInvalidSchema, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return RuleSet{}, fmt.Errorf("%w: multiple JSON values", ErrInvalidSchema)
		}
		return RuleSet{}, fmt.Errorf("%w: trailing data: %v", ErrInvalidSchema, err)
	}
	if err := ruleSet.Validate(); err != nil {
		return RuleSet{}, err
	}
	return ruleSet, nil
}

func rejectDuplicateObjectKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, duplicate := keys[key]; duplicate {
					return fmt.Errorf("duplicate object key %q", key)
				}
				keys[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter %q", delimiter)
		}
	}
	return walk()
}

// Validate checks all schema invariants and cross-rule references.
func (s RuleSet) Validate() error {
	if s.SchemaVersion != schemaVersionV1 && s.SchemaVersion != CurrentSchemaVersion {
		return schemaError("schema_version must be %d or %d", schemaVersionV1, CurrentSchemaVersion)
	}
	if len(s.Rules) == 0 {
		return schemaError("rules must not be empty")
	}
	if len(s.Rules) > maxRules {
		return schemaError("rules exceeds the limit of %d", maxRules)
	}

	byID := make(map[string]Rule, len(s.Rules))
	for i, rule := range s.Rules {
		if err := validateRule(rule, s.SchemaVersion); err != nil {
			return schemaError("rules[%d]: %v", i, err)
		}
		if _, duplicate := byID[rule.ID]; duplicate {
			return schemaError("rules[%d]: duplicate id %q", i, rule.ID)
		}
		byID[rule.ID] = rule
	}

	for _, rule := range s.Rules {
		requires := make(map[string]struct{}, len(rule.Requires))
		for _, dependency := range rule.Requires {
			if dependency == rule.ID {
				return schemaError("rule %q requires itself", rule.ID)
			}
			if _, ok := byID[dependency]; !ok {
				return schemaError("rule %q requires unknown rule %q", rule.ID, dependency)
			}
			if _, duplicate := requires[dependency]; duplicate {
				return schemaError("rule %q repeats dependency %q", rule.ID, dependency)
			}
			requires[dependency] = struct{}{}
		}
		conflicts := make(map[string]struct{}, len(rule.Conflicts))
		for _, conflict := range rule.Conflicts {
			if conflict.RuleID == rule.ID {
				return schemaError("rule %q conflicts with itself", rule.ID)
			}
			if _, ok := byID[conflict.RuleID]; !ok {
				return schemaError("rule %q conflicts with unknown rule %q", rule.ID, conflict.RuleID)
			}
			if _, duplicate := conflicts[conflict.RuleID]; duplicate {
				return schemaError("rule %q repeats conflict %q", rule.ID, conflict.RuleID)
			}
			if _, contradictory := requires[conflict.RuleID]; contradictory {
				return schemaError("rule %q both requires and conflicts with %q", rule.ID, conflict.RuleID)
			}
			conflicts[conflict.RuleID] = struct{}{}
		}
	}
	if err := validateDependencyGraph(s.Rules, byID); err != nil {
		return err
	}
	return nil
}

func validateRule(rule Rule, schemaVersion int) error {
	if !identifierPattern.MatchString(rule.ID) {
		return fmt.Errorf("id %q must be a lowercase identifier", rule.ID)
	}
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("name is required")
	}
	if !rule.Category.Valid() {
		return fmt.Errorf("category %q is invalid", rule.Category)
	}
	if strings.TrimSpace(rule.Vendor) == "" {
		return errors.New("vendor is required")
	}
	if rule.MinimumEvidence < 1 {
		return errors.New("minimum_evidence must be at least 1")
	}
	if !finiteRange(rule.MinimumScore, 25, 100) {
		return errors.New("minimum_score must be finite and between 25 and 100")
	}

	ids := make(map[string]struct{})
	positiveGroups := make(map[string]struct{})
	nodes := 0
	if err := validateCondition(rule.Match, 1, &nodes, ids, positiveGroups, schemaVersion); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	availableEvidence := nodes
	evidenceLabel := "positive predicates"
	if schemaVersion == CurrentSchemaVersion {
		availableEvidence = len(positiveGroups)
		evidenceLabel = "positive evidence groups"
	}
	if rule.MinimumEvidence > availableEvidence {
		return fmt.Errorf("minimum_evidence %d exceeds %d %s", rule.MinimumEvidence, availableEvidence, evidenceLabel)
	}
	for i, evidence := range rule.NegativeEvidence {
		if err := validatePenaltyEvidence(evidence, ids); err != nil {
			return fmt.Errorf("negative_evidence[%d]: %w", i, err)
		}
	}
	for i, evidence := range rule.AmbiguousEvidence {
		if err := validatePenaltyEvidence(evidence, ids); err != nil {
			return fmt.Errorf("ambiguous_evidence[%d]: %w", i, err)
		}
	}
	if len(ids) > maxEvidencePerRule {
		return fmt.Errorf("evidence exceeds the limit of %d", maxEvidencePerRule)
	}
	for i, conflict := range rule.Conflicts {
		if !identifierPattern.MatchString(conflict.RuleID) {
			return fmt.Errorf("conflicts[%d].rule_id %q is invalid", i, conflict.RuleID)
		}
		if !finiteRange(conflict.Penalty, 0, 100) || conflict.Penalty == 0 {
			return fmt.Errorf("conflicts[%d].penalty must be finite and between 0 and 100", i)
		}
	}
	for i, dependency := range rule.Requires {
		if !identifierPattern.MatchString(dependency) {
			return fmt.Errorf("requires[%d] %q is invalid", i, dependency)
		}
	}
	return nil
}

func validateCondition(
	condition Condition,
	depth int,
	nodes *int,
	ids map[string]struct{},
	groups map[string]struct{},
	schemaVersion int,
) error {
	if depth > maxConditionDepth {
		return fmt.Errorf("condition depth exceeds %d", maxConditionDepth)
	}
	kinds := 0
	if condition.Signal != nil {
		kinds++
	}
	if condition.All != nil {
		kinds++
	}
	if condition.Any != nil {
		kinds++
	}
	if kinds != 1 {
		return errors.New("condition must contain exactly one of signal, all, or any")
	}
	if condition.Signal != nil {
		(*nodes)++
		if *nodes > maxEvidencePerRule {
			return fmt.Errorf("positive evidence exceeds the limit of %d", maxEvidencePerRule)
		}
		if err := validateEvidence(*condition.Signal, ids); err != nil {
			return err
		}
		if schemaVersion == schemaVersionV1 && condition.Signal.Group != "" {
			return errors.New("group requires schema_version 2")
		}
		groups[evidenceGroup(*condition.Signal)] = struct{}{}
		return nil
	}
	children := condition.All
	if condition.Any != nil {
		children = condition.Any
	}
	if len(children) == 0 {
		return errors.New("condition group must not be empty")
	}
	for i, child := range children {
		if err := validateCondition(child, depth+1, nodes, ids, groups, schemaVersion); err != nil {
			return fmt.Errorf("child[%d]: %w", i, err)
		}
	}
	return nil
}

func validateEvidence(evidence Evidence, ids map[string]struct{}) error {
	if !identifierPattern.MatchString(evidence.ID) {
		return fmt.Errorf("id %q must be a lowercase identifier", evidence.ID)
	}
	if _, duplicate := ids[evidence.ID]; duplicate {
		return fmt.Errorf("duplicate evidence id %q", evidence.ID)
	}
	ids[evidence.ID] = struct{}{}
	if evidence.Group != "" && !identifierPattern.MatchString(evidence.Group) {
		return fmt.Errorf("group %q must be a lowercase identifier", evidence.Group)
	}
	if !evidence.Type.Valid() {
		return fmt.Errorf("signal type %q is invalid", evidence.Type)
	}
	if !finiteRange(evidence.Weight, 0, 100) || evidence.Weight == 0 {
		return errors.New("weight must be finite and between 0 and 100")
	}
	patterns := []*TextPattern{evidence.Source, evidence.Key, evidence.Value, evidence.URL}
	matchedFields := 0
	for _, pattern := range patterns {
		if pattern == nil {
			continue
		}
		matchedFields++
		if err := pattern.validate(); err != nil {
			return err
		}
	}
	if matchedFields == 0 {
		return errors.New("at least one of source, key, value, or url is required")
	}
	return nil
}

func validatePenaltyEvidence(evidence Evidence, ids map[string]struct{}) error {
	if evidence.Group != "" {
		return errors.New("group is only supported for positive evidence")
	}
	return validateEvidence(evidence, ids)
}

func evidenceGroup(evidence Evidence) string {
	if evidence.Group != "" {
		return evidence.Group
	}
	return evidence.ID
}

func (p TextPattern) validate() error {
	values := []*string{p.Exact, p.Contains, p.Prefix, p.Suffix, p.Regex}
	count := 0
	for _, value := range values {
		if value == nil {
			continue
		}
		count++
		if *value == "" {
			return errors.New("text pattern operand must not be empty")
		}
		if len(*value) > maxPatternBytes {
			return fmt.Errorf("text pattern exceeds %d bytes", maxPatternBytes)
		}
	}
	if count != 1 {
		return errors.New("text pattern must contain exactly one operation")
	}
	if p.Regex != nil {
		if _, err := compileRegex(*p.Regex, p.CaseInsensitive); err != nil {
			return fmt.Errorf("invalid regular expression: %w", err)
		}
	}
	return nil
}

func validateDependencyGraph(ordered []Rule, rules map[string]Rule) error {
	const (
		unvisited = iota
		visiting
		visited
	)
	states := make(map[string]int, len(rules))
	var visit func(string) error
	visit = func(id string) error {
		switch states[id] {
		case visiting:
			return schemaError("dependency cycle includes rule %q", id)
		case visited:
			return nil
		}
		states[id] = visiting
		for _, dependency := range rules[id].Requires {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		states[id] = visited
		return nil
	}
	for _, rule := range ordered {
		if err := visit(rule.ID); err != nil {
			return err
		}
	}
	return nil
}

func compileRegex(expression string, caseInsensitive bool) (*regexp.Regexp, error) {
	if caseInsensitive {
		expression = "(?i:" + expression + ")"
	}
	return regexp.Compile(expression)
}

func finiteRange(value, minimum, maximum float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= minimum && value <= maximum
}

func schemaError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSchema, fmt.Sprintf(format, args...))
}
