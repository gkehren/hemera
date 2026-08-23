// Package scanner orchestrates analyzers, detector matching, and scoring.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

var (
	// ErrInvalidConfig identifies missing or invalid scanner dependencies.
	ErrInvalidConfig = errors.New("invalid scanner configuration")
	// ErrInvalidObservation identifies an analyzer contract violation.
	ErrInvalidObservation = errors.New("invalid analyzer observation")
)

// FailurePolicy defines whether an analyzer-local error aborts the scan or
// preserves any valid partial observation and continues.
type FailurePolicy uint8

const (
	// FailurePolicyAbort makes an analyzer error fatal to the complete scan.
	FailurePolicyAbort FailurePolicy = iota
	// FailurePolicyContinue records a partial or failed analyzer outcome and
	// continues with the remaining analyzers.
	FailurePolicyContinue
)

// Analyzer is the observation boundary required by Scanner.
type Analyzer interface {
	Source() string
	Capabilities() []model.SignalType
	Observe(context.Context, analysis.Target) (analysis.Observation, error)
}

// AnalyzerConfig binds one analyzer to its local failure policy. Entries run
// sequentially in slice order.
type AnalyzerConfig struct {
	Analyzer      Analyzer
	FailurePolicy FailurePolicy
}

// Config contains the ordered analyzer pipeline, validated detector rules,
// and an optional progress observer.
type Config struct {
	Analyzers []AnalyzerConfig
	RuleSet   rules.RuleSet
	// Progress optionally receives analyzer lifecycle events during Scan.
	Progress ProgressFunc
}

// AnalyzerStatus describes the coverage produced by one analyzer run.
type AnalyzerStatus string

const (
	// AnalyzerStatusComplete means the analyzer returned without an error.
	AnalyzerStatusComplete AnalyzerStatus = "complete"
	// AnalyzerStatusPartial means the analyzer returned useful observations and
	// a non-fatal local error.
	AnalyzerStatusPartial AnalyzerStatus = "partial"
	// AnalyzerStatusFailed means a non-fatal local error produced no signals or
	// source-specific metadata.
	AnalyzerStatusFailed AnalyzerStatus = "failed"
)

// DetectionStatus distinguishes a conclusive positive or negative result from a
// result that could not be conclusively evaluated because observation coverage was
// insufficient to determine whether the detection criteria could be satisfied.
type DetectionStatus string

const (
	DetectionStatusDetected             DetectionStatus = "detected"
	DetectionStatusNotDetected          DetectionStatus = "not_detected"
	DetectionStatusInsufficientCoverage DetectionStatus = "insufficient_coverage"
)

// DetectionCoverage records the coverage-sensitive status of one rule without
// coupling that rule to a concrete analyzer package.
type DetectionCoverage struct {
	RuleID            string
	Status            DetectionStatus
	RequiredSources   []string
	IncompleteSources []string
}

// AnalyzerResult records one analyzer's observation and coverage status. Err is
// retained for diagnostics but reporters decide what is safe to disclose.
type AnalyzerResult struct {
	Observation analysis.Observation
	Status      AnalyzerStatus
	Err         error
}

// Result contains ordered analyzer outcomes, their aggregate normalized
// signals, and scored detector results.
type Result struct {
	Target     analysis.Target
	Analyzers  []AnalyzerResult
	Signals    []model.Signal
	Detections []scoring.Detection
	Coverage   []DetectionCoverage
}

type configuredAnalyzer struct {
	analyzer Analyzer
	source   string
	policy   FailurePolicy
}

// Scanner coordinates an ordered analyzer pipeline and validated detector rules.
type Scanner struct {
	analyzers  []configuredAnalyzer
	ruleSet    rules.RuleSet
	capability rules.CapabilityRegistry
	progress   ProgressFunc
}

// New validates the scanner dependencies and freezes analyzer order and source
// identities for subsequent scans.
func New(config Config) (*Scanner, error) {
	if len(config.Analyzers) == 0 {
		return nil, fmt.Errorf("%w: at least one analyzer is required", ErrInvalidConfig)
	}
	if err := config.RuleSet.Validate(); err != nil {
		return nil, fmt.Errorf("%w: detector rules: %w", ErrInvalidConfig, err)
	}
	defaultCapabilities, err := rules.DefaultCapabilityRegistry()
	if err != nil {
		return nil, fmt.Errorf("%w: production capabilities: %w", ErrInvalidConfig, err)
	}
	capabilityDeclarations := defaultCapabilities.Capabilities()

	configured := make([]configuredAnalyzer, 0, len(config.Analyzers))
	sources := make(map[string]struct{}, len(config.Analyzers))
	for index, entry := range config.Analyzers {
		if analyzerIsNil(entry.Analyzer) {
			return nil, fmt.Errorf("%w: analyzer %d is required", ErrInvalidConfig, index)
		}
		if entry.FailurePolicy != FailurePolicyAbort && entry.FailurePolicy != FailurePolicyContinue {
			return nil, fmt.Errorf("%w: analyzer %d has unsupported failure policy %d", ErrInvalidConfig, index, entry.FailurePolicy)
		}
		rawSource := entry.Analyzer.Source()
		source := strings.TrimSpace(rawSource)
		if source == "" {
			return nil, fmt.Errorf("%w: analyzer %d source is required", ErrInvalidConfig, index)
		}
		if source != rawSource {
			return nil, fmt.Errorf("%w: analyzer %d source must not contain surrounding whitespace", ErrInvalidConfig, index)
		}
		if _, exists := sources[source]; exists {
			return nil, fmt.Errorf("%w: duplicate analyzer source %q", ErrInvalidConfig, source)
		}
		advertised := append([]model.SignalType{}, entry.Analyzer.Capabilities()...)
		if len(advertised) == 0 {
			return nil, fmt.Errorf("%w: analyzer %q declares no capabilities", ErrInvalidConfig, source)
		}
		sort.Slice(advertised, func(i, j int) bool { return advertised[i] < advertised[j] })
		for capabilityIndex, signalType := range advertised {
			if !signalType.Valid() {
				return nil, fmt.Errorf(
					"%w: analyzer %q capability %d has invalid signal type %q",
					ErrInvalidConfig, source, capabilityIndex, signalType,
				)
			}
			if capabilityIndex > 0 && signalType == advertised[capabilityIndex-1] {
				return nil, fmt.Errorf(
					"%w: analyzer %q repeats capability %q",
					ErrInvalidConfig, source, signalType,
				)
			}
			capabilityDeclarations = append(capabilityDeclarations, analysis.Capability{
				Source: source, SignalType: signalType,
			})
		}
		if implemented := analysis.SupportedSignalTypes(source); len(implemented) > 0 && !slices.Equal(advertised, implemented) {
			return nil, fmt.Errorf(
				"%w: analyzer %q capabilities %v do not match production contract %v",
				ErrInvalidConfig, source, advertised, implemented,
			)
		}
		sources[source] = struct{}{}
		configured = append(configured, configuredAnalyzer{
			analyzer: entry.Analyzer, source: source, policy: entry.FailurePolicy,
		})
	}
	capabilityRegistry, err := rules.NewCapabilityRegistry(capabilityDeclarations)
	if err != nil {
		return nil, fmt.Errorf("%w: analyzer capabilities: %w", ErrInvalidConfig, err)
	}
	if err := rules.ValidateRuleSetCapabilities(config.RuleSet, capabilityRegistry); err != nil {
		return nil, fmt.Errorf("%w: detector rules: %w", ErrInvalidConfig, err)
	}

	return &Scanner{
		analyzers: configured, ruleSet: config.RuleSet,
		capability: capabilityRegistry, progress: config.Progress,
	}, nil
}

// Sources returns the frozen analyzer source identities in scan order.
func (s *Scanner) Sources() []string {
	sources := make([]string, 0, len(s.analyzers))
	for _, configured := range s.analyzers {
		sources = append(sources, configured.source)
	}
	return sources
}

func analyzerIsNil(analyzer Analyzer) bool {
	if analyzer == nil {
		return true
	}
	value := reflect.ValueOf(analyzer)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

// emit invokes the optional progress observer, ignoring nil callbacks.
func (s *Scanner) emit(event ScanEvent) {
	if s.progress != nil {
		s.progress(event)
	}
}

// Scan runs configured analyzers sequentially, validates and aggregates every
// signal in analyzer order, then evaluates all detector rules once.
func (s *Scanner) Scan(ctx context.Context, rawURL string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("scan canceled: %w", err)
	}

	result := Result{
		Target:    analysis.Target{URL: rawURL},
		Analyzers: make([]AnalyzerResult, 0, len(s.analyzers)),
		Signals:   make([]model.Signal, 0),
	}
	metadataSources := make(map[analysis.MetadataKind]string)
	for _, configured := range s.analyzers {
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("scan canceled before analyzer %q: %w", configured.source, err)
		}

		target := analysis.Target{URL: result.Target.URL, Prior: priorObservations(result.Analyzers)}
		s.emit(ScanEvent{Source: configured.source, Kind: ScanEventStarted})
		observation, analyzerErr := configured.analyzer.Observe(ctx, target)
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("analyzer %q canceled: %w", configured.source, errors.Join(analyzerErr, err))
		}
		if err := validateObservation(configured.source, observation, s.capability); err != nil {
			return Result{}, err
		}
		for _, kind := range observation.Metadata.Kinds() {
			if previousSource, exists := metadataSources[kind]; exists {
				return Result{}, fmt.Errorf(
					"%w: analyzers %q and %q produced duplicate %s metadata",
					ErrInvalidObservation, previousSource, configured.source, kind,
				)
			}
			metadataSources[kind] = configured.source
		}
		// The canonical status is classified before the terminal event so
		// progress observers see the same complete/partial/failed semantics
		// as the report, and only after every contract check passes so a
		// violating analyzer never reports as finished.
		observation = observation.Clone()
		status := AnalyzerStatusComplete
		if analyzerErr != nil {
			status = AnalyzerStatusFailed
			if len(observation.Signals) > 0 || !observation.Metadata.Empty() {
				status = AnalyzerStatusPartial
			}
		}
		s.emit(ScanEvent{Source: configured.source, Kind: ScanEventFinished, Status: status})
		if analyzerErr != nil && configured.policy == FailurePolicyAbort {
			return Result{}, fmt.Errorf("analyzer %q: %w", configured.source, analyzerErr)
		}

		result.Analyzers = append(result.Analyzers, AnalyzerResult{
			Observation: observation, Status: status, Err: analyzerErr,
		})
		result.Signals = append(result.Signals, observation.Signals...)
	}

	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("scan canceled before detector evaluation: %w", err)
	}
	detections, err := scoring.Evaluate(s.ruleSet, result.Signals)
	if err != nil {
		return Result{}, fmt.Errorf("evaluate detectors: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("scan canceled during detector evaluation: %w", err)
	}
	result.Detections = detections
	coverage, err := buildDetectionCoverage(s.ruleSet, detections, result.Analyzers, result.Signals, s.capability)
	if err != nil {
		return Result{}, fmt.Errorf("evaluate coverage: %w", err)
	}
	result.Coverage = coverage
	return result, nil
}

func buildDetectionCoverage(
	ruleSet rules.RuleSet,
	detections []scoring.Detection,
	analyzers []AnalyzerResult,
	signals []model.Signal,
	capabilities rules.CapabilityRegistry,
) ([]DetectionCoverage, error) {
	completeCapability := buildCapabilityCompleter(analyzers)

	detectionsByID := make(map[string]scoring.Detection, len(detections))
	for _, det := range detections {
		detectionsByID[det.RuleID] = det
	}

	ruleByID := make(map[string]rules.Rule, len(ruleSet.Rules))
	for _, rule := range ruleSet.Rules {
		ruleByID[rule.ID] = rule
	}

	conditionResults := make(map[string]rules.ConditionCoverageResult, len(ruleSet.Rules))
	for _, rule := range ruleSet.Rules {
		cRes, err := rules.EvaluateConditionCoverage(rule.Match, signals, capabilities, completeCapability)
		if err != nil {
			return nil, fmt.Errorf("evaluate coverage for rule %q: %w", rule.ID, err)
		}
		conditionResults[rule.ID] = cRes
	}

	type ruleCoverageState struct {
		status            DetectionStatus
		incompleteSources []string
		requiredSources   []string
	}

	evaluated := make(map[string]ruleCoverageState, len(ruleSet.Rules))
	visiting := make(map[string]bool, len(ruleSet.Rules))

	var evalRule func(string) ruleCoverageState
	evalRule = func(id string) ruleCoverageState {
		if state, ok := evaluated[id]; ok {
			return state
		}
		if visiting[id] {
			return ruleCoverageState{status: DetectionStatusNotDetected}
		}
		visiting[id] = true
		defer func() { delete(visiting, id) }()

		rule := ruleByID[id]
		det := detectionsByID[id]
		cRes := conditionResults[id]

		if det.Detected {
			state := ruleCoverageState{
				status:            DetectionStatusDetected,
				incompleteSources: nil,
				requiredSources:   cRes.RequiredSources,
			}
			evaluated[id] = state
			return state
		}

		observedPenalties := 0.0
		for _, ne := range det.NegativeEvidence {
			if ne.RawContribution < 0 {
				observedPenalties += -ne.RawContribution
			} else {
				observedPenalties += ne.RawContribution
			}
		}
		for _, ae := range det.AmbiguousEvidence {
			if ae.RawContribution < 0 {
				observedPenalties += -ae.RawContribution
			} else {
				observedPenalties += ae.RawContribution
			}
		}
		for _, ac := range det.AppliedConflicts {
			observedPenalties += ac.Penalty
		}

		ruleCovState, ruleIncomplete := rules.EvaluateRuleCoverage(rule, cRes, det.Detected, observedPenalties)

		depUnknown := false
		depNotDetected := false
		var depIncomplete []string
		var allRequired []string
		allRequired = append(allRequired, cRes.RequiredSources...)

		for _, depID := range rule.Requires {
			depState := evalRule(depID)
			allRequired = append(allRequired, depState.requiredSources...)
			if depState.status == DetectionStatusInsufficientCoverage {
				depUnknown = true
				depIncomplete = append(depIncomplete, depState.incompleteSources...)
			} else if depState.status == DetectionStatusNotDetected {
				depNotDetected = true
			}
		}

		if ruleCovState == rules.CoverageStateNotMatched {
			state := ruleCoverageState{
				status:            DetectionStatusNotDetected,
				incompleteSources: nil,
				requiredSources:   deduplicateSorted(allRequired),
			}
			evaluated[id] = state
			return state
		}

		if depNotDetected {
			state := ruleCoverageState{
				status:            DetectionStatusNotDetected,
				incompleteSources: nil,
				requiredSources:   deduplicateSorted(allRequired),
			}
			evaluated[id] = state
			return state
		}

		if depUnknown {
			var combinedIncomplete []string
			combinedIncomplete = append(combinedIncomplete, ruleIncomplete...)
			combinedIncomplete = append(combinedIncomplete, depIncomplete...)
			state := ruleCoverageState{
				status:            DetectionStatusInsufficientCoverage,
				incompleteSources: deduplicateSorted(combinedIncomplete),
				requiredSources:   deduplicateSorted(allRequired),
			}
			evaluated[id] = state
			return state
		}

		if ruleCovState == rules.CoverageStateUnknown {
			state := ruleCoverageState{
				status:            DetectionStatusInsufficientCoverage,
				incompleteSources: deduplicateSorted(ruleIncomplete),
				requiredSources:   deduplicateSorted(allRequired),
			}
			evaluated[id] = state
			return state
		}

		state := ruleCoverageState{
			status:            DetectionStatusNotDetected,
			incompleteSources: nil,
			requiredSources:   deduplicateSorted(allRequired),
		}
		evaluated[id] = state
		return state
	}

	coverage := make([]DetectionCoverage, 0, len(ruleSet.Rules))
	for _, rule := range ruleSet.Rules {
		state := evalRule(rule.ID)
		coverage = append(coverage, DetectionCoverage{
			RuleID:            rule.ID,
			Status:            state.status,
			RequiredSources:   state.requiredSources,
			IncompleteSources: state.incompleteSources,
		})
	}
	return coverage, nil
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

// buildCapabilityCompleter combines declared per-capability coverage with
// analyzer execution status into the capability lookup consumed by rule
// coverage evaluation. An analyzer that declared any capability coverage is
// treated as capability-aware: only its explicit declarations can report
// completeness, and an undeclared capability is never complete because
// analyzer-wide success must not imply that an unobserved channel was
// conclusively evaluated. Analyzers without declarations keep their previous
// analyzer-status semantics so analyzers without bounded evidence channels
// remain usable.
func buildCapabilityCompleter(analyzers []AnalyzerResult) rules.CapabilityCompleter {
	declared := make(map[model.SignalType]map[string]bool)
	statuses := make(map[string]bool, len(analyzers))
	capabilityAware := make(map[string]bool, len(analyzers))
	for _, analyzer := range analyzers {
		source := analyzer.Observation.Source
		statuses[source] = analyzer.Status == AnalyzerStatusComplete
		if len(analyzer.Observation.Capabilities) > 0 {
			capabilityAware[source] = true
		}
		for _, capability := range analyzer.Observation.Capabilities {
			bySource, ok := declared[capability.SignalType]
			if !ok {
				bySource = make(map[string]bool)
				declared[capability.SignalType] = bySource
			}
			bySource[source] = capability.Status == analysis.CapabilityComplete
		}
	}
	return func(source string, signalType model.SignalType) bool {
		if capabilityAware[source] {
			return declared[signalType][source]
		}
		return statuses[source]
	}
}

func priorObservations(results []AnalyzerResult) []analysis.Observation {
	prior := make([]analysis.Observation, 0, len(results))
	for _, result := range results {
		prior = append(prior, result.Observation.Clone())
	}
	return prior
}

func validateObservation(
	source string,
	observation analysis.Observation,
	capabilities rules.CapabilityRegistry,
) error {
	if observation.Source != source {
		return fmt.Errorf("%w: analyzer %q returned source %q", ErrInvalidObservation, source, observation.Source)
	}
	for index, signal := range observation.Signals {
		if err := signal.Validate(); err != nil {
			return fmt.Errorf("%w: analyzer %q signal %d: %w", ErrInvalidObservation, source, index, err)
		}
		if signal.Source != source {
			return fmt.Errorf(
				"%w: analyzer %q signal %d returned source %q",
				ErrInvalidObservation, source, index, signal.Source,
			)
		}
		if !capabilities.Supports(source, signal.Type) {
			return fmt.Errorf(
				"%w: analyzer %q signal %d uses undeclared capability %q",
				ErrInvalidObservation, source, index, signal.Type,
			)
		}
	}
	declared := make(map[model.SignalType]struct{}, len(observation.Capabilities))
	for index, capability := range observation.Capabilities {
		if err := capability.Validate(); err != nil {
			return fmt.Errorf("%w: analyzer %q capability %d: %w", ErrInvalidObservation, source, index, err)
		}
		if _, duplicate := declared[capability.SignalType]; duplicate {
			return fmt.Errorf(
				"%w: analyzer %q declared capability %q more than once",
				ErrInvalidObservation, source, capability.SignalType,
			)
		}
		if !capabilities.Supports(source, capability.SignalType) {
			return fmt.Errorf(
				"%w: analyzer %q coverage %d uses undeclared capability %q",
				ErrInvalidObservation, source, index, capability.SignalType,
			)
		}
		declared[capability.SignalType] = struct{}{}
	}
	return nil
}
