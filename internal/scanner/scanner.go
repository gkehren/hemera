// Package scanner orchestrates analyzers, detector matching, and scoring.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	Observe(context.Context, analysis.Target) (analysis.Observation, error)
}

// AnalyzerConfig binds one analyzer to its local failure policy. Entries run
// sequentially in slice order.
type AnalyzerConfig struct {
	Analyzer      Analyzer
	FailurePolicy FailurePolicy
}

// Config contains the ordered analyzer pipeline and validated detector rules.
type Config struct {
	Analyzers []AnalyzerConfig
	RuleSet   rules.RuleSet
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

// DetectionStatus distinguishes a negative result from a result that could not
// be evaluated because a source required by every rule branch was incomplete.
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
	analyzers []configuredAnalyzer
	ruleSet   rules.RuleSet
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
		sources[source] = struct{}{}
		configured = append(configured, configuredAnalyzer{
			analyzer: entry.Analyzer, source: source, policy: entry.FailurePolicy,
		})
	}

	return &Scanner{analyzers: configured, ruleSet: config.RuleSet}, nil
}

func analyzerIsNil(analyzer Analyzer) bool {
	if analyzer == nil {
		return true
	}
	value := reflect.ValueOf(analyzer)
	return value.Kind() == reflect.Pointer && value.IsNil()
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
		observation, analyzerErr := configured.analyzer.Observe(ctx, target)
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("analyzer %q canceled: %w", configured.source, errors.Join(analyzerErr, err))
		}
		if err := validateObservation(configured.source, observation); err != nil {
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

		observation = observation.Clone()
		status := AnalyzerStatusComplete
		if analyzerErr != nil {
			if configured.policy == FailurePolicyAbort {
				return Result{}, fmt.Errorf("analyzer %q: %w", configured.source, analyzerErr)
			}
			status = AnalyzerStatusFailed
			if len(observation.Signals) > 0 || !observation.Metadata.Empty() {
				status = AnalyzerStatusPartial
			}
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
	result.Coverage = buildDetectionCoverage(s.ruleSet, detections, result.Analyzers)
	return result, nil
}

func buildDetectionCoverage(ruleSet rules.RuleSet, detections []scoring.Detection, analyzers []AnalyzerResult) []DetectionCoverage {
	statusBySource := make(map[string]AnalyzerStatus, len(analyzers))
	for _, analyzer := range analyzers {
		statusBySource[analyzer.Observation.Source] = analyzer.Status
	}
	coverage := make([]DetectionCoverage, 0, len(ruleSet.Rules))
	for index, rule := range ruleSet.Rules {
		required := rules.RequiredSources(rule, ruleSet)
		incomplete := make([]string, 0, len(required))
		for _, source := range required {
			if status, ok := statusBySource[source]; !ok || status != AnalyzerStatusComplete {
				incomplete = append(incomplete, source)
			}
		}
		status := DetectionStatusNotDetected
		if index < len(detections) && detections[index].Detected {
			status = DetectionStatusDetected
		} else if len(incomplete) > 0 {
			status = DetectionStatusInsufficientCoverage
		}
		coverage = append(coverage, DetectionCoverage{
			RuleID: rule.ID, Status: status, RequiredSources: required, IncompleteSources: incomplete,
		})
	}
	return coverage
}

func priorObservations(results []AnalyzerResult) []analysis.Observation {
	prior := make([]analysis.Observation, 0, len(results))
	for _, result := range results {
		prior = append(prior, result.Observation.Clone())
	}
	return prior
}

func validateObservation(source string, observation analysis.Observation) error {
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
	}
	return nil
}
