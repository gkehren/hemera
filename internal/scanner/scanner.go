// Package scanner orchestrates analyzers, detector matching, and scoring.
package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scoring"
)

var (
	// ErrInvalidConfig identifies missing or invalid scanner dependencies.
	ErrInvalidConfig = errors.New("invalid scanner configuration")
)

// HTTPAnalyzer is the observation boundary required by Scanner.
type HTTPAnalyzer interface {
	Analyze(context.Context, string) (httpanalyzer.Result, error)
}

// Result contains raw HTTP observations and scored detector results.
type Result struct {
	HTTP       httpanalyzer.Result
	Detections []scoring.Detection
}

// Scanner coordinates one analyzer and a validated detector rule set.
type Scanner struct {
	analyzer HTTPAnalyzer
	ruleSet  rules.RuleSet
}

// New validates the scanner dependencies.
func New(analyzer HTTPAnalyzer, ruleSet rules.RuleSet) (*Scanner, error) {
	if analyzer == nil {
		return nil, fmt.Errorf("%w: HTTP analyzer is required", ErrInvalidConfig)
	}
	if err := ruleSet.Validate(); err != nil {
		return nil, fmt.Errorf("%w: detector rules: %w", ErrInvalidConfig, err)
	}
	return &Scanner{analyzer: analyzer, ruleSet: ruleSet}, nil
}

// Scan performs one HTTP analysis and evaluates every configured detector.
func (s *Scanner) Scan(ctx context.Context, rawURL string) (Result, error) {
	httpResult, err := s.analyzer.Analyze(ctx, rawURL)
	if err != nil {
		return Result{}, err
	}
	detections, err := scoring.Evaluate(s.ruleSet, httpResult.Signals)
	if err != nil {
		return Result{}, fmt.Errorf("evaluate detectors: %w", err)
	}
	return Result{HTTP: httpResult, Detections: detections}, nil
}
