package detectors

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

func TestBuiltInRulesComplyWithSupportStandard(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSupportStandard(ruleSet); err != nil {
		t.Fatalf("ValidateSupportStandard() failed for built-in rules: %v", err)
	}
}

func TestValidateSupportStandardRejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		modify func(*rules.RuleSet)
	}{
		{
			name: "empty rules",
			modify: func(rs *rules.RuleSet) {
				rs.Rules = nil
			},
		},
		{
			name: "invalid id format without dot",
			modify: func(rs *rules.RuleSet) {
				rs.Rules[0].ID = "nodot"
			},
		},
		{
			name: "missing description",
			modify: func(rs *rules.RuleSet) {
				rs.Rules[0].Description = ""
			},
		},
		{
			name: "missing vendor",
			modify: func(rs *rules.RuleSet) {
				rs.Rules[0].Vendor = ""
			},
		},
		{
			name: "product category missing product",
			modify: func(rs *rules.RuleSet) {
				rs.Rules[0].Category = rules.CategoryCAPTCHAChallenge
				rs.Rules[0].Product = ""
			},
		},
		{
			name: "minimum score too low",
			modify: func(rs *rules.RuleSet) {
				rs.Rules[0].MinimumScore = 10
			},
		},
		{
			name: "minimum evidence too high for available groups",
			modify: func(rs *rules.RuleSet) {
				rs.Rules[0].MinimumEvidence = 10
			},
		},
		{
			name: "max achievable score less than minimum_score",
			modify: func(rs *rules.RuleSet) {
				rs.Rules[0].MinimumScore = 95
				rs.Rules[0].Match.Any[0].Signal.Weight = 40
				rs.Rules[0].Match.Any[1].Signal.Weight = 40
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ruleSet, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			tc.modify(&ruleSet)
			if err := ValidateSupportStandard(ruleSet); !errors.Is(err, ErrSupportStandardViolation) {
				t.Fatalf("ValidateSupportStandard() error = %v, want ErrSupportStandardViolation", err)
			}
		})
	}
}

func TestBuiltInRulesHaveRequiredFixtureCoverage(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	type fixtureCase struct {
		Name     string              `json:"name"`
		Fixture  string              `json:"fixture"`
		Detected []string            `json:"detected"`
		Scores   map[string]float64  `json:"scores"`
		Levels   map[string]string   `json:"levels"`
		Evidence map[string][]string `json:"evidence"`
	}

	manifestPath := filepath.Join("..", "scanner", "testdata", "cases.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	var cases []fixtureCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}

	for _, rule := range ruleSet.Rules {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			t.Parallel()
			var (
				hasPositive            bool
				hasNegative            bool
				hasAmbiguityRegression bool
			)

			for _, c := range cases {
				isDetected := slices.Contains(c.Detected, rule.ID)
				score := c.Scores[rule.ID]

				if isDetected && score >= rule.MinimumScore {
					hasPositive = true
				}
				if !isDetected && score == 0 {
					hasNegative = true
				}
				if !isDetected && score > 0 && score < rule.MinimumScore {
					hasAmbiguityRegression = true
				}
			}

			if !hasPositive {
				t.Errorf("rule %q lacks a positive fixture case with score >= %v", rule.ID, rule.MinimumScore)
			}
			if !hasNegative {
				t.Errorf("rule %q lacks a negative fixture case with score == 0", rule.ID)
			}
			if !hasAmbiguityRegression {
				t.Errorf("rule %q lacks an ambiguity/regression fixture case with 0 < score < %v", rule.ID, rule.MinimumScore)
			}
		})
	}
}

func TestSupportingEvidenceAloneCannotTriggerDetection(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	for _, rule := range ruleSet.Rules {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			t.Parallel()
			var supportingSignals []model.Signal

			var collectSupporting func(c rules.Condition)
			collectSupporting = func(c rules.Condition) {
				if c.Signal != nil {
					if c.Signal.Weight < rule.MinimumScore {
						sig := model.Signal{
							Type:       c.Signal.Type,
							Source:     analysis.SourceHTTP,
							Key:        "marker",
							Value:      "sample-marker",
							Confidence: 1.0,
						}
						if c.Signal.Key != nil && c.Signal.Key.Exact != nil {
							sig.Key = *c.Signal.Key.Exact
						}
						if c.Signal.Value != nil && c.Signal.Value.Exact != nil {
							sig.Value = *c.Signal.Value.Exact
						}
						supportingSignals = append(supportingSignals, sig)
					}
					return
				}
				for _, child := range c.All {
					collectSupporting(child)
				}
				for _, child := range c.Any {
					collectSupporting(child)
				}
			}

			collectSupporting(rule.Match)

			if len(supportingSignals) == 0 {
				t.Logf("rule %q has no supporting-only signals", rule.ID)
				return
			}

			detections, err := scoring.Evaluate(rules.RuleSet{
				SchemaVersion: rules.CurrentSchemaVersion,
				Rules:         []rules.Rule{rule},
			}, supportingSignals)
			if err != nil {
				t.Fatal(err)
			}

			if detections[0].Detected {
				t.Errorf("rule %q was detected from supporting signals alone: score = %v", rule.ID, detections[0].Score)
			}
			if detections[0].Score >= rule.MinimumScore {
				t.Errorf("rule %q score (%v) >= minimum_score (%v) from supporting signals alone", rule.ID, detections[0].Score, rule.MinimumScore)
			}
		})
	}
}

func TestVendorSignalsDoNotIncurProductDetections(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	vendorSignals := []model.Signal{
		{
			Type:       model.SignalTypeResponseHeader,
			Source:     analysis.SourceHTTP,
			Key:        "Server",
			Value:      "cloudflare",
			Confidence: 1.0,
		},
		{
			Type:       model.SignalTypeDNSRecord,
			Source:     analysis.SourceDNSTLS,
			Key:        "cname",
			Value:      "example.cdn.cloudflare.net",
			Confidence: 1.0,
		},
		{
			Type:       model.SignalTypeResponseHeader,
			Source:     analysis.SourceHTTP,
			Key:        "Server",
			Value:      "gws",
			Confidence: 1.0,
		},
	}

	detections, err := scoring.Evaluate(ruleSet, vendorSignals)
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range detections {
		if d.Detected {
			t.Errorf("vendor infrastructure signals triggered product detection %q (score = %v)", d.RuleID, d.Score)
		}
		if d.Score != 0 {
			t.Errorf("vendor infrastructure signals produced non-zero score for %q (score = %v)", d.RuleID, d.Score)
		}
	}
}

func TestBuiltInRulesAreDocumentedInSupportStandard(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	docPath := filepath.Join("..", "..", "docs", "detector-support-standard.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}
	docContent := string(data)

	for _, rule := range ruleSet.Rules {
		if !strings.Contains(docContent, rule.ID) {
			t.Errorf("rule %q is not mentioned in %s", rule.ID, docPath)
		}
		if !strings.Contains(docContent, rule.Vendor) {
			t.Errorf("rule vendor %q is not mentioned in %s", rule.Vendor, docPath)
		}
		if rule.Product != "" && !strings.Contains(docContent, rule.Product) {
			t.Errorf("rule product %q is not mentioned in %s", rule.Product, docPath)
		}
	}
}
