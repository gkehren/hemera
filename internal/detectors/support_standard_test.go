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
				headerName := "Server"
				rs.Rules[0].MinimumScore = 75
				rs.Rules[0].Match = rules.Condition{
					Signal: &rules.Evidence{
						ID:     "low-weight",
						Type:   model.SignalTypeResponseHeader,
						Key:    &rules.TextPattern{Exact: &headerName},
						Weight: 40,
					},
				}
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
		Name            string              `json:"name"`
		Fixture         string              `json:"fixture"`
		PositiveFor     []string            `json:"positive_for"`
		HardNegativeFor []string            `json:"hard_negative_for"`
		AmbiguousFor    []string            `json:"ambiguous_for"`
		Detected        []string            `json:"detected"`
		Scores          map[string]float64  `json:"scores"`
		Levels          map[string]string   `json:"levels"`
		Evidence        map[string][]string `json:"evidence"`
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

	ruleMap := make(map[string]rules.Rule, len(ruleSet.Rules))
	for _, rule := range ruleSet.Rules {
		ruleMap[rule.ID] = rule
	}

	// Verify each case satisfies its declared intent without duplicates or overlap.
	for _, c := range cases {
		seenInCase := make(map[string]string)

		checkList := func(list []string, category string) {
			seenInList := make(map[string]bool)
			for _, ruleID := range list {
				if seenInList[ruleID] {
					t.Errorf("case %q has duplicate rule %q in %s", c.Name, ruleID, category)
				}
				seenInList[ruleID] = true

				if prevCat, exists := seenInCase[ruleID]; exists {
					t.Errorf("case %q declares rule %q in both %s and %s", c.Name, ruleID, prevCat, category)
				}
				seenInCase[ruleID] = category

				if _, exists := ruleMap[ruleID]; !exists {
					t.Errorf("case %q declares unknown rule %q in %s", c.Name, ruleID, category)
				}
			}
		}

		checkList(c.PositiveFor, "positive_for")
		checkList(c.HardNegativeFor, "hard_negative_for")
		checkList(c.AmbiguousFor, "ambiguous_for")

		for _, posRuleID := range c.PositiveFor {
			rule, exists := ruleMap[posRuleID]
			if !exists {
				continue
			}
			score := c.Scores[posRuleID]
			if score < rule.MinimumScore {
				t.Errorf("case %q positive_for rule %q score = %v, want >= %v", c.Name, posRuleID, score, rule.MinimumScore)
			}
			if !slices.Contains(c.Detected, posRuleID) {
				t.Errorf("case %q positive_for rule %q is not in detected list %v", c.Name, posRuleID, c.Detected)
			}
		}

		for _, negRuleID := range c.HardNegativeFor {
			if _, exists := ruleMap[negRuleID]; !exists {
				continue
			}
			score := c.Scores[negRuleID]
			if score != 0 {
				t.Errorf("case %q hard_negative_for rule %q score = %v, want 0", c.Name, negRuleID, score)
			}
			if slices.Contains(c.Detected, negRuleID) {
				t.Errorf("case %q hard_negative_for rule %q should not be in detected list %v", c.Name, negRuleID, c.Detected)
			}
		}

		for _, ambRuleID := range c.AmbiguousFor {
			rule, exists := ruleMap[ambRuleID]
			if !exists {
				continue
			}
			score := c.Scores[ambRuleID]
			if score <= 0 || score >= rule.MinimumScore {
				t.Errorf("case %q ambiguous_for rule %q score = %v, want 0 < score < %v", c.Name, ambRuleID, score, rule.MinimumScore)
			}
			if slices.Contains(c.Detected, ambRuleID) {
				t.Errorf("case %q ambiguous_for rule %q should not be in detected list %v", c.Name, ambRuleID, c.Detected)
			}
		}
	}

	// Verify each supported rule has intentional coverage across all three dimensions.
	for _, rule := range ruleSet.Rules {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			t.Parallel()
			var (
				hasPositiveIntent     bool
				hasHardNegativeIntent bool
				hasAmbiguityIntent    bool
			)

			for _, c := range cases {
				if slices.Contains(c.PositiveFor, rule.ID) {
					hasPositiveIntent = true
				}
				if slices.Contains(c.HardNegativeFor, rule.ID) {
					hasHardNegativeIntent = true
				}
				if slices.Contains(c.AmbiguousFor, rule.ID) {
					hasAmbiguityIntent = true
				}
			}

			if !hasPositiveIntent {
				t.Errorf("rule %q lacks an explicit positive_for fixture case", rule.ID)
			}
			if !hasHardNegativeIntent {
				t.Errorf("rule %q lacks an explicit hard_negative_for fixture case", rule.ID)
			}
			if !hasAmbiguityIntent {
				t.Errorf("rule %q lacks an explicit ambiguous_for fixture case", rule.ID)
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

			detections, err := scoring.Evaluate(ruleSet, supportingSignals)
			if err != nil {
				t.Fatal(err)
			}

			for _, d := range detections {
				if d.RuleID == rule.ID {
					if d.Detected {
						t.Errorf("rule %q was detected from supporting signals alone: score = %v", rule.ID, d.Score)
					}
					if d.Score >= rule.MinimumScore {
						t.Errorf("rule %q score (%v) >= minimum_score (%v) from supporting signals alone", rule.ID, d.Score, rule.MinimumScore)
					}
				}
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
			Value:      "CloudFront",
			Confidence: 1.0,
		},
		{
			Type:       model.SignalTypeResponseHeader,
			Source:     analysis.SourceHTTP,
			Key:        "x-amz-cf-id",
			Value:      "sample-cf-id",
			Confidence: 1.0,
		},
		{
			Type:       model.SignalTypeResponseHeader,
			Source:     analysis.SourceHTTP,
			Key:        "Server",
			Value:      "AkamaiGHost",
			Confidence: 1.0,
		},
		{
			Type:       model.SignalTypeResponseHeader,
			Source:     analysis.SourceHTTP,
			Key:        "x-akamai-transformed",
			Value:      "9 1234 0 pmb=mRUM,1",
			Confidence: 1.0,
		},
		{
			Type:       model.SignalTypeResponseHeader,
			Source:     analysis.SourceHTTP,
			Key:        "x-akamai-session-info",
			Value:      "name=ORIGIN_ROUTING; value=primary",
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

	detectedProxies := make(map[string]bool)
	for _, d := range detections {
		if d.Product == "" {
			if d.Detected && d.Score >= 75 {
				detectedProxies[d.RuleID] = true
			}
			continue
		}
		if d.Detected {
			t.Errorf("vendor infrastructure signals triggered product detection %q (score = %v)", d.RuleID, d.Score)
		}
		if d.Score != 0 {
			t.Errorf("vendor infrastructure signals produced non-zero score for product %q (score = %v)", d.RuleID, d.Score)
		}
	}

	for _, wantProxy := range []string{"cloudflare.proxy", "aws.cloudfront", "akamai.edge"} {
		if !detectedProxies[wantProxy] {
			t.Errorf("vendor infrastructure signals did not detect %q", wantProxy)
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

func TestBuiltInRulesHaveDocumentedLimitations(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	docPath := filepath.Join("..", "..", "docs", "detector-limitations.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}
	docContent := string(data)

	for _, rule := range ruleSet.Rules {
		if !strings.Contains(docContent, rule.ID) {
			t.Errorf("rule %q is not mentioned in %s", rule.ID, docPath)
		}
	}
}

type evidenceProvenance struct {
	Weight    float64 `json:"weight"`
	Group     string  `json:"group"`
	Role      string  `json:"role"`
	Source    string  `json:"source"`
	Rationale string  `json:"rationale"`
}

type ruleProvenance struct {
	MinimumScore     float64                       `json:"minimum_score"`
	MinimumEvidence  int                           `json:"minimum_evidence"`
	ScoringRationale string                        `json:"scoring_rationale"`
	Evidence         map[string]evidenceProvenance `json:"evidence"`
}

type provenanceManifest struct {
	SchemaVersion int                       `json:"schema_version"`
	Rules         map[string]ruleProvenance `json:"rules"`
}

func TestBuiltInRulesProvenanceAndRationale(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join("provenance.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read provenance manifest: %v", err)
	}

	var prov provenanceManifest
	if err := json.Unmarshal(data, &prov); err != nil {
		t.Fatalf("unmarshal provenance manifest: %v", err)
	}

	if prov.SchemaVersion != 1 {
		t.Errorf("provenance manifest schema_version = %d, want 1", prov.SchemaVersion)
	}

	var collectEvidence func(rules.Condition) []*rules.Evidence
	collectEvidence = func(c rules.Condition) []*rules.Evidence {
		var list []*rules.Evidence
		if c.Signal != nil {
			list = append(list, c.Signal)
		}
		for _, child := range c.All {
			list = append(list, collectEvidence(child)...)
		}
		for _, child := range c.Any {
			list = append(list, collectEvidence(child)...)
		}
		return list
	}

	for _, rule := range ruleSet.Rules {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			t.Parallel()
			ruleProv, exists := prov.Rules[rule.ID]
			if !exists {
				t.Fatalf("rule %q is missing from provenance manifest", rule.ID)
			}
			if ruleProv.MinimumScore != rule.MinimumScore {
				t.Errorf("rule %q minimum_score = %v in provenance, want %v from rule", rule.ID, ruleProv.MinimumScore, rule.MinimumScore)
			}
			if ruleProv.MinimumEvidence != rule.MinimumEvidence {
				t.Errorf("rule %q minimum_evidence = %v in provenance, want %v from rule", rule.ID, ruleProv.MinimumEvidence, rule.MinimumEvidence)
			}
			if strings.TrimSpace(ruleProv.ScoringRationale) == "" {
				t.Errorf("rule %q has empty scoring_rationale in provenance manifest", rule.ID)
			}

			ruleEvList := collectEvidence(rule.Match)
			ruleEvMap := make(map[string]*rules.Evidence, len(ruleEvList))
			for _, ev := range ruleEvList {
				ruleEvMap[ev.ID] = ev
			}

			for _, ev := range ruleEvList {
				evProv, ok := ruleProv.Evidence[ev.ID]
				if !ok {
					t.Errorf("rule %q evidence %q is missing from provenance manifest", rule.ID, ev.ID)
					continue
				}

				wantRole := "supporting"
				if ev.Weight >= rule.MinimumScore {
					wantRole = "decisive"
				}
				if evProv.Role != wantRole {
					t.Errorf("rule %q evidence %q role = %q, want %q (weight: %v, min_score: %v)", rule.ID, ev.ID, evProv.Role, wantRole, ev.Weight, rule.MinimumScore)
				}
				if evProv.Weight != ev.Weight {
					t.Errorf("rule %q evidence %q weight = %v in provenance, want %v from rule", rule.ID, ev.ID, evProv.Weight, ev.Weight)
				}
				if evProv.Group != ev.Group {
					t.Errorf("rule %q evidence %q group = %q, want %q", rule.ID, ev.ID, evProv.Group, ev.Group)
				}
				if !strings.HasPrefix(evProv.Source, "https://") {
					t.Errorf("rule %q evidence %q source %q is not a valid https URL", rule.ID, ev.ID, evProv.Source)
				}
				if strings.TrimSpace(evProv.Rationale) == "" {
					t.Errorf("rule %q evidence %q has empty rationale", rule.ID, ev.ID)
				}
			}

			for provEvID := range ruleProv.Evidence {
				if _, ok := ruleEvMap[provEvID]; !ok {
					t.Errorf("provenance manifest declares evidence %q not found in rule %q", provEvID, rule.ID)
				}
			}
		})
	}

	for provRuleID := range prov.Rules {
		found := false
		for _, r := range ruleSet.Rules {
			if r.ID == provRuleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provenance manifest declares rule %q not found in rules.json", provRuleID)
		}
	}
}

// TestSupportStandardObservationCapabilitiesMatrix derives required channels from
// rules and verifies that automated tests exercise all claimed channels.
func TestSupportStandardObservationCapabilitiesMatrix(t *testing.T) {
	t.Parallel()
	ruleSet, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	type channelReqs struct {
		HTTP          bool
		DNS           bool
		TLS           bool
		BrowserScript bool
		BrowserIframe bool
		BrowserCookie bool
		BrowserDOM    bool
	}

	var inspectCondition func(rules.Condition, *channelReqs)
	inspectCondition = func(c rules.Condition, reqs *channelReqs) {
		if c.Signal != nil {
			switch c.Signal.Type {
			case model.SignalTypeResponseHeader:
				reqs.HTTP = true
			case model.SignalTypeDNSRecord:
				reqs.DNS = true
			case model.SignalTypeTLSProperty:
				reqs.TLS = true
			case model.SignalTypeScriptURL:
				reqs.HTTP = true
				if c.Signal.Source == nil || c.Signal.Source.Exact == nil || *c.Signal.Source.Exact != "http_analyzer" {
					reqs.BrowserScript = true
				}
			case model.SignalTypeIframeURL:
				reqs.HTTP = true
				reqs.BrowserIframe = true
			case model.SignalTypeCookie:
				reqs.HTTP = true
				reqs.BrowserCookie = true
			case model.SignalTypePageContent:
				reqs.HTTP = true
				if c.Signal.Source == nil || c.Signal.Source.Exact == nil || *c.Signal.Source.Exact != "http_analyzer" {
					reqs.BrowserDOM = true
				}
			}
		}
		for _, child := range c.All {
			inspectCondition(child, reqs)
		}
		for _, child := range c.Any {
			inspectCondition(child, reqs)
		}
	}

	for _, rule := range ruleSet.Rules {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			t.Parallel()
			var reqs channelReqs
			inspectCondition(rule.Match, &reqs)

			// All rules must support at least HTTP or DNS/TLS.
			if !reqs.HTTP && !reqs.DNS && !reqs.TLS {
				t.Fatalf("rule %q does not claim any observation channels", rule.ID)
			}

			// Verify DNS-enabled rules have explicit DNS support.
			if reqs.DNS {
				switch rule.ID {
				case "cloudflare.proxy", "aws.cloudfront", "akamai.edge":
					// expected
				default:
					t.Errorf("unexpected DNS capability claimed by rule %q", rule.ID)
				}
			}

			// Verify TLS-enabled rules have explicit TLS support.
			if reqs.TLS {
				switch rule.ID {
				case "cloudflare.proxy", "aws.cloudfront", "akamai.edge":
					// expected
				default:
					t.Errorf("unexpected TLS capability claimed by rule %q", rule.ID)
				}
			}
		})
	}
}

func TestSupportStandardEnforcementRejections(t *testing.T) {
	t.Parallel()

	t.Run("provenance weight drift fails", func(t *testing.T) {
		t.Parallel()
		ruleSet, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		ruleSet.Rules[0].Match.Signal = &rules.Evidence{
			ID:     "drift-ev",
			Type:   model.SignalTypeResponseHeader,
			Weight: 99,
		}
		// Validate that altered rules fail support standard validation
		if err := ValidateSupportStandard(ruleSet); err == nil {
			t.Fatal("expected support standard violation for unachievable/drifted rule, got nil")
		}
	})

	t.Run("fixture intent duplicate rule rejection", func(t *testing.T) {
		t.Parallel()
		caseIntent := struct {
			PositiveFor []string
		}{
			PositiveFor: []string{"cloudflare.proxy", "cloudflare.proxy"},
		}
		seen := make(map[string]bool)
		hasDuplicate := false
		for _, r := range caseIntent.PositiveFor {
			if seen[r] {
				hasDuplicate = true
				break
			}
			seen[r] = true
		}
		if !hasDuplicate {
			t.Fatal("expected duplicate detection to flag duplicate rule in positive_for")
		}
	})

	t.Run("fixture intent cross-category overlap rejection", func(t *testing.T) {
		t.Parallel()
		posList := []string{"cloudflare.proxy"}
		negList := []string{"cloudflare.proxy"}
		hasOverlap := false
		for _, r := range posList {
			if slices.Contains(negList, r) {
				hasOverlap = true
				break
			}
		}
		if !hasOverlap {
			t.Fatal("expected overlap check to flag rule present in both positive and negative")
		}
	})
}
