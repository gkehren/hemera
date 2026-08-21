// Package report builds safe scan reports and renders them as human-oriented
// text or versioned, deterministic JSON without performing detection.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/safeoutput"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

const (
	// SchemaVersion identifies the current experimental JSON report contract.
	SchemaVersion = 5
)

// Report is the deterministic representation shared by text and JSON renderers.
type Report struct {
	SchemaVersion int               `json:"schema_version"`
	ToolVersion   string            `json:"tool_version"`
	RequestedURL  string            `json:"requested_url"`
	FinalURL      *string           `json:"final_url"`
	HTTP          *HTTP             `json:"http"`
	Analyzers     []AnalyzerReport  `json:"analyzers"`
	Detections    []DetectionReport `json:"detections"`
}

// HTTP contains bounded navigation metadata.
type HTTP struct {
	StatusCode    int        `json:"status_code"`
	BodyTruncated bool       `json:"body_truncated"`
	Redirects     []Redirect `json:"redirects"`
	Warnings      []string   `json:"warnings"`
}

// Redirect is one sanitized navigation redirect.
type Redirect struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status int    `json:"status"`
}

// AnalyzerReport describes deterministic observation coverage without exposing
// analyzer error details that may contain untrusted input.
type AnalyzerReport struct {
	Source   string                 `json:"source"`
	Status   scanner.AnalyzerStatus `json:"status"`
	Warnings []string               `json:"warnings"`
}

// DetectionReport is one fully explained detector result.
type DetectionReport struct {
	ID                     string                  `json:"id"`
	Name                   string                  `json:"name"`
	Category               rules.Category          `json:"category"`
	Vendor                 string                  `json:"vendor"`
	Product                string                  `json:"product,omitempty"`
	Detected               bool                    `json:"detected"`
	Status                 scanner.DetectionStatus `json:"status"`
	IncompleteSources      []string                `json:"incomplete_sources"`
	ConditionMatched       bool                    `json:"condition_matched"`
	MinimumEvidenceMet     bool                    `json:"minimum_evidence_met"`
	EvidenceScore          float64                 `json:"evidence_score"`
	Score                  float64                 `json:"score"`
	Level                  scoring.Level           `json:"level"`
	Evidence               EvidenceReport          `json:"evidence"`
	PositiveEvidenceGroups []EvidenceGroup         `json:"positive_evidence_groups"`
	MissingEvidence        []string                `json:"missing_evidence"`
	MissingDependencies    []string                `json:"missing_dependencies"`
	AppliedConflicts       []ConflictReport        `json:"applied_conflicts"`
}

// EvidenceReport groups evidence by its scoring role.
type EvidenceReport struct {
	Positive  []Evidence `json:"positive"`
	Negative  []Evidence `json:"negative"`
	Ambiguous []Evidence `json:"ambiguous"`
}

// Evidence is a sanitized observation with raw and effective contributions.
type Evidence struct {
	ID              string           `json:"id"`
	Group           string           `json:"group,omitempty"`
	Description     string           `json:"description,omitempty"`
	Type            model.SignalType `json:"type"`
	Source          string           `json:"source"`
	Key             string           `json:"key"`
	Value           string           `json:"value,omitempty"`
	URL             string           `json:"url,omitempty"`
	Confidence      float64          `json:"confidence"`
	Weight          float64          `json:"weight"`
	RawContribution float64          `json:"raw_contribution"`
	Contribution    float64          `json:"contribution"`
}

// EvidenceGroup explains the maximum contribution selected from correlated
// positive evidence.
type EvidenceGroup struct {
	ID                 string   `json:"id"`
	EvidenceIDs        []string `json:"evidence_ids"`
	SelectedEvidenceID string   `json:"selected_evidence_id"`
	RawContribution    float64  `json:"raw_contribution"`
	Contribution       float64  `json:"contribution"`
}

// ConflictReport records one fixed cross-rule score penalty.
type ConflictReport struct {
	RuleID  string  `json:"rule_id"`
	Penalty float64 `json:"penalty"`
}

// Build converts internal scan state into a secret-minimized report.
func Build(toolVersion string, result scanner.Result) Report {
	var httpMetadata *HTTP
	requestedURL := safeoutput.SanitizeURL(result.Target.URL)
	var finalURL *string
	analyzers := make([]AnalyzerReport, 0, len(result.Analyzers))
	for _, analyzerResult := range result.Analyzers {
		observation := analyzerResult.Observation
		analyzers = append(analyzers, AnalyzerReport{
			Source: observation.Source, Status: analyzerResult.Status,
			Warnings: append([]string{}, observation.Warnings...),
		})
		if observation.Metadata.HTTP == nil {
			continue
		}
		metadata := observation.Metadata.HTTP
		requestedURL = safeoutput.SanitizeURL(metadata.RequestedURL)
		if sanitizedFinalURL := safeoutput.SanitizeURL(metadata.FinalURL); sanitizedFinalURL != "" {
			finalURL = &sanitizedFinalURL
		}
		httpMetadata = &HTTP{
			StatusCode: metadata.StatusCode, BodyTruncated: metadata.BodyTruncated,
			Redirects: make([]Redirect, 0, len(metadata.Redirects)),
			Warnings:  append([]string{}, observation.Warnings...),
		}
		for _, redirect := range metadata.Redirects {
			httpMetadata.Redirects = append(httpMetadata.Redirects, Redirect{
				From: safeoutput.SanitizeURL(redirect.From), To: safeoutput.SanitizeURL(redirect.To), Status: redirect.Status,
			})
		}
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVersion,
		RequestedURL:  requestedURL,
		FinalURL:      finalURL,
		HTTP:          httpMetadata,
		Analyzers:     analyzers,
		Detections:    make([]DetectionReport, 0, len(result.Detections)),
	}
	coverage := make(map[string]scanner.DetectionCoverage, len(result.Coverage))
	for _, entry := range result.Coverage {
		coverage[entry.RuleID] = entry
	}
	for _, detection := range result.Detections {
		report.Detections = append(report.Detections, buildDetection(detection, coverage[detection.RuleID]))
	}
	return report
}

// WriteJSON renders one report using the versioned JSON contract.
func WriteJSON(writer io.Writer, report Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	return nil
}

// WriteText renders one human-readable report.
func WriteText(writer io.Writer, report Report) error {
	var output strings.Builder
	fmt.Fprintf(&output, "Hemera scan report\nTarget: %s\n", report.RequestedURL)
	if report.HTTP == nil {
		fmt.Fprintln(&output, "HTTP observation: unavailable")
	} else {
		if report.FinalURL != nil {
			fmt.Fprintf(&output, "Final URL: %s\n", *report.FinalURL)
		}
		fmt.Fprintf(&output, "HTTP status: %d\n", report.HTTP.StatusCode)
		if report.HTTP.BodyTruncated {
			fmt.Fprintln(&output, "Body: truncated")
		}
		if len(report.HTTP.Redirects) > 0 {
			fmt.Fprintln(&output, "Redirects:")
			for _, redirect := range report.HTTP.Redirects {
				fmt.Fprintf(&output, "  %d %s -> %s\n", redirect.Status, redirect.From, redirect.To)
			}
		}
	}
	fmt.Fprintln(&output, "\nDetections:")
	detected := 0
	for _, detection := range report.Detections {
		if !detection.Detected {
			continue
		}
		detected++
		fmt.Fprintf(&output, "  %s  %.1f  %s\n", detection.Name, detection.Score, levelLabel(detection.Level))
		writeEvidence(&output, detection)
	}
	if detected == 0 {
		fmt.Fprintln(&output, "  (none)")
	}
	fmt.Fprintln(&output, "\nNot detected:")
	notDetected := 0
	for _, detection := range report.Detections {
		if detection.Status != scanner.DetectionStatusNotDetected {
			continue
		}
		notDetected++
		fmt.Fprintf(&output, "  %s  %.1f  %s\n", detection.Name, detection.Score, levelLabel(detection.Level))
		writeEvidence(&output, detection)
	}
	if notDetected == 0 {
		fmt.Fprintln(&output, "  (none)")
	}
	fmt.Fprintln(&output, "\nInsufficient coverage:")
	insufficient := 0
	for _, detection := range report.Detections {
		if detection.Status != scanner.DetectionStatusInsufficientCoverage {
			continue
		}
		insufficient++
		fmt.Fprintf(&output, "  %s", detection.Name)
		if len(detection.IncompleteSources) > 0 {
			fmt.Fprintf(&output, "  missing %s", strings.Join(detection.IncompleteSources, ", "))
		}
		fmt.Fprintln(&output)
		writeEvidence(&output, detection)
	}
	if insufficient == 0 {
		fmt.Fprintln(&output, "  (none)")
	}
	if report.HTTP != nil && len(report.HTTP.Warnings) > 0 {
		fmt.Fprintln(&output, "\nWarnings:")
		for _, warning := range report.HTTP.Warnings {
			fmt.Fprintf(&output, "  - %s\n", warning)
		}
	}
	writeIncompleteAnalyzers(&output, report.Analyzers)
	if _, err := io.WriteString(writer, output.String()); err != nil {
		return fmt.Errorf("write text report: %w", err)
	}
	return nil
}

func writeIncompleteAnalyzers(output *strings.Builder, analyzers []AnalyzerReport) {
	printedHeader := false
	for _, analyzer := range analyzers {
		if analyzer.Status == scanner.AnalyzerStatusComplete &&
			(analyzer.Source == analysis.SourceHTTP || len(analyzer.Warnings) == 0) {
			continue
		}
		if !printedHeader {
			fmt.Fprintln(output, "\nAnalyzer coverage:")
			printedHeader = true
		}
		fmt.Fprintf(output, "  %s: %s\n", analyzer.Source, analyzer.Status)
		for _, warning := range analyzer.Warnings {
			fmt.Fprintf(output, "    - %s\n", warning)
		}
	}
}

func buildDetection(detection scoring.Detection, coverage scanner.DetectionCoverage) DetectionReport {
	status := coverage.Status
	if status == "" {
		if detection.Detected {
			status = scanner.DetectionStatusDetected
		} else {
			status = scanner.DetectionStatusNotDetected
		}
	}
	report := DetectionReport{
		ID: detection.RuleID, Name: detection.Name, Category: detection.Category,
		Vendor: detection.Vendor, Product: detection.Product, Detected: detection.Detected,
		Status: status, IncompleteSources: append([]string{}, coverage.IncompleteSources...),
		ConditionMatched: detection.ConditionMatched, MinimumEvidenceMet: detection.MinimumEvidenceMet,
		EvidenceScore: detection.EvidenceScore, Score: detection.Score, Level: detection.Level,
		Evidence: EvidenceReport{
			Positive:  buildEvidence(detection.PositiveEvidence, true),
			Negative:  buildEvidence(detection.NegativeEvidence, false),
			Ambiguous: buildEvidence(detection.AmbiguousEvidence, false),
		},
		PositiveEvidenceGroups: buildEvidenceGroups(detection.PositiveEvidenceGroups),
		MissingEvidence:        append([]string{}, detection.MissingPositiveEvidence...),
		MissingDependencies:    append([]string{}, detection.MissingDependencies...),
		AppliedConflicts:       make([]ConflictReport, 0, len(detection.AppliedConflicts)),
	}
	for _, conflict := range detection.AppliedConflicts {
		report.AppliedConflicts = append(report.AppliedConflicts, ConflictReport{
			RuleID: conflict.RuleID, Penalty: conflict.Penalty,
		})
	}
	return report
}

func buildEvidence(scored []scoring.ScoredEvidence, includeGroup bool) []Evidence {
	evidence := make([]Evidence, 0, len(scored))
	for _, scoredEvidence := range scored {
		match := scoredEvidence.Match
		group := ""
		if includeGroup {
			group = match.Group
		}
		evidence = append(evidence, Evidence{
			ID: match.EvidenceID, Group: group,
			Description: match.Description, Type: match.Signal.Type,
			Source: match.Signal.Source, Key: match.Signal.Key,
			Value: safeValue(match.Signal), URL: safeoutput.SanitizeURL(match.Signal.URL),
			Confidence: match.Signal.Confidence, Weight: match.Weight,
			RawContribution: scoredEvidence.RawContribution,
			Contribution:    scoredEvidence.Contribution,
		})
	}
	return evidence
}

func buildEvidenceGroups(groups []scoring.EvidenceGroup) []EvidenceGroup {
	reports := make([]EvidenceGroup, 0, len(groups))
	for _, group := range groups {
		reports = append(reports, EvidenceGroup{
			ID: group.ID, EvidenceIDs: append([]string{}, group.EvidenceIDs...),
			SelectedEvidenceID: group.SelectedEvidenceID,
			RawContribution:    group.RawContribution,
			Contribution:       group.Contribution,
		})
	}
	return reports
}

func safeValue(signal model.Signal) string {
	switch signal.Type {
	case model.SignalTypeScriptURL, model.SignalTypeIframeURL,
		model.SignalTypeNetworkRequest, model.SignalTypeRedirect:
		return safeoutput.SanitizeURL(signal.Value)
	case model.SignalTypeResourceHost:
		return signal.Value
	case model.SignalTypeDNSRecord, model.SignalTypeTLSProperty:
		return safePlainValue(signal.Value)
	case model.SignalTypeNetworkResponse:
		if signal.Key == "status" {
			return signal.Value
		}
	}
	return ""
}

func safePlainValue(value string) string {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

func writeEvidence(output *strings.Builder, detection DetectionReport) {
	for _, evidence := range detection.Evidence.Positive {
		fmt.Fprintf(output, "    + %s: %s", evidence.ID, evidence.Type)
		if evidence.Value != "" {
			fmt.Fprintf(output, " %s", evidence.Value)
		}
		fmt.Fprintf(output, " (raw %.1f; group %s)\n", evidence.RawContribution, evidence.Group)
	}
	for _, group := range detection.PositiveEvidenceGroups {
		fmt.Fprintf(output, "    = group %s: %.1f (%.1f raw; selected %s)\n",
			group.ID, group.Contribution, group.RawContribution, group.SelectedEvidenceID)
	}
	for _, evidence := range detection.Evidence.Negative {
		fmt.Fprintf(output, "    - %s: %s (%.1f)\n", evidence.ID, evidence.Type, evidence.Contribution)
	}
	for _, evidence := range detection.Evidence.Ambiguous {
		fmt.Fprintf(output, "    ~ %s: %s (%.1f)\n", evidence.ID, evidence.Type, evidence.Contribution)
	}
	for _, conflict := range detection.AppliedConflicts {
		fmt.Fprintf(output, "    ! conflict %s: -%.1f\n", conflict.RuleID, conflict.Penalty)
	}
	if len(detection.MissingEvidence) > 0 {
		fmt.Fprintf(output, "    missing: %s\n", strings.Join(detection.MissingEvidence, ", "))
	}
	if len(detection.MissingDependencies) > 0 {
		fmt.Fprintf(output, "    dependencies: %s\n", strings.Join(detection.MissingDependencies, ", "))
	}
}

func levelLabel(level scoring.Level) string {
	return strings.ToUpper(strings.ReplaceAll(string(level), "_", " "))
}
