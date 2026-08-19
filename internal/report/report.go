// Package report builds safe, stable scan reports and renders them as text or
// versioned JSON without performing detection.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/gkehren/hemera/internal/rules"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

const (
	// SchemaVersion identifies the stable JSON report contract.
	SchemaVersion = 2
)

// Report is the stable representation shared by text and JSON renderers.
type Report struct {
	SchemaVersion int               `json:"schema_version"`
	ToolVersion   string            `json:"tool_version"`
	RequestedURL  string            `json:"requested_url"`
	FinalURL      string            `json:"final_url"`
	HTTP          HTTP              `json:"http"`
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

// DetectionReport is one fully explained detector result.
type DetectionReport struct {
	ID                     string           `json:"id"`
	Name                   string           `json:"name"`
	Category               rules.Category   `json:"category"`
	Vendor                 string           `json:"vendor"`
	Product                string           `json:"product,omitempty"`
	Detected               bool             `json:"detected"`
	ConditionMatched       bool             `json:"condition_matched"`
	MinimumEvidenceMet     bool             `json:"minimum_evidence_met"`
	EvidenceScore          float64          `json:"evidence_score"`
	Score                  float64          `json:"score"`
	Level                  scoring.Level    `json:"level"`
	Evidence               EvidenceReport   `json:"evidence"`
	PositiveEvidenceGroups []EvidenceGroup  `json:"positive_evidence_groups"`
	MissingEvidence        []string         `json:"missing_evidence"`
	MissingDependencies    []string         `json:"missing_dependencies"`
	AppliedConflicts       []ConflictReport `json:"applied_conflicts"`
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
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVersion,
		RequestedURL:  sanitizeURL(result.HTTP.RequestedURL),
		FinalURL:      sanitizeURL(result.HTTP.FinalURL),
		HTTP: HTTP{
			StatusCode: result.HTTP.StatusCode, BodyTruncated: result.HTTP.BodyTruncated,
			Redirects: make([]Redirect, 0, len(result.HTTP.Redirects)),
			Warnings:  append([]string{}, result.HTTP.Warnings...),
		},
		Detections: make([]DetectionReport, 0, len(result.Detections)),
	}
	for _, redirect := range result.HTTP.Redirects {
		report.HTTP.Redirects = append(report.HTTP.Redirects, Redirect{
			From: sanitizeURL(redirect.From), To: sanitizeURL(redirect.To), Status: redirect.Status,
		})
	}
	for _, detection := range result.Detections {
		report.Detections = append(report.Detections, buildDetection(detection))
	}
	return report
}

// WriteJSON renders one report using the stable, versioned JSON contract.
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
	fmt.Fprintf(&output, "Hemera scan report\nTarget: %s\nFinal URL: %s\nHTTP status: %d\n",
		report.RequestedURL, report.FinalURL, report.HTTP.StatusCode)
	if report.HTTP.BodyTruncated {
		fmt.Fprintln(&output, "Body: truncated")
	}
	if len(report.HTTP.Redirects) > 0 {
		fmt.Fprintln(&output, "Redirects:")
		for _, redirect := range report.HTTP.Redirects {
			fmt.Fprintf(&output, "  %d %s -> %s\n", redirect.Status, redirect.From, redirect.To)
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
		if detection.Detected {
			continue
		}
		notDetected++
		fmt.Fprintf(&output, "  %s  %.1f  %s\n", detection.Name, detection.Score, levelLabel(detection.Level))
		writeEvidence(&output, detection)
	}
	if notDetected == 0 {
		fmt.Fprintln(&output, "  (none)")
	}
	if len(report.HTTP.Warnings) > 0 {
		fmt.Fprintln(&output, "\nWarnings:")
		for _, warning := range report.HTTP.Warnings {
			fmt.Fprintf(&output, "  - %s\n", warning)
		}
	}
	if _, err := io.WriteString(writer, output.String()); err != nil {
		return fmt.Errorf("write text report: %w", err)
	}
	return nil
}

func buildDetection(detection scoring.Detection) DetectionReport {
	report := DetectionReport{
		ID: detection.RuleID, Name: detection.Name, Category: detection.Category,
		Vendor: detection.Vendor, Product: detection.Product, Detected: detection.Detected,
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
			Value: safeValue(match.Signal), URL: sanitizeURL(match.Signal.URL),
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
		return sanitizeURL(signal.Value)
	case model.SignalTypeResourceHost:
		return signal.Value
	case model.SignalTypeNetworkResponse:
		if signal.Key == "status" {
			return signal.Value
		}
	}
	return ""
}

func sanitizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.Fragment = ""
	parsed.RawFragment = ""
	if parsed.RawQuery != "" {
		parsed.RawQuery = "redacted"
		parsed.ForceQuery = false
	}
	return parsed.String()
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
