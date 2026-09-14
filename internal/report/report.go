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
	SchemaVersion = 6
)

// Report is the deterministic representation shared by text and JSON renderers.
// Every scanned page appears exactly once in Pages, in scan order.
type Report struct {
	SchemaVersion int            `json:"schema_version"`
	ToolVersion   string         `json:"tool_version"`
	Pages         []PageReport   `json:"pages"`
	Summary       *SummaryReport `json:"summary,omitempty"`
}

// PageReport is the complete minimized result for one scanned page. Failed is
// true when the page could not be scanned; the remaining fields then describe
// nothing and collections are empty.
type PageReport struct {
	RequestedURL string            `json:"requested_url"`
	Failed       bool              `json:"failed"`
	FinalURL     *string           `json:"final_url"`
	HTTP         *HTTP             `json:"http"`
	Network      *NetworkReport    `json:"network,omitempty"`
	Analyzers    []AnalyzerReport  `json:"analyzers"`
	Detections   []DetectionReport `json:"detections"`
}

// SummaryReport folds multi-page detection outcomes into one bounded overview.
// It only aggregates scores that per-page detection already produced and adds
// no detection semantics of its own.
type SummaryReport struct {
	PageCount   int                `json:"page_count"`
	FailedPages int                `json:"failed_pages"`
	Detections  []SummaryDetection `json:"detections"`
}

// SummaryDetection records the cross-page outcome of one detector rule.
type SummaryDetection struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Category      rules.Category `json:"category"`
	Vendor        string         `json:"vendor"`
	Product       string         `json:"product,omitempty"`
	DetectedPages int            `json:"detected_pages"`
	MaxScore      float64        `json:"max_score"`
	MaxLevel      scoring.Level  `json:"max_level"`
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

// NetworkReport contains bounded browser network diagnostics. Durations are
// integer milliseconds; no timestamps, remote addresses, headers, bodies, or
// connection identifiers are exposed.
type NetworkReport struct {
	FinalURL       string                     `json:"final_url,omitempty"`
	RequestCount   int                        `json:"request_count"`
	ResponseCount  int                        `json:"response_count"`
	WireBytesTotal int64                      `json:"wire_bytes_total"`
	POSTEndpoints  []string                   `json:"post_endpoints"`
	Protocols      []NetworkNameCountReport   `json:"protocols"`
	StatusClasses  []NetworkNameCountReport   `json:"status_classes"`
	Hosts          []NetworkHostReport        `json:"hosts"`
	QueueTiming    NetworkTimingReport        `json:"queue_timing"`
	TTFBTiming     NetworkTimingReport        `json:"ttfb_timing"`
	Transactions   []NetworkTransactionReport `json:"transactions"`
	Truncated      bool                       `json:"truncated"`
}

// NetworkNameCountReport counts observations sharing one bounded label.
type NetworkNameCountReport struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// NetworkHostReport summarizes the browser requests observed for one host.
type NetworkHostReport struct {
	Host           string `json:"host"`
	Requests       int    `json:"requests"`
	ReusedRequests int    `json:"reused_requests"`
}

// NetworkTimingReport summarizes one duration family in integer milliseconds.
type NetworkTimingReport struct {
	P50Ms int64 `json:"p50_ms"`
	P95Ms int64 `json:"p95_ms"`
	MaxMs int64 `json:"max_ms"`
}

// NetworkTransactionReport is one correlated browser request/response row of
// the bounded network waterfall.
type NetworkTransactionReport struct {
	Method           string `json:"method"`
	URL              string `json:"url"`
	Status           int    `json:"status"`
	Protocol         string `json:"protocol,omitempty"`
	ConnectionReused bool   `json:"connection_reused"`
	WireBytes        int64  `json:"wire_bytes"`
	QueueMs          int64  `json:"queue_ms"`
	TTFBMs           int64  `json:"ttfb_ms"`
	TotalMs          int64  `json:"total_ms"`
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

// Build converts one single-page scan result into a secret-minimized report.
func Build(toolVersion string, result scanner.Result) Report {
	return BuildPages(toolVersion, []scanner.PageResult{{URL: result.Target.URL, Result: result}})
}

// BuildPages converts ordered multi-page scan outcomes into a secret-minimized
// report. A page-level error produces a failed page entry without leaking the
// error; failed pages never contribute detections to the summary.
func BuildPages(toolVersion string, pages []scanner.PageResult) Report {
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVersion,
		Pages:         make([]PageReport, 0, len(pages)),
	}
	for _, page := range pages {
		if page.Err != nil {
			report.Pages = append(report.Pages, PageReport{
				RequestedURL: safeoutput.SanitizeURL(page.URL),
				Failed:       true,
				Analyzers:    make([]AnalyzerReport, 0),
				Detections:   make([]DetectionReport, 0),
			})
			continue
		}
		report.Pages = append(report.Pages, buildPage(page.Result))
	}
	if len(report.Pages) > 1 {
		report.Summary = buildSummary(report.Pages)
	}
	return report
}

func buildPage(result scanner.Result) PageReport {
	var httpMetadata *HTTP
	var networkMetadata *NetworkReport
	requestedURL := safeoutput.SanitizeURL(result.Target.URL)
	var finalURL *string
	analyzers := make([]AnalyzerReport, 0, len(result.Analyzers))
	for _, analyzerResult := range result.Analyzers {
		observation := analyzerResult.Observation
		analyzers = append(analyzers, AnalyzerReport{
			Source: observation.Source, Status: analyzerResult.Status,
			Warnings: append([]string{}, observation.Warnings...),
		})
		if observation.Metadata.Network != nil && networkMetadata == nil {
			networkMetadata = buildNetworkReport(observation.Metadata.Network)
		}
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
	page := PageReport{
		RequestedURL: requestedURL,
		FinalURL:     finalURL,
		HTTP:         httpMetadata,
		Network:      networkMetadata,
		Analyzers:    analyzers,
		Detections:   make([]DetectionReport, 0, len(result.Detections)),
	}
	coverage := make(map[string]scanner.DetectionCoverage, len(result.Coverage))
	for _, entry := range result.Coverage {
		coverage[entry.RuleID] = entry
	}
	for _, detection := range result.Detections {
		page.Detections = append(page.Detections, buildDetection(detection, coverage[detection.RuleID]))
	}
	return page
}

// buildSummary folds per-page detections into one cross-page overview. Rule
// order follows the first page that reported the rule.
func buildSummary(pages []PageReport) *SummaryReport {
	summary := &SummaryReport{
		PageCount:  len(pages),
		Detections: make([]SummaryDetection, 0),
	}
	indexByID := make(map[string]int)
	for _, page := range pages {
		if page.Failed {
			summary.FailedPages++
			continue
		}
		for _, detection := range page.Detections {
			index, exists := indexByID[detection.ID]
			if !exists {
				summary.Detections = append(summary.Detections, SummaryDetection{
					ID: detection.ID, Name: detection.Name, Category: detection.Category,
					Vendor: detection.Vendor, Product: detection.Product,
				})
				index = len(summary.Detections) - 1
				indexByID[detection.ID] = index
			}
			entry := &summary.Detections[index]
			if detection.Detected {
				entry.DetectedPages++
			}
			if detection.Score > entry.MaxScore {
				entry.MaxScore = detection.Score
				entry.MaxLevel = detection.Level
			}
		}
	}
	return summary
}

// buildNetworkReport maps bounded browser network metadata into the sanitized
// report contract. URLs pass through output sanitization again even though the
// capture boundary already cleaned them.
func buildNetworkReport(metadata *analysis.NetworkMetadata) *NetworkReport {
	report := &NetworkReport{
		FinalURL:       safeoutput.SanitizeURL(metadata.FinalURL),
		RequestCount:   metadata.RequestCount,
		ResponseCount:  metadata.ResponseCount,
		WireBytesTotal: metadata.WireBytesTotal,
		POSTEndpoints:  make([]string, 0, len(metadata.POSTEndpoints)),
		Protocols:      make([]NetworkNameCountReport, 0, len(metadata.Protocols)),
		StatusClasses:  make([]NetworkNameCountReport, 0, len(metadata.StatusClasses)),
		Hosts:          make([]NetworkHostReport, 0, len(metadata.Hosts)),
		QueueTiming: NetworkTimingReport{
			P50Ms: metadata.QueueTiming.P50Ms, P95Ms: metadata.QueueTiming.P95Ms, MaxMs: metadata.QueueTiming.MaxMs,
		},
		TTFBTiming: NetworkTimingReport{
			P50Ms: metadata.TTFBTiming.P50Ms, P95Ms: metadata.TTFBTiming.P95Ms, MaxMs: metadata.TTFBTiming.MaxMs,
		},
		Transactions: make([]NetworkTransactionReport, 0, len(metadata.Transactions)),
		Truncated:    metadata.Truncated,
	}
	for _, endpoint := range metadata.POSTEndpoints {
		if sanitized := safeoutput.SanitizeURL(endpoint); sanitized != "" {
			report.POSTEndpoints = append(report.POSTEndpoints, sanitized)
		}
	}
	for _, protocol := range metadata.Protocols {
		report.Protocols = append(report.Protocols, NetworkNameCountReport{Name: protocol.Name, Count: protocol.Count})
	}
	for _, statusClass := range metadata.StatusClasses {
		report.StatusClasses = append(report.StatusClasses, NetworkNameCountReport{Name: statusClass.Name, Count: statusClass.Count})
	}
	for _, host := range metadata.Hosts {
		report.Hosts = append(report.Hosts, NetworkHostReport{
			Host: host.Host, Requests: host.Requests, ReusedRequests: host.ReusedRequests,
		})
	}
	for _, transaction := range metadata.Transactions {
		report.Transactions = append(report.Transactions, NetworkTransactionReport{
			Method:           transaction.Method,
			URL:              safeoutput.SanitizeURL(transaction.URL),
			Status:           transaction.Status,
			Protocol:         transaction.Protocol,
			ConnectionReused: transaction.ConnectionReused,
			WireBytes:        transaction.WireBytes,
			QueueMs:          transaction.QueueMs,
			TTFBMs:           transaction.TTFBMs,
			TotalMs:          transaction.TotalMs,
		})
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
	fmt.Fprintln(&output, "Hemera scan report")
	multi := len(report.Pages) > 1
	for index, page := range report.Pages {
		if multi {
			fmt.Fprintf(&output, "\n=== Page %d of %d ===\n", index+1, len(report.Pages))
		}
		writePageText(&output, page)
	}
	writeSummaryText(&output, report.Summary)
	if _, err := io.WriteString(writer, output.String()); err != nil {
		return fmt.Errorf("write text report: %w", err)
	}
	return nil
}

func writePageText(output *strings.Builder, page PageReport) {
	fmt.Fprintf(output, "Target: %s\n", page.RequestedURL)
	if page.Failed {
		fmt.Fprintln(output, "Page scan: failed (no observations)")
		return
	}
	if page.HTTP == nil {
		fmt.Fprintln(output, "HTTP observation: unavailable")
	} else {
		if page.FinalURL != nil {
			fmt.Fprintf(output, "Final URL: %s\n", *page.FinalURL)
		}
		fmt.Fprintf(output, "HTTP status: %d\n", page.HTTP.StatusCode)
		if page.HTTP.BodyTruncated {
			fmt.Fprintln(output, "Body: truncated")
		}
		if len(page.HTTP.Redirects) > 0 {
			fmt.Fprintln(output, "Redirects:")
			for _, redirect := range page.HTTP.Redirects {
				fmt.Fprintf(output, "  %d %s -> %s\n", redirect.Status, redirect.From, redirect.To)
			}
		}
	}
	fmt.Fprintln(output, "\nDetections:")
	detected := 0
	for _, detection := range page.Detections {
		if !detection.Detected {
			continue
		}
		detected++
		fmt.Fprintf(output, "  %s  %.1f  %s\n", detection.Name, detection.Score, levelLabel(detection.Level))
		writeEvidence(output, detection)
	}
	if detected == 0 {
		fmt.Fprintln(output, "  (none)")
	}
	fmt.Fprintln(output, "\nNot detected:")
	notDetected := 0
	for _, detection := range page.Detections {
		if detection.Status != scanner.DetectionStatusNotDetected {
			continue
		}
		notDetected++
		fmt.Fprintf(output, "  %s  %.1f  %s\n", detection.Name, detection.Score, levelLabel(detection.Level))
		writeEvidence(output, detection)
	}
	if notDetected == 0 {
		fmt.Fprintln(output, "  (none)")
	}
	fmt.Fprintln(output, "\nInsufficient coverage:")
	insufficient := 0
	for _, detection := range page.Detections {
		if detection.Status != scanner.DetectionStatusInsufficientCoverage {
			continue
		}
		insufficient++
		fmt.Fprintf(output, "  %s", detection.Name)
		if len(detection.IncompleteSources) > 0 {
			fmt.Fprintf(output, "  missing %s", strings.Join(detection.IncompleteSources, ", "))
		}
		fmt.Fprintln(output)
		writeEvidence(output, detection)
	}
	if insufficient == 0 {
		fmt.Fprintln(output, "  (none)")
	}
	writeNetworkSection(output, page.Network)
	if page.HTTP != nil && len(page.HTTP.Warnings) > 0 {
		fmt.Fprintln(output, "\nWarnings:")
		for _, warning := range page.HTTP.Warnings {
			fmt.Fprintf(output, "  - %s\n", warning)
		}
	}
	writeIncompleteAnalyzers(output, page.Analyzers)
}

func writeSummaryText(output *strings.Builder, summary *SummaryReport) {
	if summary == nil {
		return
	}
	fmt.Fprintf(output, "\nSummary across %d pages (%d failed):\n", summary.PageCount, summary.FailedPages)
	fmt.Fprintln(output, "  Rule  Detected on  Max score")
	for _, detection := range summary.Detections {
		fmt.Fprintf(output, "  %s  %d/%d  %.1f  %s\n",
			detection.Name, detection.DetectedPages, summary.PageCount-summary.FailedPages,
			detection.MaxScore, levelLabel(detection.MaxLevel))
	}
}

const (
	maxNetworkPOSTDisplay    = 20
	maxNetworkHostDisplay    = 20
	maxNetworkRequestDisplay = 50
)

func writeNetworkSection(output *strings.Builder, network *NetworkReport) {
	if network == nil {
		return
	}
	fmt.Fprintln(output, "\nNetwork:")
	fmt.Fprintf(output, "  Requests: %d observed, %d with response, %d bytes transferred\n",
		network.RequestCount, network.ResponseCount, network.WireBytesTotal)
	if summary := formatNameCounts(network.Protocols); summary != "" {
		fmt.Fprintf(output, "  Protocols: %s\n", summary)
	}
	if summary := formatNameCounts(network.StatusClasses); summary != "" {
		fmt.Fprintf(output, "  Status classes: %s\n", summary)
	}
	if len(network.POSTEndpoints) > 0 {
		fmt.Fprintf(output, "  POST endpoints (%d):\n", len(network.POSTEndpoints))
		for index, endpoint := range network.POSTEndpoints {
			if index == maxNetworkPOSTDisplay {
				fmt.Fprintf(output, "    ... %d more\n", len(network.POSTEndpoints)-index)
				break
			}
			fmt.Fprintf(output, "    - %s\n", endpoint)
		}
	}
	if len(network.Hosts) > 0 {
		fmt.Fprintln(output, "  Hosts:")
		for index, host := range network.Hosts {
			if index == maxNetworkHostDisplay {
				fmt.Fprintf(output, "    ... %d more\n", len(network.Hosts)-index)
				break
			}
			fmt.Fprintf(output, "    - %s: %d requests (%d reused)\n",
				host.Host, host.Requests, host.ReusedRequests)
		}
	}
	fmt.Fprintf(output, "  Queue (ms): p50=%d p95=%d max=%d; TTFB (ms): p50=%d p95=%d max=%d\n",
		network.QueueTiming.P50Ms, network.QueueTiming.P95Ms, network.QueueTiming.MaxMs,
		network.TTFBTiming.P50Ms, network.TTFBTiming.P95Ms, network.TTFBTiming.MaxMs)
	if len(network.Transactions) > 0 {
		fmt.Fprintf(output, "  Requests (sorted, %d of %d shown):\n",
			min(len(network.Transactions), maxNetworkRequestDisplay), len(network.Transactions))
		for index, transaction := range network.Transactions {
			if index == maxNetworkRequestDisplay {
				fmt.Fprintf(output, "    ... %d more\n", len(network.Transactions)-index)
				break
			}
			fmt.Fprintf(output, "    - %s %s %d%s queue=%dms ttfb=%dms total=%dms wire=%d%s\n",
				transaction.Method, transaction.URL, transaction.Status,
				formatOptionalField(" ", transaction.Protocol),
				transaction.QueueMs, transaction.TTFBMs, transaction.TotalMs,
				transaction.WireBytes, formatReused(transaction.ConnectionReused))
		}
	}
	if network.Truncated {
		fmt.Fprintln(output, "  Note: network detail was truncated by capture limits")
	}
}

func formatNameCounts(counts []NetworkNameCountReport) string {
	parts := make([]string, 0, len(counts))
	for _, count := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", count.Name, count.Count))
	}
	return strings.Join(parts, ", ")
}

func formatOptionalField(prefix, value string) string {
	if value == "" {
		return ""
	}
	return prefix + value
}

func formatReused(reused bool) string {
	if reused {
		return " reused"
	}
	return ""
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
		model.SignalTypeNetworkRequest, model.SignalTypeRedirect,
		model.SignalTypeFormSubmission:
		return safeoutput.SanitizeURL(signal.Value)
	case model.SignalTypeResourceHost:
		return signal.Value
	case model.SignalTypeDNSRecord, model.SignalTypeTLSProperty,
		model.SignalTypeNetworkTransaction:
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
