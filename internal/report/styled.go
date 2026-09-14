package report

import (
	"fmt"
	"io"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/scoring"
)

// Styled-report palette. The 256-color codes match the interactive TUI so the
// final output feels continuous with the live progress view.
var (
	styledBannerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("16")).Background(lipgloss.Color("135")).Padding(0, 2)
	styledKeyStyle     = lipgloss.NewStyle().Faint(true).Width(12)
	styledValueStyle   = lipgloss.NewStyle()
	styledDimStyle     = lipgloss.NewStyle().Faint(true)
	styledNameStyle    = lipgloss.NewStyle().Bold(true)
	styledDetectedMark = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("46"))
	styledPendingMark  = lipgloss.NewStyle().Faint(true)
	styledUnknownMark  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styledWarnMark     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styledPositive     = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	styledGroup        = lipgloss.NewStyle().Foreground(lipgloss.Color("111"))
	styledNegative     = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styledAmbiguous    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styledConflict     = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	styledHighBadge    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	styledMediumBadge  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styledLowBadge     = lipgloss.NewStyle().Foreground(lipgloss.Color("111"))
)

// WriteStyled renders one human-readable report using the same visual language
// as the interactive progress view. It explains exactly the same evidence as
// WriteText and performs no detection of its own.
func WriteStyled(writer io.Writer, report Report) error {
	var b strings.Builder
	writeStyledBanner(&b, report)
	multi := len(report.Pages) > 1
	for index, page := range report.Pages {
		if multi {
			b.WriteString("\n" + styledNameStyle.Render(fmt.Sprintf("── Page %d of %d ──", index+1, len(report.Pages))) + "\n\n")
		}
		writeStyledPage(&b, page)
	}
	writeStyledSummary(&b, report.Summary)
	if _, err := io.WriteString(writer, b.String()); err != nil {
		return fmt.Errorf("write styled report: %w", err)
	}
	return nil
}

func writeStyledBanner(b *strings.Builder, report Report) {
	b.WriteString(styledBannerStyle.Render("Hemera scan report"))
	b.WriteString("\n")
	if len(report.Pages) > 1 && report.Summary != nil {
		styledKeyValue(b, "Pages", fmt.Sprintf("%d scanned · %d failed",
			report.Summary.PageCount-report.Summary.FailedPages, report.Summary.FailedPages))
	}
	b.WriteString("\n")
}

func writeStyledPage(b *strings.Builder, page PageReport) {
	styledKeyValue(b, "Target", page.RequestedURL)
	if page.Failed {
		styledKeyValue(b, "Result", styledWarnMark.Render("page scan failed (no observations)"))
		b.WriteString("\n")
		return
	}
	if page.HTTP == nil {
		styledKeyValue(b, "HTTP", "observation unavailable")
	} else {
		if page.FinalURL != nil && *page.FinalURL != page.RequestedURL {
			styledKeyValue(b, "Final URL", *page.FinalURL)
		}
		status := fmt.Sprintf("%d", page.HTTP.StatusCode)
		if page.HTTP.BodyTruncated {
			status += " · body truncated"
		}
		styledKeyValue(b, "Status", status)
		for _, redirect := range page.HTTP.Redirects {
			styledKeyValue(b, "Redirect", fmt.Sprintf("%d %s -> %s", redirect.Status, redirect.From, redirect.To))
		}
	}

	if page.Network != nil {
		network := fmt.Sprintf("%d requests · %d responses · %d bytes",
			page.Network.RequestCount, page.Network.ResponseCount, page.Network.WireBytesTotal)
		styledKeyValue(b, "Network", network)
		if p95 := page.Network.TTFBTiming.P95Ms; p95 > 0 {
			styledKeyValue(b, "TTFB p95", fmt.Sprintf("%d ms", p95))
		}
		if len(page.Network.POSTEndpoints) > 0 {
			styledKeyValue(b, "POST", fmt.Sprintf("%d endpoint(s)", len(page.Network.POSTEndpoints)))
		}
	}

	detected, inconclusive := 0, 0
	for _, detection := range page.Detections {
		switch {
		case detection.Detected:
			detected++
		case detection.Status == scanner.DetectionStatusInsufficientCoverage:
			inconclusive++
		}
	}
	styledKeyValue(b, "Detections", fmt.Sprintf("%d detected · %d not detected · %d inconclusive",
		detected, len(page.Detections)-detected-inconclusive, inconclusive))
	b.WriteString("\n")
	writeStyledDetections(b, page)
}

func writeStyledSummary(b *strings.Builder, summary *SummaryReport) {
	if summary == nil {
		return
	}
	b.WriteString("\n")
	b.WriteString(styledValueStyle.Render("Σ Summary across pages"))
	b.WriteString("\n")
	for _, detection := range summary.Detections {
		if detection.DetectedPages == 0 {
			continue
		}
		line := "  " + styledDetectedMark.Render("✔") + " " + styledNameStyle.Render(detection.Name)
		line += "   " + styledLevelBadge(detection.MaxLevel)
		line += styledDimStyle.Render(fmt.Sprintf(" on %d/%d pages · max score %.1f",
			detection.DetectedPages, summary.PageCount-summary.FailedPages, detection.MaxScore))
		b.WriteString(line)
		b.WriteString("\n")
	}
}

func styledKeyValue(b *strings.Builder, key, value string) {
	fmt.Fprintf(b, "%s %s\n", styledKeyStyle.Render(key), styledValueStyle.Render(value))
}

func writeStyledDetections(b *strings.Builder, page PageReport) {
	detected, notDetected, insufficient := splitByStatus(page.Detections)

	b.WriteString(styledDetectedMark.Render("✔ Detections"))
	b.WriteString("\n")
	if len(detected) == 0 {
		b.WriteString(styledDimStyle.Render("  (none)"))
		b.WriteString("\n")
	}
	for _, detection := range detected {
		writeStyledDetectionHeadline(b, detection, styledDetectedMark.Render("✔"))
		writeStyledEvidence(b, detection)
	}

	b.WriteString("\n")
	b.WriteString(styledValueStyle.Render("○ Not detected"))
	b.WriteString("\n")
	if len(notDetected) == 0 {
		b.WriteString(styledDimStyle.Render("  (none)"))
		b.WriteString("\n")
	}
	for _, detection := range notDetected {
		writeStyledDetectionHeadline(b, detection, styledPendingMark.Render("○"))
		writeStyledEvidence(b, detection)
	}

	b.WriteString("\n")
	b.WriteString(styledUnknownMark.Render("? Insufficient coverage"))
	b.WriteString("\n")
	if len(insufficient) == 0 {
		b.WriteString(styledDimStyle.Render("  (none)"))
		b.WriteString("\n")
	}
	for _, detection := range insufficient {
		headline := "  " + styledUnknownMark.Render("?") + " " + styledNameStyle.Render(detection.Name)
		if len(detection.IncompleteSources) > 0 {
			headline += "   " + styledDimStyle.Render("missing "+strings.Join(detection.IncompleteSources, ", "))
		}
		b.WriteString(headline)
		b.WriteString("\n")
		writeStyledEvidence(b, detection)
	}

	if page.HTTP != nil && len(page.HTTP.Warnings) > 0 {
		b.WriteString("\n")
		b.WriteString(styledWarnMark.Render("⚠ Warnings"))
		b.WriteString("\n")
		for _, warning := range page.HTTP.Warnings {
			fmt.Fprintf(b, "  %s %s\n", styledWarnMark.Render("⚠"), warning)
		}
	}
	writeStyledIncompleteAnalyzers(b, page.Analyzers)
}

func splitByStatus(detections []DetectionReport) (detected, notDetected, insufficient []DetectionReport) {
	for _, detection := range detections {
		switch {
		case detection.Detected:
			detected = append(detected, detection)
		case detection.Status == scanner.DetectionStatusNotDetected:
			notDetected = append(notDetected, detection)
		case detection.Status == scanner.DetectionStatusInsufficientCoverage:
			insufficient = append(insufficient, detection)
		}
	}
	return detected, notDetected, insufficient
}

func writeStyledDetectionHeadline(b *strings.Builder, detection DetectionReport, mark string) {
	headline := "  " + mark + " " + styledNameStyle.Render(detection.Name)
	headline += "   " + styledLevelBadge(detection.Level)
	headline += " " + styledDimStyle.Render(fmt.Sprintf("score %.1f", detection.Score))
	b.WriteString(headline)
	b.WriteString("\n")
}

func styledLevelBadge(level scoring.Level) string {
	label := fmt.Sprintf("[%s]", levelLabel(level))
	switch level {
	case scoring.LevelVeryHigh, scoring.LevelHigh:
		return styledHighBadge.Render(label)
	case scoring.LevelMedium:
		return styledMediumBadge.Render(label)
	case scoring.LevelLow:
		return styledLowBadge.Render(label)
	default:
		return styledDimStyle.Render(label)
	}
}

func writeStyledEvidence(b *strings.Builder, detection DetectionReport) {
	for _, evidence := range detection.Evidence.Positive {
		line := fmt.Sprintf("%s %s: %s", styledPositive.Render("+"), evidence.ID, evidence.Type)
		if evidence.Value != "" {
			line += " " + evidence.Value
		}
		line += styledDimStyle.Render(fmt.Sprintf(" (raw %.1f; group %s)", evidence.RawContribution, evidence.Group))
		b.WriteString("      " + line + "\n")
	}
	for _, group := range detection.PositiveEvidenceGroups {
		line := fmt.Sprintf("%s group %s: %.1f", styledGroup.Render("="), group.ID, group.Contribution)
		line += styledDimStyle.Render(fmt.Sprintf(" (%.1f raw; selected %s)", group.RawContribution, group.SelectedEvidenceID))
		b.WriteString("      " + line + "\n")
	}
	for _, evidence := range detection.Evidence.Negative {
		line := fmt.Sprintf("%s %s: %s", styledNegative.Render("-"), evidence.ID, evidence.Type)
		line += styledDimStyle.Render(fmt.Sprintf(" (%.1f)", evidence.Contribution))
		b.WriteString("      " + line + "\n")
	}
	for _, evidence := range detection.Evidence.Ambiguous {
		line := fmt.Sprintf("%s %s: %s", styledAmbiguous.Render("~"), evidence.ID, evidence.Type)
		line += styledDimStyle.Render(fmt.Sprintf(" (%.1f)", evidence.Contribution))
		b.WriteString("      " + line + "\n")
	}
	for _, conflict := range detection.AppliedConflicts {
		line := fmt.Sprintf("%s conflict %s:", styledConflict.Render("!"), conflict.RuleID)
		line += styledDimStyle.Render(fmt.Sprintf(" -%.1f", conflict.Penalty))
		b.WriteString("      " + line + "\n")
	}
	if len(detection.MissingEvidence) > 0 {
		b.WriteString("      " + styledDimStyle.Render("missing: "+strings.Join(detection.MissingEvidence, ", ")) + "\n")
	}
	if len(detection.MissingDependencies) > 0 {
		b.WriteString("      " + styledDimStyle.Render("dependencies: "+strings.Join(detection.MissingDependencies, ", ")) + "\n")
	}
}

func writeStyledIncompleteAnalyzers(b *strings.Builder, analyzers []AnalyzerReport) {
	printedHeader := false
	for _, analyzer := range analyzers {
		if analyzer.Status == scanner.AnalyzerStatusComplete &&
			(analyzer.Source == analysis.SourceHTTP || len(analyzer.Warnings) == 0) {
			continue
		}
		if !printedHeader {
			b.WriteString("\n")
			b.WriteString(styledValueStyle.Render("◐ Analyzer coverage"))
			b.WriteString("\n")
			printedHeader = true
		}
		status := string(analyzer.Status)
		if analyzer.Status != scanner.AnalyzerStatusComplete {
			status = styledUnknownMark.Render(status)
		}
		fmt.Fprintf(b, "  %s: %s\n", analyzer.Source, status)
		for _, warning := range analyzer.Warnings {
			fmt.Fprintf(b, "    %s %s\n", styledWarnMark.Render("-"), warning)
		}
	}
}
