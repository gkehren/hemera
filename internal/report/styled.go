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
	writeStyledHeader(&b, report)
	writeStyledDetections(&b, report)
	if _, err := io.WriteString(writer, b.String()); err != nil {
		return fmt.Errorf("write styled report: %w", err)
	}
	return nil
}

func writeStyledHeader(b *strings.Builder, report Report) {
	b.WriteString(styledBannerStyle.Render("Hemera scan report"))
	b.WriteString("\n\n")
	styledKeyValue(b, "Target", report.RequestedURL)
	if report.HTTP == nil {
		styledKeyValue(b, "HTTP", "observation unavailable")
	} else {
		if report.FinalURL != nil && *report.FinalURL != report.RequestedURL {
			styledKeyValue(b, "Final URL", *report.FinalURL)
		}
		status := fmt.Sprintf("%d", report.HTTP.StatusCode)
		if report.HTTP.BodyTruncated {
			status += " · body truncated"
		}
		styledKeyValue(b, "Status", status)
		for _, redirect := range report.HTTP.Redirects {
			styledKeyValue(b, "Redirect", fmt.Sprintf("%d %s -> %s", redirect.Status, redirect.From, redirect.To))
		}
	}

	detected, inconclusive := 0, 0
	for _, detection := range report.Detections {
		switch {
		case detection.Detected:
			detected++
		case detection.Status == scanner.DetectionStatusInsufficientCoverage:
			inconclusive++
		}
	}
	styledKeyValue(b, "Detections", fmt.Sprintf("%d detected · %d not detected · %d inconclusive",
		detected, len(report.Detections)-detected-inconclusive, inconclusive))
	b.WriteString("\n")
}

func styledKeyValue(b *strings.Builder, key, value string) {
	fmt.Fprintf(b, "%s %s\n", styledKeyStyle.Render(key), styledValueStyle.Render(value))
}

func writeStyledDetections(b *strings.Builder, report Report) {
	detected, notDetected, insufficient := splitByStatus(report.Detections)

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

	if report.HTTP != nil && len(report.HTTP.Warnings) > 0 {
		b.WriteString("\n")
		b.WriteString(styledWarnMark.Render("⚠ Warnings"))
		b.WriteString("\n")
		for _, warning := range report.HTTP.Warnings {
			fmt.Fprintf(b, "  %s %s\n", styledWarnMark.Render("⚠"), warning)
		}
	}
	writeStyledIncompleteAnalyzers(b, report.Analyzers)
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
