package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/gkehren/hemera/internal/safeoutput"
	"github.com/gkehren/hemera/internal/scanner"
)

// Outcome carries the finished scan result out of the progress view.
type Outcome struct {
	Result scanner.Result
	Err    error
}

// Msg is one update for the progress view. Exactly one message with Final set
// is delivered per run, carrying the authoritative Outcome; Event messages
// precede it in analyzer order.
type Msg struct {
	Event   scanner.ScanEvent
	Final   bool
	Outcome Outcome
}

type stageState uint8

const (
	stagePending stageState = iota
	stageRunning
	stageDone
	stagePartial
	stageFailed
)

type stage struct {
	source string
	label  string
	state  stageState
}

// failedStageDetail is the only text ever shown for a failed stage. Progress
// events intentionally carry no analyzer error details: they may embed
// untrusted input (for example request URLs), and minimization is the
// report's job, not the terminal's.
const failedStageDetail = "observation unavailable"

// partialStageDetail mirrors the report vocabulary for an analyzer that
// produced useful evidence plus a non-fatal error.
const partialStageDetail = "partial observation"

// progressEventMsg wraps one progress update for the bubbletea loop.
type progressEventMsg Msg

var (
	labelStyle     = lipgloss.NewStyle().Bold(true)
	pendingStyle   = lipgloss.NewStyle().Faint(true)
	runningStyle   = lipgloss.NewStyle()
	doneStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	partialStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	failedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	errDetailStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Faint(true)
	titleStyle     = lipgloss.NewStyle().Bold(true).MarginBottom(1)
)

func stageLabel(source string) string {
	switch source {
	case "http_analyzer":
		return "HTTP analysis"
	case "dns_tls_analyzer":
		return "DNS/TLS analysis"
	case "browser_analyzer":
		return "Browser analysis"
	default:
		// Source identifiers are registered by Hemera code, so this branch
		// is expected to stay Hemera-controlled; unknown values still
		// render inert if they ever carry control bytes.
		return safeoutput.PlainText(strings.NewReplacer("_", " ").Replace(source))
	}
}

type progressModel struct {
	stages   []stage
	target   string
	spinner  spinner.Model
	progress progress.Model
	outcome  *Outcome
	percent  float64
	canceled bool
	msgs     <-chan Msg
}

func newProgressModel(sources []string, target string, msgs <-chan Msg) progressModel {
	stages := make([]stage, 0, len(sources))
	for _, source := range sources {
		stages = append(stages, stage{source: source, label: stageLabel(source)})
	}
	return progressModel{
		stages: stages,
		// Defense in depth: the view renders only the minimized display
		// form, even if a caller passes a raw target. Network execution
		// keeps the exact original URL; this copy is presentation-only.
		target:   safeoutput.DisplayURL(target),
		spinner:  spinner.New(spinner.WithSpinner(spinner.Dot)),
		progress: progress.New(progress.WithWidth(40)),
		msgs:     msgs,
	}
}

func (m progressModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForProgressMsg(m.msgs))
}

func waitForProgressMsg(msgs <-chan Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-msgs
		if !ok {
			return nil
		}
		return progressEventMsg(msg)
	}
}

// Update routes messages; it is exported so tests can drive the model without
// a real terminal.
func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		var cmd tea.Cmd
		m.progress, cmd = m.progress.Update(msg)
		return m, cmd

	case progressEventMsg:
		if msg.Final {
			outcome := msg.Outcome
			m.outcome = &outcome
			if outcome.Err != nil {
				m.markUnfinishedFailed()
				m.percent = m.settledFraction()
			} else {
				// A completed scan always shows a full bar; the spring
				// animation would not finish before tea.Quit renders.
				m.percent = 1.0
			}
			return m, tea.Quit
		}
		m.applyEvent(msg.Event)
		m.percent = m.settledFraction()
		cmds := []tea.Cmd{waitForProgressMsg(m.msgs)}
		if cmd := m.progress.SetPercent(m.percent); cmd != nil {
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			m.canceled = true
			return m, tea.Quit
		}
		return m, nil

	default:
		return m, nil
	}
}

func (m *progressModel) applyEvent(event scanner.ScanEvent) {
	for index := range m.stages {
		if m.stages[index].source != event.Source {
			continue
		}
		switch event.Kind {
		case scanner.ScanEventStarted:
			m.stages[index].state = stageRunning
		case scanner.ScanEventFinished:
			switch event.Status {
			case scanner.AnalyzerStatusComplete:
				m.stages[index].state = stageDone
			case scanner.AnalyzerStatusPartial:
				m.stages[index].state = stagePartial
			default:
				m.stages[index].state = stageFailed
			}
		}
		return
	}
}

func (m *progressModel) markUnfinishedFailed() {
	for index := range m.stages {
		if m.stages[index].state == stagePending || m.stages[index].state == stageRunning {
			m.stages[index].state = stageFailed
		}
	}
}

func (m *progressModel) settledFraction() float64 {
	if len(m.stages) == 0 {
		return 0
	}
	settled := 0.0
	for _, s := range m.stages {
		if s.state == stageDone || s.state == stagePartial || s.state == stageFailed {
			settled++
		}
	}
	return settled / float64(len(m.stages))
}

// View renders the live progress screen or the final summary frame.
func (m progressModel) View() tea.View {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Hemera scan"))
	b.WriteString("\n")
	b.WriteString(pendingStyle.Render(m.target))
	b.WriteString("\n\n")

	for _, s := range m.stages {
		b.WriteString(renderStage(s, m.spinner.View()))
		b.WriteString("\n")
		switch s.state {
		case stageFailed:
			b.WriteString(errDetailStyle.Render("    " + failedStageDetail))
			b.WriteString("\n")
		case stagePartial:
			b.WriteString(pendingStyle.Render("    " + partialStageDetail))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	if m.outcome != nil {
		// Render the settled value exactly; the spring animation cannot
		// complete before the program quits on the final message.
		b.WriteString(m.progress.ViewAs(m.percent))
	} else {
		b.WriteString(m.progress.View())
	}
	b.WriteString("\n")

	if m.canceled {
		b.WriteString(failedStyle.Render("Scan canceled by user."))
		b.WriteString("\n")
	}
	return tea.NewView(b.String())
}

func renderStage(s stage, spinnerView string) string {
	switch s.state {
	case stageRunning:
		return runningStyle.Render(fmt.Sprintf(" %s %s…", spinnerView, s.label))
	case stageDone:
		return doneStyle.Render(fmt.Sprintf(" ✔ %s", s.label))
	case stagePartial:
		return partialStyle.Render(fmt.Sprintf(" ◐ %s", s.label)) +
			pendingStyle.Render(" · partial")
	case stageFailed:
		return failedStyle.Render(fmt.Sprintf(" ✘ %s", s.label))
	default:
		return pendingStyle.Render(fmt.Sprintf(" ○ %s", s.label))
	}
}

// ErrViewCanceled reports that the progress view exited before the scan's
// final message arrived, typically because the user pressed Ctrl+C. The scan
// itself observes context cancellation independently through the caller's
// completion channel.
var ErrViewCanceled = errors.New("progress view canceled")

// RunProgress renders live analyzer progress until the program exits because
// the scan finished or the user canceled it. The target is display-only and
// is minimized before rendering; the scanner's exact target never passes
// through here. The msgs channel must deliver exactly one final Msg (with
// Final set) and then be closed by the producer. It returns ErrViewCanceled
// when the view exits early; the authoritative scan outcome stays with the
// caller's own completion channel.
func RunProgress(ctx context.Context, output io.Writer, sources []string, target string, msgs <-chan Msg) error {
	model := newProgressModel(sources, target, msgs)
	program := tea.NewProgram(
		model,
		tea.WithOutput(output),
		tea.WithContext(ctx),
		tea.WithoutSignalHandler(),
	)
	finalModel, err := program.Run()
	// The application context owns process cancellation. Prefer it over any
	// concurrent framework result so callers get deterministic classification.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("run progress view: %w", err)
	}
	finished, ok := finalModel.(progressModel)
	if !ok || finished.outcome == nil {
		// A clean quit without the final message means user cancellation:
		// bubbletea reports no error for a model-initiated tea.Quit.
		return ErrViewCanceled
	}
	return nil
}
