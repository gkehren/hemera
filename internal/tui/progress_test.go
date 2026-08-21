package tui

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/gkehren/hemera/internal/safeoutput"
	"github.com/gkehren/hemera/internal/scanner"
)

func newTestModel() progressModel {
	return newProgressModel(
		[]string{"http_analyzer", "dns_tls_analyzer", "browser_analyzer"},
		"https://example.test/",
		nil,
	)
}

func eventMsg(event scanner.ScanEvent) progressEventMsg {
	return progressEventMsg(Msg{Event: event})
}

func startedEvent(source string) progressEventMsg {
	return eventMsg(scanner.ScanEvent{Source: source, Kind: scanner.ScanEventStarted})
}

func finishedEvent(source string, status scanner.AnalyzerStatus) progressEventMsg {
	return eventMsg(scanner.ScanEvent{Source: source, Kind: scanner.ScanEventFinished, Status: status})
}

func finalMsg(outcome Outcome) progressEventMsg {
	return progressEventMsg(Msg{Final: true, Outcome: outcome})
}

func update(t *testing.T, model progressModel, msg tea.Msg) progressModel {
	t.Helper()
	updated, _ := model.Update(msg)
	next, ok := updated.(progressModel)
	if !ok {
		t.Fatalf("Update returned %T, want progressModel", updated)
	}
	return next
}

func TestProgressModelTracksStageLifecycle(t *testing.T) {
	t.Parallel()
	model := newTestModel()

	model = update(t, model, startedEvent("http_analyzer"))
	view := model.View().Content
	if !strings.Contains(view, "HTTP analysis…") {
		t.Errorf("running view = %q, want running HTTP stage", view)
	}

	model = update(t, model, finishedEvent("http_analyzer", scanner.AnalyzerStatusComplete))
	view = model.View().Content
	if !strings.Contains(view, "✔ HTTP analysis") {
		t.Errorf("completed view = %q, want completed HTTP stage", view)
	}
	if strings.Contains(view, "✔ DNS/TLS analysis") {
		t.Errorf("view = %q, want DNS/TLS still pending", view)
	}
}

func TestProgressModelShowsSafeTextForFailedAnalyzer(t *testing.T) {
	t.Parallel()
	model := newTestModel()

	model = update(t, model, finishedEvent("dns_tls_analyzer", scanner.AnalyzerStatusFailed))
	view := model.View().Content
	if !strings.Contains(view, "✘ DNS/TLS analysis") {
		t.Errorf("view = %q, want failed DNS/TLS stage", view)
	}
	if !strings.Contains(view, failedStageDetail) {
		t.Errorf("view = %q, want the controlled failure detail", view)
	}
}

// TestProgressModelRendersPartialDistinctFromFailed covers the review
// requirement: an analyzer with useful evidence plus a non-fatal error must
// render as partial, never as a complete failure.
func TestProgressModelRendersPartialDistinctFromFailed(t *testing.T) {
	t.Parallel()
	model := newTestModel()

	model = update(t, model, startedEvent("browser_analyzer"))
	model = update(t, model, finishedEvent("browser_analyzer", scanner.AnalyzerStatusPartial))
	view := model.View().Content
	if !strings.Contains(view, "◐ Browser analysis") || !strings.Contains(view, "partial") {
		t.Errorf("view = %q, want a distinct partial stage", view)
	}
	if strings.Contains(view, "✘") || strings.Contains(view, failedStageDetail) {
		t.Errorf("view = %q, want partial not rendered as failure", view)
	}
}

func TestProgressModelNeverShowsRawErrors(t *testing.T) {
	t.Parallel()
	model := newTestModel()
	model = update(t, model, eventMsg(scanner.ScanEvent{
		Source: "browser_analyzer", Kind: scanner.ScanEventStarted,
	}))
	model = update(t, model, finalMsg(Outcome{
		Err: errors.New("navigation failed for https://example.test/?token=secret\nANSI\x1b[31mred"),
	}))

	view := model.View().Content
	for _, leaked := range []string{"token=secret", "\x1b[31m", "navigation failed"} {
		if strings.Contains(view, leaked) {
			t.Errorf("view leaks analyzer error detail %q:\n%s", leaked, view)
		}
	}
	if !strings.Contains(view, failedStageDetail) {
		t.Errorf("view = %q, want the controlled failure detail", view)
	}
}

func TestProgressModelMarksUnfinishedStagesOnFailure(t *testing.T) {
	t.Parallel()
	model := newTestModel()
	model = update(t, model, finishedEvent("http_analyzer", scanner.AnalyzerStatusComplete))

	model = update(t, model, finalMsg(Outcome{Err: errors.New("boom")}))
	view := model.View().Content
	if !strings.Contains(view, "✔ HTTP analysis") {
		t.Errorf("view = %q, want completed HTTP stage preserved", view)
	}
	if strings.Count(view, "✘") != 2 {
		t.Errorf("view = %q, want two failed unfinished stages", view)
	}
}

func TestProgressModelIgnoresUnknownSource(t *testing.T) {
	t.Parallel()
	model := newTestModel()
	model = update(t, model, eventMsg(scanner.ScanEvent{
		Source: "mystery_analyzer", Kind: scanner.ScanEventStarted,
	}))
	view := model.View().Content
	if strings.Contains(view, "mystery analyzer") {
		t.Errorf("view = %q, want unknown source ignored", view)
	}
	if !strings.Contains(view, "○ HTTP analysis") {
		t.Errorf("view = %q, want stages untouched", view)
	}
}

func TestProgressModelCancelViaCtrlC(t *testing.T) {
	t.Parallel()
	model := newTestModel()

	updated, cmd := model.Update(tea.KeyPressMsg{Mod: tea.ModCtrl, Code: 'c'})
	canceled, ok := updated.(progressModel)
	if !ok {
		t.Fatalf("Update returned %T, want progressModel", updated)
	}
	if !canceled.canceled {
		t.Fatal("ctrl+c did not set the canceled flag")
	}
	if canceled.outcome != nil {
		t.Fatal("ctrl+c stored an outcome; RunProgress would treat it as completion")
	}
	if cmd == nil {
		t.Fatal("ctrl+c did not return a quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("cmd() = %#v, want tea.QuitMsg", cmd())
	}
	if !strings.Contains(canceled.View().Content, "Scan canceled by user.") {
		t.Errorf("view = %q, want cancellation notice", canceled.View().Content)
	}
}

func TestProgressModelDoneWithoutErrorKeepsStates(t *testing.T) {
	t.Parallel()
	model := newTestModel()
	model = update(t, model, eventMsg(scanner.ScanEvent{
		Source: "browser_analyzer", Kind: scanner.ScanEventStarted,
	}))

	model = update(t, model, finalMsg(Outcome{}))
	view := model.View().Content
	if !strings.Contains(view, "○ HTTP analysis") || !strings.Contains(view, "○ DNS/TLS analysis") {
		t.Errorf("view = %q, want pending stages preserved", view)
	}
	if strings.Contains(view, "✘") {
		t.Errorf("view = %q, want no failed stages on success", view)
	}
}

func TestProgressModelShowsFullBarOnSuccess(t *testing.T) {
	t.Parallel()
	model := newTestModel()
	for _, source := range []string{"http_analyzer", "dns_tls_analyzer", "browser_analyzer"} {
		model = update(t, model, eventMsg(scanner.ScanEvent{
			Source: source, Kind: scanner.ScanEventStarted,
		}))
		model = update(t, model, finishedEvent(source, scanner.AnalyzerStatusComplete))
	}

	if strings.Contains(model.View().Content, "100%") {
		t.Fatalf("view shows 100%% before the final message: %q", model.View().Content)
	}
	model = update(t, model, finalMsg(Outcome{}))
	view := model.View().Content
	if !strings.Contains(view, "100%") {
		t.Errorf("final view = %q, want the bar settled at 100%%", view)
	}
}

func TestStageLabelFallback(t *testing.T) {
	t.Parallel()
	if got := stageLabel("custom_source"); got != "custom source" {
		t.Errorf("stageLabel() = %q, want %q", got, "custom source")
	}
}

// TestProgressModelRedactsTargetQuery proves the view never echoes a raw
// target query string, even when constructed with one.
func TestProgressModelRedactsTargetQuery(t *testing.T) {
	t.Parallel()
	model := newProgressModel([]string{"http_analyzer"},
		"https://example.test/api?token=SUPER_SECRET", nil)
	content := model.View().Content
	if strings.Contains(content, "SUPER_SECRET") || strings.Contains(content, "token=") {
		t.Errorf("view leaks the target query: %q", content)
	}
	if !strings.Contains(content, "https://example.test/api?redacted") {
		t.Errorf("view lacks minimized target: %q", content)
	}
}

func TestProgressModelRemovesCredentialsAndFragments(t *testing.T) {
	t.Parallel()
	model := newProgressModel([]string{"http_analyzer"},
		"https://user:password@example.test/path?x=y#fragment", nil)
	content := model.View().Content
	for _, leaked := range []string{"user:", "password", "x=y", "#fragment", "fragment"} {
		if strings.Contains(content, leaked) {
			t.Errorf("view leaks %q: %q", leaked, content)
		}
	}
	if !strings.Contains(content, "https://example.test/path?redacted") {
		t.Errorf("view lacks minimized target: %q", content)
	}
}

func TestProgressModelKeepsPlainTargetsReadable(t *testing.T) {
	t.Parallel()
	model := newProgressModel([]string{"http_analyzer"}, "https://example.test/path", nil)
	if content := model.View().Content; !strings.Contains(content, "https://example.test/path") {
		t.Errorf("view over-redacted plain target: %q", content)
	}
}

func TestProgressModelReplacesUnparseableTarget(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"not a url", "", "ftp://example.test/"} {
		model := newProgressModel([]string{"http_analyzer"}, raw, nil)
		content := model.View().Content
		if !strings.Contains(content, safeoutput.InvalidTargetPlaceholder) {
			t.Errorf("view for %q lacks placeholder: %q", raw, content)
		}
		if strings.Contains(content, raw) && raw != "" {
			t.Errorf("view echoed unparseable target %q: %q", raw, content)
		}
	}
}
