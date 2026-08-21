package tui

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

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

	model = update(t, model, eventMsg(scanner.ScanEvent{
		Source: "http_analyzer", Kind: scanner.ScanEventStarted,
	}))
	view := model.View().Content
	if !strings.Contains(view, "HTTP analysis…") {
		t.Errorf("running view = %q, want running HTTP stage", view)
	}

	model = update(t, model, eventMsg(scanner.ScanEvent{
		Source: "http_analyzer", Kind: scanner.ScanEventCompleted,
	}))
	view = model.View().Content
	if !strings.Contains(view, "✔ HTTP analysis") {
		t.Errorf("completed view = %q, want completed HTTP stage", view)
	}
	if strings.Contains(view, "✔ DNS/TLS analysis") {
		t.Errorf("view = %q, want DNS/TLS still pending", view)
	}
}

func TestProgressModelShowsFailedAnalyzerError(t *testing.T) {
	t.Parallel()
	model := newTestModel()

	model = update(t, model, eventMsg(scanner.ScanEvent{
		Source: "dns_tls_analyzer", Kind: scanner.ScanEventFailed,
		Err: errors.New("lookup exploded\nsecond line"),
	}))
	view := model.View().Content
	if !strings.Contains(view, "✘ DNS/TLS analysis") {
		t.Errorf("view = %q, want failed DNS/TLS stage", view)
	}
	if !strings.Contains(view, "lookup exploded") {
		t.Errorf("view = %q, want first error line", view)
	}
	if strings.Contains(view, "second line") {
		t.Errorf("view = %q, want only the first error line", view)
	}
}

func TestProgressModelMarksUnfinishedStagesOnFailure(t *testing.T) {
	t.Parallel()
	model := newTestModel()
	model = update(t, model, eventMsg(scanner.ScanEvent{
		Source: "http_analyzer", Kind: scanner.ScanEventCompleted,
	}))

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
		model = update(t, model, eventMsg(scanner.ScanEvent{
			Source: source, Kind: scanner.ScanEventCompleted,
		}))
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
