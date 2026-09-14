//go:build browser_integration

package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/browser"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/scoring"
	"github.com/gkehren/hemera/pkg/model"
)

// formInteractionHarness serves inline pages over an httptest server that
// accepts POST routes, wires the full HTTP+browser pipeline with the opt-in
// bounded form interaction phase, and runs one scan.
type formInteractionHarness struct {
	engine    *Scanner
	serverURL string
}

func newFormInteractionHarness(t *testing.T, enableForms bool, pages map[string]http.HandlerFunc) (*formInteractionHarness, func()) {
	t.Helper()
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	for pattern, handler := range pages {
		mux.HandleFunc(pattern, handler)
	}
	server := httptest.NewServer(mux)

	localURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := fixtureResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	})
	dialer := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, localURL.Host)
	}
	httpConfig := httpanalyzer.DefaultConfig()
	httpConfig.Resolver = resolver
	httpConfig.Dialer = dialer
	httpAnalyzer, err := httpanalyzer.New(httpConfig)
	if err != nil {
		t.Fatal(err)
	}
	browserConfig := browser.DefaultConfig()
	browserConfig.StartupTimeout = 20 * time.Second
	browserConfig.ExecutablePath, _ = integrationBrowserPath(t)
	browserConfig.Resolver = resolver
	browserConfig.Dialer = dialer
	browserConfig.Forms = enableForms
	browserAnalyzer, err := browser.NewAnalyzer(browserConfig)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{
		Analyzers: []AnalyzerConfig{
			{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
			{Analyzer: browserAnalyzer, FailurePolicy: FailurePolicyContinue},
		},
		RuleSet: ruleSet,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(localURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	return &formInteractionHarness{engine: engine, serverURL: "http://fixture.example:" + port + "/"}, server.Close
}

func (h *formInteractionHarness) run(t *testing.T) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := h.engine.Scan(ctx, h.serverURL)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// TestBrowserFormSubmissionInteractionDetectsDataDomeReaction exercises the
// datadome.form_reaction rule end to end: the opt-in bounded form interaction
// phase submits one eligible same-origin form, the POST is answered 403 with a
// DataDome interstitial marker, and all three evidence groups must be present.
func TestBrowserFormSubmissionInteractionDetectsDataDomeReaction(t *testing.T) {
	denied := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "form action expects POST", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>DataDome CAPTCHA</title></head><body>
<script src="https://geo.captcha-delivery.com/captcha.js"></script>
<div>DataDome CAPTCHA verification required</div></body></html>`))
	}
	harness, closeServer := newFormInteractionHarness(t, true, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Contact</title></head><body>
<form method="POST" action="/contact">
  <input type="text" name="name">
  <input type="email" name="email">
  <textarea name="message"></textarea>
  <button type="submit">Send</button>
</form>
</body></html>`))
		},
		"/contact": denied,
	})
	defer closeServer()

	result := harness.run(t)
	if len(result.Analyzers) != 2 || result.Analyzers[1].Observation.Source != analysis.SourceBrowser {
		t.Fatalf("analyzers = %#v", result.Analyzers)
	}

	var submissions, transactions int
	for _, signal := range result.Signals {
		switch signal.Type {
		case model.SignalTypeFormSubmission:
			submissions++
			if !strings.HasSuffix(signal.Value, "/contact") {
				t.Errorf("form submission value = %q, want the cleaned contact action", signal.Value)
			}
		case model.SignalTypeNetworkTransaction:
			transactions++
			if signal.Key != "POST" || signal.Value != "403" {
				t.Errorf("transaction signal = %s/%s, want POST/403", signal.Key, signal.Value)
			}
		}
	}
	if submissions != 1 {
		t.Errorf("form_submission signals = %d, want exactly one", submissions)
	}
	if transactions != 1 {
		t.Errorf("network_transaction signals = %d, want exactly one", transactions)
	}

	var reaction *scoring.Detection
	for index := range result.Detections {
		if result.Detections[index].RuleID == "datadome.form_reaction" {
			reaction = &result.Detections[index]
		}
	}
	if reaction == nil {
		t.Fatalf("datadome.form_reaction detection missing: %#v", result.Detections)
	}
	if !reaction.Detected {
		t.Fatalf("datadome.form_reaction not detected: score %v level %v", reaction.Score, reaction.Level)
	}
	if reaction.Score != 90 {
		t.Errorf("datadome.form_reaction score = %v, want 90", reaction.Score)
	}
	var evidenceIDs []string
	for _, evidence := range reaction.PositiveEvidence {
		evidenceIDs = append(evidenceIDs, evidence.Match.EvidenceID)
	}
	for _, want := range []string{"datadome-form-submitted", "datadome-form-post-denied", "datadome-reaction-marker"} {
		if !slices.Contains(evidenceIDs, want) {
			t.Errorf("evidence %v missing %q", evidenceIDs, want)
		}
	}
}

// TestBrowserFormSubmissionSkipsCredentialForms verifies the eligibility
// guard: a page whose only form collects a password is observed passively and
// never submitted.
func TestBrowserFormSubmissionSkipsCredentialForms(t *testing.T) {
	hits := 0
	harness, closeServer := newFormInteractionHarness(t, true, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Sign in</title></head><body>
<form method="POST" action="/signin">
  <input type="text" name="user">
  <input type="password" name="secret">
  <button type="submit">Sign in</button>
</form>
</body></html>`))
		},
		"/signin": func(w http.ResponseWriter, r *http.Request) {
			hits++
			_, _ = w.Write([]byte("should never be reached"))
		},
	})
	defer closeServer()

	result := harness.run(t)
	if hits != 0 {
		t.Errorf("credential form was submitted %d time(s)", hits)
	}
	for _, signal := range result.Signals {
		if signal.Type == model.SignalTypeFormSubmission || signal.Type == model.SignalTypeNetworkTransaction {
			t.Errorf("unexpected interaction signal %#v", signal)
		}
	}
}
