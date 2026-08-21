package httpanalyzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/pkg/model"
)

func TestCapabilityCoverageDerivation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		result         Result
		wantIncomplete []model.SignalType
		wantComplete   []model.SignalType
	}{
		{
			name:   "clean navigation declares every capability complete",
			result: Result{StatusCode: http.StatusOK},
			wantComplete: []model.SignalType{
				model.SignalTypeRedirect, model.SignalTypeNetworkResponse,
				model.SignalTypeResponseHeader, model.SignalTypeCookie,
				model.SignalTypePageContent, model.SignalTypeScriptURL,
				model.SignalTypeIframeURL, model.SignalTypeResourceHost,
			},
		},
		{
			name:   "raw body truncation bounds content and resource capabilities",
			result: Result{StatusCode: http.StatusOK, BodyTruncated: true},
			wantIncomplete: []model.SignalType{
				model.SignalTypePageContent, model.SignalTypeScriptURL,
				model.SignalTypeIframeURL, model.SignalTypeResourceHost,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeRedirect, model.SignalTypeNetworkResponse,
				model.SignalTypeResponseHeader, model.SignalTypeCookie,
			},
		},
		{
			name:   "decoded HTML truncation bounds content and resource capabilities",
			result: Result{StatusCode: http.StatusOK, HTMLTruncated: true},
			wantIncomplete: []model.SignalType{
				model.SignalTypePageContent, model.SignalTypeScriptURL,
				model.SignalTypeIframeURL, model.SignalTypeResourceHost,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeRedirect, model.SignalTypeNetworkResponse,
				model.SignalTypeResponseHeader, model.SignalTypeCookie,
			},
		},
		{
			name:   "failed HTML decoding bounds content and resource capabilities",
			result: Result{StatusCode: http.StatusOK, PageContentIncomplete: true, ResourcesIncomplete: true},
			wantIncomplete: []model.SignalType{
				model.SignalTypePageContent, model.SignalTypeScriptURL,
				model.SignalTypeIframeURL, model.SignalTypeResourceHost,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeRedirect, model.SignalTypeNetworkResponse,
				model.SignalTypeResponseHeader, model.SignalTypeCookie,
			},
		},
		{
			name:   "resource ceiling leaves page content conclusive",
			result: Result{StatusCode: http.StatusOK, ResourcesIncomplete: true},
			wantIncomplete: []model.SignalType{
				model.SignalTypeScriptURL, model.SignalTypeIframeURL, model.SignalTypeResourceHost,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeRedirect, model.SignalTypeNetworkResponse,
				model.SignalTypeResponseHeader, model.SignalTypeCookie, model.SignalTypePageContent,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			statuses := make(map[model.SignalType]analysis.CapabilityStatus)
			for _, capability := range capabilityCoverage(tt.result) {
				if _, duplicate := statuses[capability.SignalType]; duplicate {
					t.Fatalf("duplicate capability declaration for %q", capability.SignalType)
				}
				statuses[capability.SignalType] = capability.Status
			}
			for _, signalType := range tt.wantIncomplete {
				if got := statuses[signalType]; got != analysis.CapabilityIncomplete {
					t.Errorf("capability %q = %q, want incomplete", signalType, got)
				}
			}
			for _, signalType := range tt.wantComplete {
				if got := statuses[signalType]; got != analysis.CapabilityComplete {
					t.Errorf("capability %q = %q, want complete", signalType, got)
				}
			}
		})
	}
}

func TestObserveDeclaresCapabilitiesOnSuccessAndOmitsThemOnFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer server.Close()

	analyzer := analyzerForServer(t, server.URL, nil)
	observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: "http://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Capabilities) == 0 {
		t.Fatal("capabilities = empty, want declared coverage on success")
	}
	for _, capability := range observation.Capabilities {
		if capability.Status != analysis.CapabilityComplete {
			t.Errorf("capability %q = %q, want complete on clean navigation", capability.SignalType, capability.Status)
		}
	}

	failing := analyzerForServer(t, server.URL, nil)
	failingObservation, err := failing.Observe(context.Background(), analysis.Target{URL: "http://127.0.0.1:1/"})
	if err == nil {
		t.Fatal("Observe() error = nil, want forbidden-destination failure")
	}
	if len(failingObservation.Capabilities) != 0 {
		t.Errorf("failed observation declared %#v, want no declarations so execution-status fallback applies", failingObservation.Capabilities)
	}
}

func TestAnalyzeBodyTruncationSetsStructuredFlags(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>"+strings.Repeat("x", 256)+"</body></html>")
	}))
	defer server.Close()
	result, err := analyzerForServer(t, server.URL, func(config *Config) { config.MaxBodyBytes = 64 }).Analyze(context.Background(), "http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if !result.BodyTruncated {
		t.Fatalf("BodyTruncated = false, want true")
	}
	if result.HTMLTruncated || result.PageContentIncomplete || result.ResourcesIncomplete {
		t.Errorf("decoded flags = %t/%t/%t, want all clear: decoded evidence covers the full retained prefix",
			result.HTMLTruncated, result.PageContentIncomplete, result.ResourcesIncomplete)
	}
}

func TestAnalyzeResourceLimitSetsStructuredFlag(t *testing.T) {
	t.Parallel()
	var body strings.Builder
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&body, `<script src="/%d.js"></script>`, i)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body.String())
	}))
	defer server.Close()
	result, err := analyzerForServer(t, server.URL, func(config *Config) { config.MaxHTMLResources = 3 }).Analyze(context.Background(), "http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if !result.ResourcesIncomplete {
		t.Error("ResourcesIncomplete = false, want true after resource ceiling")
	}
	if result.BodyTruncated || result.HTMLTruncated || result.PageContentIncomplete {
		t.Errorf("content flags = %t/%t/%t, want all clear", result.BodyTruncated, result.HTMLTruncated, result.PageContentIncomplete)
	}
}

func TestAnalyzeCharsetFailureSetsStructuredFlags(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=definitely-unknown")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer server.Close()
	result, err := analyzerForServer(t, server.URL, nil).Analyze(context.Background(), "http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if !result.PageContentIncomplete || !result.ResourcesIncomplete {
		t.Fatalf("incomplete flags = %t/%t, want both set after local HTML failure", result.PageContentIncomplete, result.ResourcesIncomplete)
	}
	if len(result.Warnings) == 0 {
		t.Error("warnings = empty, want charset diagnostic")
	}
}
