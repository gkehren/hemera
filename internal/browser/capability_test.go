package browser

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/pkg/model"
)

func TestCaptureCleanChannelsReportCompleteTruncationState(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	collector.addRequest("GET", "https://example.test/", "Document")
	collector.addResponse("https://example.test/", 200, "text/html", "Document")
	result := collector.snapshot("https://example.test/", "<html><body>ok</body></html>", []CaptureCookie{
		{Name: "session", Domain: "example.test"},
	})
	if result.RequestsTruncated || result.ResponsesTruncated || result.ScriptURLsTruncated ||
		result.IframeURLsTruncated || result.CookiesTruncated || result.DOMTruncated {
		t.Fatalf("clean capture reported truncation: %#v", result)
	}
}

func TestCaptureOversizedURLTruncatesOnlyItsOwnChannel(t *testing.T) {
	t.Parallel()
	longURL := "https://example.test/" + strings.Repeat("x", maxBrowserURLBytes)

	t.Run("oversized request URL marks requests incomplete", func(t *testing.T) {
		t.Parallel()
		collector := newCaptureCollector()
		collector.addRequest("GET", longURL, "Fetch")
		collector.addResponse("https://example.test/", 200, "text/plain", "Fetch")
		result := collector.snapshot("https://example.test/", "", nil)
		if !result.RequestsTruncated {
			t.Error("RequestsTruncated = false, want true after oversized request URL")
		}
		if result.ResponsesTruncated || result.ScriptURLsTruncated || result.IframeURLsTruncated {
			t.Errorf("unrelated channels marked truncated: responses %t scripts %t iframes %t",
				result.ResponsesTruncated, result.ScriptURLsTruncated, result.IframeURLsTruncated)
		}
	})

	t.Run("oversized response URL marks responses incomplete", func(t *testing.T) {
		t.Parallel()
		collector := newCaptureCollector()
		collector.addResponse(longURL, 200, "text/plain", "Fetch")
		result := collector.snapshot("https://example.test/", "", nil)
		if !result.ResponsesTruncated {
			t.Error("ResponsesTruncated = false, want true after oversized response URL")
		}
		if result.RequestsTruncated {
			t.Error("RequestsTruncated = true, want clear")
		}
	})

	t.Run("oversized static resource marks its resource channel incomplete", func(t *testing.T) {
		t.Parallel()
		collector := newCaptureCollector()
		dom := fmt.Sprintf(`<script src="%s"></script><iframe src="https://example.test/frame"></iframe>`, longURL)
		result := collector.snapshot("https://example.test/", dom, nil)
		if !result.ScriptURLsTruncated {
			t.Error("ScriptURLsTruncated = false, want true after oversized script URL")
		}
		if result.IframeURLsTruncated {
			t.Error("IframeURLsTruncated = true, want clear for valid iframe")
		}
	})
}

func TestBrowserCapabilityCoverageDerivation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                string
		result              CaptureResult
		normalizationFailed bool
		wantIncomplete      []model.SignalType
		wantComplete        []model.SignalType
	}{
		{
			name:   "clean navigation declares every capability complete",
			result: CaptureResult{FinalURL: "https://example.test/"},
			wantComplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypeNetworkResponse,
				model.SignalTypePageContent, model.SignalTypeScriptURL,
				model.SignalTypeIframeURL, model.SignalTypeCookie,
			},
		},
		{
			name:   "failed navigation leaves every capability inconclusive",
			result: CaptureResult{FinalURL: "https://example.test/", NavigationIncomplete: true},
			wantIncomplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypeNetworkResponse,
				model.SignalTypePageContent, model.SignalTypeScriptURL,
				model.SignalTypeIframeURL, model.SignalTypeCookie,
			},
		},
		{
			name:                "signal normalization failure leaves every capability inconclusive",
			result:              CaptureResult{FinalURL: "https://example.test/"},
			normalizationFailed: true,
			wantIncomplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypeNetworkResponse,
				model.SignalTypePageContent, model.SignalTypeScriptURL,
				model.SignalTypeIframeURL, model.SignalTypeCookie,
			},
		},
		{
			name: "DOM truncation scopes incompleteness to page content",
			result: CaptureResult{
				FinalURL: "https://example.test/", DOMTruncated: true,
			},
			wantIncomplete: []model.SignalType{
				model.SignalTypePageContent,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypeNetworkResponse,
				model.SignalTypeScriptURL, model.SignalTypeIframeURL, model.SignalTypeCookie,
			},
		},
		{
			name: "DOM collection failure scopes incompleteness to DOM-derived channels",
			result: CaptureResult{
				FinalURL: "https://example.test/", DOMIncomplete: true,
			},
			wantIncomplete: []model.SignalType{
				model.SignalTypePageContent, model.SignalTypeScriptURL, model.SignalTypeIframeURL,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypeNetworkResponse, model.SignalTypeCookie,
			},
		},
		{
			name: "lost final URL scopes incompleteness to final-URL provenance",
			result: CaptureResult{
				FinalURL: "", FinalURLIncomplete: true,
			},
			wantIncomplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypePageContent,
				model.SignalTypeScriptURL, model.SignalTypeIframeURL, model.SignalTypeCookie,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeNetworkResponse,
			},
		},
		{
			name: "cookie collection failure stays scoped to cookies",
			result: CaptureResult{
				FinalURL: "https://example.test/", CookiesIncomplete: true,
			},
			wantIncomplete: []model.SignalType{
				model.SignalTypeCookie,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypeNetworkResponse,
				model.SignalTypePageContent, model.SignalTypeScriptURL, model.SignalTypeIframeURL,
			},
		},
		{
			name: "per-channel ceilings scope incompleteness independently",
			result: CaptureResult{
				FinalURL:          "https://example.test/",
				RequestsTruncated: true, CookiesTruncated: true,
			},
			wantIncomplete: []model.SignalType{
				model.SignalTypeNetworkRequest, model.SignalTypeCookie,
			},
			wantComplete: []model.SignalType{
				model.SignalTypeNetworkResponse, model.SignalTypePageContent,
				model.SignalTypeScriptURL, model.SignalTypeIframeURL,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			statuses := make(map[model.SignalType]analysis.CapabilityStatus)
			for _, capability := range browserCapabilityCoverage(tt.result, tt.normalizationFailed) {
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

func TestObserveDeclaresCapabilitiesFromCaptureState(t *testing.T) {
	t.Parallel()

	t.Run("unavailable client declares no capabilities", func(t *testing.T) {
		t.Parallel()
		analyzer := newAnalyzer(nil)
		observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: "https://example.test/"})
		if err == nil {
			t.Fatal("Observe() error = nil, want unavailable client failure")
		}
		if len(observation.Capabilities) != 0 {
			t.Fatalf("unavailable observation declared %#v, want no declarations", observation.Capabilities)
		}
	})

	t.Run("successful capture declares per-channel coverage", func(t *testing.T) {
		t.Parallel()
		source := &fakeCaptureSource{result: CaptureResult{
			FinalURL: "https://example.test/",
			DOM:      "<html><body>ok</body></html>",
			Requests: []CaptureRequest{{Method: "GET", URL: "https://example.test/"}},
		}}
		analyzer := analyzerForBackend(t, newFakeAnalyzerBackend(source, nil))
		observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: "https://example.test/"})
		if err != nil {
			t.Fatal(err)
		}
		if len(observation.Capabilities) == 0 {
			t.Fatal("capabilities = empty, want declared coverage")
		}
		for _, capability := range observation.Capabilities {
			if capability.Status != analysis.CapabilityComplete {
				t.Errorf("capability %q = %q, want complete on clean capture",
					capability.SignalType, capability.Status)
			}
		}
	})

	t.Run("isolated channel failure does not downgrade unrelated capabilities", func(t *testing.T) {
		t.Parallel()
		// Regression: a failed Storage.getCookies call must not mark the
		// network or DOM channels inconclusive; the aggregated finish error
		// is an analyzer-status input, not a coverage proxy.
		source := &fakeCaptureSource{result: CaptureResult{
			FinalURL:          "https://example.test/",
			DOM:               "<html><body>ok</body></html>",
			Requests:          []CaptureRequest{{Method: "GET", URL: "https://example.test/"}},
			CookiesIncomplete: true,
		}}
		analyzer := analyzerForBackend(t, newFakeAnalyzerBackend(source, nil))
		observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: "https://example.test/"})
		if err != nil {
			t.Fatal(err)
		}
		statuses := make(map[model.SignalType]analysis.CapabilityStatus)
		for _, capability := range observation.Capabilities {
			statuses[capability.SignalType] = capability.Status
		}
		if got := statuses[model.SignalTypeCookie]; got != analysis.CapabilityIncomplete {
			t.Errorf("cookie capability = %q, want incomplete after cookie collection failure", got)
		}
		for _, signalType := range []model.SignalType{
			model.SignalTypeNetworkRequest, model.SignalTypeNetworkResponse,
			model.SignalTypePageContent, model.SignalTypeScriptURL, model.SignalTypeIframeURL,
		} {
			if got := statuses[signalType]; got != analysis.CapabilityComplete {
				t.Errorf("capability %q = %q, want complete despite cookie failure", signalType, got)
			}
		}
	})

	t.Run("lost final URL keeps URL-provenance channels inconclusive", func(t *testing.T) {
		t.Parallel()
		longURL := "https://example.test/" + strings.Repeat("x", maxBrowserURLBytes)
		collector := newCaptureCollector()
		result := collector.snapshot(longURL, "<html><body>ok</body></html>", []CaptureCookie{
			{Name: "session", Domain: "example.test"},
		})
		if result.FinalURL != "" || !result.FinalURLIncomplete {
			t.Fatalf("final URL = %q incomplete=%t, want omitted with FinalURLIncomplete", result.FinalURL, result.FinalURLIncomplete)
		}
		analyzer := analyzerForBackend(t, newFakeAnalyzerBackend(&fakeCaptureSource{result: result}, nil))
		observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: longURL})
		if err != nil {
			t.Fatal(err)
		}
		statuses := make(map[model.SignalType]analysis.CapabilityStatus)
		for _, capability := range observation.Capabilities {
			statuses[capability.SignalType] = capability.Status
		}
		for _, signalType := range []model.SignalType{
			model.SignalTypeNetworkRequest, model.SignalTypePageContent,
			model.SignalTypeScriptURL, model.SignalTypeIframeURL, model.SignalTypeCookie,
		} {
			if got := statuses[signalType]; got != analysis.CapabilityIncomplete {
				t.Errorf("capability %q = %q, want incomplete after final URL loss", signalType, got)
			}
		}
		if got := statuses[model.SignalTypeNetworkResponse]; got != analysis.CapabilityComplete {
			t.Errorf("network response capability = %q, want complete despite final URL loss", got)
		}
	})

	t.Run("failed navigation with partial capture marks every capability incomplete", func(t *testing.T) {
		t.Parallel()
		source := &fakeCaptureSource{result: CaptureResult{
			FinalURL: "https://example.test/",
			Cookies:  []CaptureCookie{{Name: "partial_cookie", Domain: "example.test"}},
		}}
		analyzer := analyzerForBackend(t, newFakeAnalyzerBackend(source, errors.New("navigation budget exceeded")))
		observation, err := analyzer.Observe(context.Background(), analysis.Target{URL: "https://example.test/"})
		if err == nil {
			t.Fatal("Observe() error = nil, want navigation failure")
		}
		if len(observation.Capabilities) == 0 {
			t.Fatal("capabilities = empty, want conservative declarations on partial capture")
		}
		for _, capability := range observation.Capabilities {
			if capability.Status != analysis.CapabilityIncomplete {
				t.Errorf("capability %q = %q, want incomplete after failed navigation",
					capability.SignalType, capability.Status)
			}
		}
	})
}
