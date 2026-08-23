package analysis

import (
	"slices"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

func TestImplementedCapabilityContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   []model.SignalType
	}{
		{
			name:   "HTTP",
			source: SourceHTTP,
			want: []model.SignalType{
				model.SignalTypeCookie,
				model.SignalTypeIframeURL,
				model.SignalTypeNetworkResponse,
				model.SignalTypePageContent,
				model.SignalTypeRedirect,
				model.SignalTypeResourceHost,
				model.SignalTypeResponseHeader,
				model.SignalTypeScriptURL,
			},
		},
		{
			name:   "DNS and TLS",
			source: SourceDNSTLS,
			want: []model.SignalType{
				model.SignalTypeDNSRecord,
				model.SignalTypeTLSProperty,
			},
		},
		{
			name:   "Browser",
			source: SourceBrowser,
			want: []model.SignalType{
				model.SignalTypeCookie,
				model.SignalTypeIframeURL,
				model.SignalTypeNetworkRequest,
				model.SignalTypeNetworkResponse,
				model.SignalTypePageContent,
				model.SignalTypeScriptURL,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SupportedSignalTypes(tt.source); !slices.Equal(got, tt.want) {
				t.Fatalf("SupportedSignalTypes(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}

	for _, unsupported := range []model.SignalType{
		model.SignalTypeDOMSelector,
		model.SignalTypeJSGlobal,
		model.SignalTypeResourceHost,
	} {
		if slices.Contains(SupportedSignalTypes(SourceBrowser), unsupported) {
			t.Errorf("Browser unexpectedly supports %q", unsupported)
		}
	}
}

func TestImplementedCapabilitiesReturnsCopy(t *testing.T) {
	t.Parallel()
	first := ImplementedCapabilities()
	first[0] = Capability{Source: "mutated", SignalType: model.SignalTypeJSGlobal}
	if slices.Equal(first, ImplementedCapabilities()) {
		t.Fatal("ImplementedCapabilities returned shared mutable state")
	}
}
