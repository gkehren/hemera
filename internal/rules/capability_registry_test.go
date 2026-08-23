package rules

import (
	"errors"
	"slices"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/pkg/model"
)

func TestValidateRuleSetCapabilities(t *testing.T) {
	t.Parallel()
	registry, err := DefaultCapabilityRegistry()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		signalType model.SignalType
		source     string
		ignoreCase bool
		wantError  bool
	}{
		{
			name: "Browser JS global has no producer", signalType: model.SignalTypeJSGlobal,
			source: analysis.SourceBrowser, wantError: true,
		},
		{
			name: "Browser script URL is supported", signalType: model.SignalTypeScriptURL,
			source: analysis.SourceBrowser,
		},
		{
			name: "HTTP response header is supported", signalType: model.SignalTypeResponseHeader,
			source: analysis.SourceHTTP,
		},
		{
			name: "case insensitive HTTP response header is supported", signalType: model.SignalTypeResponseHeader,
			source: "HTTP_ANALYZER", ignoreCase: true,
		},
		{
			name: "case sensitive uppercase HTTP source is unsupported", signalType: model.SignalTypeResponseHeader,
			source: "HTTP_ANALYZER", wantError: true,
		},
		{
			name: "DNS TLS property is supported", signalType: model.SignalTypeTLSProperty,
			source: analysis.SourceDNSTLS,
		},
		{
			name: "Browser resource host has no producer", signalType: model.SignalTypeResourceHost,
			source: analysis.SourceBrowser, wantError: true,
		},
		{
			name: "source agnostic unsupported type", signalType: model.SignalTypeDOMSelector,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ruleSet := validRuleSet()
			ruleSet.Rules[0].Match.Signal.Type = tt.signalType
			ruleSet.Rules[0].Match.Signal.Source = nil
			if tt.source != "" {
				ruleSet.Rules[0].Match.Signal.Source = exact(tt.source)
				ruleSet.Rules[0].Match.Signal.Source.CaseInsensitive = tt.ignoreCase
			}
			err := ValidateRuleSetCapabilities(ruleSet, registry)
			if tt.wantError && !errors.Is(err, ErrUnsupportedCapability) {
				t.Fatalf("ValidateRuleSetCapabilities() error = %v, want ErrUnsupportedCapability", err)
			}
			if !tt.wantError && err != nil {
				t.Fatalf("ValidateRuleSetCapabilities() error = %v", err)
			}
		})
	}
}

func TestValidateRuleSetCapabilitiesChecksPenaltyEvidence(t *testing.T) {
	t.Parallel()
	registry, err := DefaultCapabilityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	ruleSet := validRuleSet()
	unsupported := Evidence{
		ID: "global", Type: model.SignalTypeJSGlobal,
		Source: exact(analysis.SourceBrowser), Key: exact("unsupported"), Weight: 10,
	}
	ruleSet.Rules[0].NegativeEvidence = []Evidence{unsupported}
	if err := ValidateRuleSetCapabilities(ruleSet, registry); !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("negative evidence error = %v, want ErrUnsupportedCapability", err)
	}
	ruleSet.Rules[0].NegativeEvidence = nil
	ruleSet.Rules[0].AmbiguousEvidence = []Evidence{unsupported}
	if err := ValidateRuleSetCapabilities(ruleSet, registry); !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("ambiguous evidence error = %v, want ErrUnsupportedCapability", err)
	}
}

func TestCapabilityRegistrySupportsExtensionsAndReturnsCopies(t *testing.T) {
	t.Parallel()
	capabilities := analysis.ImplementedCapabilities()
	capabilities = append(capabilities, analysis.Capability{
		Source: "extension_analyzer", SignalType: model.SignalTypeJSGlobal,
	}, analysis.Capability{
		Source: "EXTENSION_ANALYZER", SignalType: model.SignalTypeJSGlobal,
	})
	registry, err := NewCapabilityRegistry(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.Supports("extension_analyzer", model.SignalTypeJSGlobal) {
		t.Fatal("extension capability is not registered")
	}
	extensionSource := "extension_analyzer"
	caseInsensitiveExact := Evidence{
		Type: model.SignalTypeJSGlobal,
		Source: &TextPattern{
			Exact: &extensionSource, CaseInsensitive: true,
		},
	}
	if got, want := registry.CapableSources(caseInsensitiveExact), []string{"EXTENSION_ANALYZER", "extension_analyzer"}; !slices.Equal(got, want) {
		t.Fatalf("case-insensitive extension sources = %v, want %v", got, want)
	}
	returned := registry.Capabilities()
	returned[0] = analysis.Capability{Source: "mutated", SignalType: model.SignalTypeDOMSelector}
	if slices.Equal(returned, registry.Capabilities()) {
		t.Fatal("Capabilities returned shared mutable state")
	}
}

func TestNewCapabilityRegistryRejectsMalformedDeclarations(t *testing.T) {
	t.Parallel()
	for _, capability := range []analysis.Capability{
		{Source: " ", SignalType: model.SignalTypeScriptURL},
		{Source: "source", SignalType: "unknown"},
	} {
		if _, err := NewCapabilityRegistry([]analysis.Capability{capability}); !errors.Is(err, ErrInvalidCapabilityRegistry) {
			t.Errorf("NewCapabilityRegistry(%#v) error = %v, want ErrInvalidCapabilityRegistry", capability, err)
		}
	}
}
