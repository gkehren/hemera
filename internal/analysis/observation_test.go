package analysis

import (
	"slices"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

func TestObservationCloneOwnsSlicesAndMetadata(t *testing.T) {
	t.Parallel()
	original := Observation{
		Source: "fixture",
		Signals: []model.Signal{{
			Type: model.SignalTypeScriptURL, Source: "fixture", Key: "src", Confidence: 1,
		}},
		Warnings: []string{"fixture warning"},
		Metadata: Metadata{HTTP: &HTTPMetadata{
			RequestedURL: "https://example.test/",
			TLS:          &TLSMetadata{DNSNames: []string{"example.test"}},
			Redirects: []HTTPRedirect{{
				From: "https://example.test/", To: "https://example.test/final", Status: 302,
			}},
		}},
	}
	cloned := original.Clone()
	original.Signals[0].Key = "changed"
	original.Warnings[0] = "changed"
	original.Metadata.HTTP.Redirects[0].To = "https://changed.test/"
	original.Metadata.HTTP.TLS.DNSNames[0] = "changed.test"

	if cloned.Signals[0].Key != "src" || cloned.Warnings[0] != "fixture warning" ||
		cloned.Metadata.HTTP.Redirects[0].To != "https://example.test/final" ||
		cloned.Metadata.HTTP.TLS.DNSNames[0] != "example.test" {
		t.Fatalf("Clone() retained analyzer-owned slices: %#v", cloned)
	}
	if !slices.Equal(cloned.Metadata.Kinds(), []MetadataKind{MetadataKindHTTP}) || cloned.Metadata.Empty() {
		t.Errorf("metadata kinds/empty = %v/%t", cloned.Metadata.Kinds(), cloned.Metadata.Empty())
	}
}

func TestEmptyMetadataHasNoKinds(t *testing.T) {
	t.Parallel()
	metadata := Metadata{}
	if !metadata.Empty() || len(metadata.Kinds()) != 0 {
		t.Errorf("empty metadata kinds/empty = %v/%t", metadata.Kinds(), metadata.Empty())
	}
}

func TestObservationCloneOwnsCapabilities(t *testing.T) {
	t.Parallel()
	original := Observation{
		Source: "fixture",
		Capabilities: []CapabilityCoverage{
			{SignalType: model.SignalTypePageContent, Status: CapabilityComplete},
		},
	}
	cloned := original.Clone()
	original.Capabilities[0].Status = CapabilityIncomplete

	if cloned.Capabilities[0].Status != CapabilityComplete {
		t.Fatalf("Clone() retained analyzer-owned capabilities: %#v", cloned.Capabilities)
	}
}

func TestCapabilityCoverageValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		capability CapabilityCoverage
		wantError  bool
	}{
		{
			name:       "complete status is valid",
			capability: CapabilityCoverage{SignalType: model.SignalTypeScriptURL, Status: CapabilityComplete},
		},
		{
			name:       "incomplete status is valid",
			capability: CapabilityCoverage{SignalType: model.SignalTypeCookie, Status: CapabilityIncomplete},
		},
		{
			name:       "unknown signal type is invalid",
			capability: CapabilityCoverage{SignalType: "bogus", Status: CapabilityComplete},
			wantError:  true,
		},
		{
			name:       "missing status is invalid",
			capability: CapabilityCoverage{SignalType: model.SignalTypeScriptURL},
			wantError:  true,
		},
		{
			name:       "unsupported status is invalid",
			capability: CapabilityCoverage{SignalType: model.SignalTypeScriptURL, Status: "partial"},
			wantError:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.capability.Validate()
			if (err != nil) != tt.wantError {
				t.Fatalf("Validate() error = %v, wantError %t", err, tt.wantError)
			}
		})
	}
}

func TestObservationCloneOwnsNetworkMetadata(t *testing.T) {
	t.Parallel()
	original := Observation{
		Source: "fixture",
		Metadata: Metadata{Network: &NetworkMetadata{
			FinalURL:      "https://example.test/",
			POSTEndpoints: []string{"https://api.example.test/submit"},
			Protocols:     []NetworkNameCount{{Name: "h2", Count: 2}},
			Hosts:         []NetworkHostTraffic{{Host: "example.test", Requests: 2}},
			Transactions:  []NetworkTransaction{{Method: "POST", URL: "https://api.example.test/submit", Status: 403}},
		}},
	}
	cloned := original.Clone()
	original.Metadata.Network.POSTEndpoints[0] = "changed"
	original.Metadata.Network.Protocols[0].Count = 99
	original.Metadata.Network.Hosts[0].Requests = 99
	original.Metadata.Network.Transactions[0].Status = 0

	network := cloned.Metadata.Network
	if network == nil || network.POSTEndpoints[0] != "https://api.example.test/submit" ||
		network.Protocols[0].Count != 2 || network.Hosts[0].Requests != 2 ||
		network.Transactions[0].Status != 403 {
		t.Fatalf("Clone() retained network metadata slices: %#v", network)
	}
	if !slices.Equal(cloned.Metadata.Kinds(), []MetadataKind{MetadataKindNetwork}) || cloned.Metadata.Empty() {
		t.Errorf("metadata kinds/empty = %v/%t", cloned.Metadata.Kinds(), cloned.Metadata.Empty())
	}
}
