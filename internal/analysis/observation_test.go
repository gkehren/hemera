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
			Redirects: []HTTPRedirect{{
				From: "https://example.test/", To: "https://example.test/final", Status: 302,
			}},
		}},
	}
	cloned := original.Clone()
	original.Signals[0].Key = "changed"
	original.Warnings[0] = "changed"
	original.Metadata.HTTP.Redirects[0].To = "https://changed.test/"

	if cloned.Signals[0].Key != "src" || cloned.Warnings[0] != "fixture warning" ||
		cloned.Metadata.HTTP.Redirects[0].To != "https://example.test/final" {
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
