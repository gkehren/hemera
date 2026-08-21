// Package analysis defines the typed observation envelope shared by analyzers
// and scan orchestration.
package analysis

import (
	"fmt"

	"github.com/gkehren/hemera/pkg/model"
)

const (
	// SourceHTTP identifies observations produced by the bounded HTTP analyzer.
	SourceHTTP = "http_analyzer"
	// SourceDNSTLS identifies DNS and TLS signals derived from bounded DNS
	// observation and the established HTTP connection.
	SourceDNSTLS = "dns_tls_analyzer"
	// SourceBrowser identifies observations produced by sandboxed Chromium.
	SourceBrowser = "browser_analyzer"
)

// Target identifies the user-requested resource passed to every analyzer. Prior
// contains cloned observations from analyzers that completed earlier in the
// configured pipeline.
type Target struct {
	URL   string
	Prior []Observation
}

// CapabilityStatus expresses whether one analyzer signal capability was
// observed completely within its bounded contract.
type CapabilityStatus string

const (
	// CapabilityComplete means the channel was fully observed under the
	// analyzer's bounded collection contract, so absence of a matching value is
	// conclusive evidence for that capability.
	CapabilityComplete CapabilityStatus = "complete"
	// CapabilityIncomplete means the channel may hold unobserved
	// detector-relevant evidence because a resource ceiling was reached,
	// evidence was truncated, or collection did not finish. Absence of a
	// matching value is inconclusive for this capability.
	CapabilityIncomplete CapabilityStatus = "incomplete"
)

// CapabilityCoverage reports the observation completeness of one normalized
// signal capability. Analyzers declare coverage per signal type so that
// detection status can distinguish a conclusive negative from bounded
// observation; analyzer execution status alone cannot express this distinction.
type CapabilityCoverage struct {
	SignalType model.SignalType
	Status     CapabilityStatus
}

// Validate checks that a declared capability names a known signal type and an
// exact capability status.
func (c CapabilityCoverage) Validate() error {
	if !c.SignalType.Valid() {
		return fmt.Errorf("capability coverage declares invalid signal type %q", c.SignalType)
	}
	switch c.Status {
	case CapabilityComplete, CapabilityIncomplete:
		return nil
	default:
		return fmt.Errorf("capability %q has unsupported status %q", c.SignalType, c.Status)
	}
}

// Observation contains one analyzer's normalized signals, local warnings,
// declared per-capability coverage, and bounded source-specific metadata.
// Warnings must be safe diagnostic summaries and must not contain raw
// attacker-controlled input or secrets.
type Observation struct {
	Source       string
	Signals      []model.Signal
	Warnings     []string
	Capabilities []CapabilityCoverage
	Metadata     Metadata
}

// Clone returns an observation whose slices and typed metadata can be retained
// independently of analyzer-owned buffers.
func (o Observation) Clone() Observation {
	cloned := Observation{
		Source: o.Source, Signals: append([]model.Signal{}, o.Signals...),
		Warnings:     append([]string{}, o.Warnings...),
		Capabilities: append([]CapabilityCoverage{}, o.Capabilities...),
	}
	if o.Metadata.HTTP != nil {
		httpMetadata := *o.Metadata.HTTP
		httpMetadata.Redirects = append([]HTTPRedirect{}, o.Metadata.HTTP.Redirects...)
		if o.Metadata.HTTP.TLS != nil {
			tlsMetadata := *o.Metadata.HTTP.TLS
			tlsMetadata.DNSNames = append([]string{}, o.Metadata.HTTP.TLS.DNSNames...)
			httpMetadata.TLS = &tlsMetadata
		}
		cloned.Metadata.HTTP = &httpMetadata
	}
	return cloned
}

// MetadataKind identifies one typed source-specific metadata contract.
type MetadataKind string

const (
	// MetadataKindHTTP identifies bounded HTTP navigation metadata.
	MetadataKindHTTP MetadataKind = "http"
)

// Metadata is the typed envelope for source-specific diagnostic data. New
// analyzer metadata belongs here rather than in unstructured maps or signals.
type Metadata struct {
	HTTP *HTTPMetadata
}

// Empty reports whether the envelope contains no source-specific metadata.
func (m Metadata) Empty() bool {
	return m.HTTP == nil
}

// Kinds returns the populated metadata contracts in stable field order.
func (m Metadata) Kinds() []MetadataKind {
	kinds := make([]MetadataKind, 0, 1)
	if m.HTTP != nil {
		kinds = append(kinds, MetadataKindHTTP)
	}
	return kinds
}

// HTTPMetadata contains bounded navigation diagnostics that do not participate
// directly in rule matching or scoring.
type HTTPMetadata struct {
	RequestedURL  string
	FinalURL      string
	StatusCode    int
	Redirects     []HTTPRedirect
	BodyTruncated bool
	TLS           *TLSMetadata
}

// TLSMetadata is the bounded subset of the verified final HTTP connection's
// TLS state that can support detector evidence without another handshake.
type TLSMetadata struct {
	Version            uint16
	NegotiatedProtocol string
	CertificateIssuer  string
	CertificateSubject string
	DNSNames           []string
}

// HTTPRedirect records one sanitized HTTP redirect.
type HTTPRedirect struct {
	From   string
	To     string
	Status int
}
