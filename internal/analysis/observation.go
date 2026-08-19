// Package analysis defines the typed observation envelope shared by analyzers
// and scan orchestration.
package analysis

import "github.com/gkehren/hemera/pkg/model"

const (
	// SourceHTTP identifies observations produced by the bounded HTTP analyzer.
	SourceHTTP = "http_analyzer"
	// SourceDNSTLS identifies DNS and TLS signals derived from bounded DNS
	// observation and the established HTTP connection.
	SourceDNSTLS = "dns_tls_analyzer"
)

// Target identifies the user-requested resource passed to every analyzer. Prior
// contains cloned observations from analyzers that completed earlier in the
// configured pipeline.
type Target struct {
	URL   string
	Prior []Observation
}

// Observation contains one analyzer's normalized signals, local warnings, and
// bounded source-specific metadata. Warnings must be safe diagnostic summaries
// and must not contain raw attacker-controlled input or secrets.
type Observation struct {
	Source   string
	Signals  []model.Signal
	Warnings []string
	Metadata Metadata
}

// Clone returns an observation whose slices and typed metadata can be retained
// independently of analyzer-owned buffers.
func (o Observation) Clone() Observation {
	cloned := Observation{
		Source: o.Source, Signals: append([]model.Signal{}, o.Signals...),
		Warnings: append([]string{}, o.Warnings...),
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
