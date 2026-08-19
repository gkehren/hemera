// Package dnstls normalizes bounded DNS and TLS observations without opening a
// separate TLS connection.
package dnstls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/networkguard"
	"github.com/gkehren/hemera/pkg/model"
)

const (
	source           = analysis.SourceDNSTLS
	maxLookupTimeout = 2 * time.Second
	maxDNSNameBytes  = 253
	maxTLSValueBytes = 2048
	maxTLSDNSNames   = 256
)

var (
	// ErrInvalidConfig identifies DNS/TLS analyzer configuration outside its
	// bounded policy.
	ErrInvalidConfig = errors.New("invalid DNS/TLS analyzer configuration")
	// ErrMissingHTTPMetadata means the analyzer could not reuse an earlier HTTP
	// navigation result.
	ErrMissingHTTPMetadata = errors.New("HTTP connection metadata is unavailable")
	// ErrInvalidObservation identifies malformed reusable HTTP/TLS metadata.
	ErrInvalidObservation = errors.New("invalid DNS/TLS observation")
)

// CNAMEResolver is the single DNS operation used for alias observation. It
// cannot open a network connection to a resolved destination.
type CNAMEResolver interface {
	LookupCNAME(context.Context, string) (string, error)
}

// Config controls the bounded CNAME lookup and supplies an injectable resolver.
type Config struct {
	LookupTimeout time.Duration
	Resolver      CNAMEResolver
}

// DefaultConfig returns the low-impact DNS observation limits.
func DefaultConfig() Config {
	return Config{LookupTimeout: maxLookupTimeout}
}

// Analyzer derives DNS and TLS signals after the HTTP analyzer.
type Analyzer struct {
	lookupTimeout time.Duration
	resolver      CNAMEResolver
}

// New validates config and constructs an analyzer.
func New(config Config) (*Analyzer, error) {
	if config.LookupTimeout <= 0 || config.LookupTimeout > maxLookupTimeout {
		return nil, fmt.Errorf("%w: lookup timeout must be positive and at most %s", ErrInvalidConfig, maxLookupTimeout)
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Analyzer{lookupTimeout: config.LookupTimeout, resolver: resolver}, nil
}

// Source returns the stable identity used for DNS and TLS observations.
func (*Analyzer) Source() string {
	return source
}

// Observe emits a CNAME when the final host is an alias and emits selected TLS
// properties from the verified final HTTP connection. It never performs a TLS
// handshake itself.
func (a *Analyzer) Observe(ctx context.Context, target analysis.Target) (analysis.Observation, error) {
	observation := analysis.Observation{Source: source}
	httpMetadata := priorHTTPMetadata(target.Prior)
	if httpMetadata == nil {
		return observation, ErrMissingHTTPMetadata
	}
	finalURL, err := networkguard.ParseURL(httpMetadata.FinalURL)
	if err != nil {
		return observation, fmt.Errorf("%w: final URL: %w", ErrInvalidObservation, err)
	}

	tlsSignals, err := normalizeTLS(httpMetadata.TLS, httpMetadata.FinalURL)
	if err != nil {
		return observation, err
	}
	observation.Signals = tlsSignals

	host := finalURL.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return observation, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, a.lookupTimeout)
	defer cancel()
	canonical, err := a.resolver.LookupCNAME(lookupCtx, host)
	if err != nil {
		observation.Warnings = []string{"CNAME observation was unavailable"}
		return observation, fmt.Errorf("look up final-host CNAME: %w", err)
	}
	canonical, err = normalizeDNSName(canonical, false)
	if err != nil {
		observation.Warnings = []string{"CNAME observation was unavailable"}
		return observation, fmt.Errorf("%w: CNAME: %w", ErrInvalidObservation, err)
	}
	normalizedHost, err := normalizeDNSName(host, false)
	if err != nil {
		return observation, fmt.Errorf("%w: final host: %w", ErrInvalidObservation, err)
	}
	if canonical == normalizedHost {
		return observation, nil
	}
	dnsSignal := model.Signal{
		Type: model.SignalTypeDNSRecord, Source: source, Key: "cname",
		Value: canonical, URL: httpMetadata.FinalURL, Confidence: 1,
	}
	observation.Signals = append([]model.Signal{dnsSignal}, observation.Signals...)
	return observation, nil
}

func priorHTTPMetadata(prior []analysis.Observation) *analysis.HTTPMetadata {
	for index := len(prior) - 1; index >= 0; index-- {
		if prior[index].Source == analysis.SourceHTTP && prior[index].Metadata.HTTP != nil {
			return prior[index].Metadata.HTTP
		}
	}
	return nil
}

func normalizeTLS(metadata *analysis.TLSMetadata, finalURL string) ([]model.Signal, error) {
	if metadata == nil {
		return nil, nil
	}
	if metadata.Version != tls.VersionTLS12 && metadata.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("%w: unsupported TLS version %d", ErrInvalidObservation, metadata.Version)
	}
	version := tls.VersionName(metadata.Version)
	signals := []model.Signal{{
		Type: model.SignalTypeTLSProperty, Source: source, Key: "version",
		Value: version, URL: finalURL, Confidence: 1,
	}}
	properties := []struct {
		key   string
		value string
	}{
		{key: "alpn", value: metadata.NegotiatedProtocol},
		{key: "certificate_issuer", value: metadata.CertificateIssuer},
		{key: "certificate_subject", value: metadata.CertificateSubject},
	}
	for _, property := range properties {
		if property.value == "" {
			continue
		}
		if !safeProperty(property.value) {
			return nil, fmt.Errorf("%w: unsafe %s value", ErrInvalidObservation, property.key)
		}
		signals = append(signals, model.Signal{
			Type: model.SignalTypeTLSProperty, Source: source, Key: property.key,
			Value: property.value, URL: finalURL, Confidence: 1,
		})
	}

	if len(metadata.DNSNames) > maxTLSDNSNames {
		return nil, fmt.Errorf("%w: certificate DNS names exceed %d entries", ErrInvalidObservation, maxTLSDNSNames)
	}
	dnsNames := make([]string, 0, len(metadata.DNSNames))
	for _, dnsName := range metadata.DNSNames {
		normalized, err := normalizeDNSName(dnsName, true)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate DNS name: %w", ErrInvalidObservation, err)
		}
		dnsNames = append(dnsNames, normalized)
	}
	sort.Strings(dnsNames)
	previous := ""
	for _, dnsName := range dnsNames {
		if dnsName == previous {
			continue
		}
		previous = dnsName
		signals = append(signals, model.Signal{
			Type: model.SignalTypeTLSProperty, Source: source, Key: "certificate_dns_name",
			Value: dnsName, URL: finalURL, Confidence: 1,
		})
	}
	return signals, nil
}

func normalizeDNSName(value string, allowWildcard bool) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > maxDNSNameBytes {
		return "", errors.New("DNS name is empty or too long")
	}
	labels := strings.Split(value, ".")
	for index, label := range labels {
		if allowWildcard && index == 0 && label == "*" {
			continue
		}
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("DNS name contains an invalid label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", errors.New("DNS name contains an invalid character")
			}
		}
	}
	return value, nil
}

func safeProperty(value string) bool {
	if value == "" || len(value) > maxTLSValueBytes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) && character != ' ' {
			return false
		}
	}
	return true
}
