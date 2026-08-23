package dnstls

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/pkg/model"
)

type cnameResolverFunc func(context.Context, string) (string, error)

func (f cnameResolverFunc) LookupCNAME(ctx context.Context, host string) (string, error) {
	return f(ctx, host)
}

func TestDefaultConfigAndValidation(t *testing.T) {
	t.Parallel()
	if got := DefaultConfig().LookupTimeout; got != maxLookupTimeout {
		t.Errorf("DefaultConfig().LookupTimeout = %s, want %s", got, maxLookupTimeout)
	}
	for _, timeout := range []time.Duration{0, -time.Second, maxLookupTimeout + time.Nanosecond} {
		if _, err := New(Config{LookupTimeout: timeout}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(timeout %s) error = %v, want ErrInvalidConfig", timeout, err)
		}
	}
}

func TestObserveNormalizesCNAMEAndReusedTLSDeterministically(t *testing.T) {
	t.Parallel()
	var resolvedHost string
	analyzer, err := New(Config{
		LookupTimeout: time.Second,
		Resolver: cnameResolverFunc(func(_ context.Context, host string) (string, error) {
			resolvedHost = host
			return "EDGE.Example.NET.", nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	target := targetWithHTTP(&analysis.TLSMetadata{
		Version: tls.VersionTLS13, NegotiatedProtocol: "h2",
		CertificateIssuer: "CN=Fixture Issuer", CertificateSubject: "CN=example.test",
		DNSNames: []string{"www.example.test", "*.Example.Test", "www.example.test"},
	})
	observation, err := analyzer.Observe(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if resolvedHost != "example.test" || observation.Source != analysis.SourceDNSTLS {
		t.Fatalf("resolver host/source = %q/%q", resolvedHost, observation.Source)
	}
	want := []model.Signal{
		testSignal(model.SignalTypeDNSRecord, "cname", "edge.example.net"),
		testSignal(model.SignalTypeTLSProperty, "version", "TLS 1.3"),
		testSignal(model.SignalTypeTLSProperty, "alpn", "h2"),
		testSignal(model.SignalTypeTLSProperty, "certificate_issuer", "CN=Fixture Issuer"),
		testSignal(model.SignalTypeTLSProperty, "certificate_subject", "CN=example.test"),
		testSignal(model.SignalTypeTLSProperty, "certificate_dns_name", "*.example.test"),
		testSignal(model.SignalTypeTLSProperty, "certificate_dns_name", "www.example.test"),
	}
	if !slices.Equal(observation.Signals, want) {
		t.Fatalf("signals = %#v, want %#v", observation.Signals, want)
	}
	for _, signal := range observation.Signals {
		if err := signal.Validate(); err != nil {
			t.Errorf("signal %#v is invalid: %v", signal, err)
		}
	}
	producedTypes := make([]model.SignalType, 0, len(observation.Signals))
	for _, signal := range observation.Signals {
		producedTypes = append(producedTypes, signal.Type)
	}
	slices.Sort(producedTypes)
	producedTypes = slices.Compact(producedTypes)
	if want := analyzer.Capabilities(); !slices.Equal(producedTypes, want) {
		t.Fatalf("normalization produces %v, advertised capabilities are %v", producedTypes, want)
	}
}

func TestObserveSkipsUnaliasedAndLiteralHosts(t *testing.T) {
	t.Parallel()
	var calls int
	analyzer, err := New(Config{LookupTimeout: time.Second, Resolver: cnameResolverFunc(
		func(_ context.Context, host string) (string, error) {
			calls++
			return host + ".", nil
		},
	)})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := analyzer.Observe(context.Background(), targetWithHTTP(nil))
	if err != nil || len(observation.Signals) != 0 {
		t.Fatalf("unaliased observation/error = %#v/%v", observation, err)
	}
	literal := targetWithHTTP(nil)
	literal.Prior[0].Metadata.HTTP.FinalURL = "https://8.8.8.8/"
	observation, err = analyzer.Observe(context.Background(), literal)
	if err != nil || len(observation.Signals) != 0 || calls != 1 {
		t.Fatalf("literal observation/error/calls = %#v/%v/%d", observation, err, calls)
	}
}

func TestObserveReturnsReusableTLSOnCNAMEFailure(t *testing.T) {
	t.Parallel()
	lookupErr := errors.New("resolver unavailable")
	analyzer, err := New(Config{LookupTimeout: time.Second, Resolver: cnameResolverFunc(
		func(ctx context.Context, _ string) (string, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("resolver context has no deadline")
			}
			return "", lookupErr
		},
	)})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := analyzer.Observe(context.Background(), targetWithHTTP(&analysis.TLSMetadata{Version: tls.VersionTLS12}))
	if !errors.Is(err, lookupErr) || len(observation.Signals) != 1 || observation.Signals[0].Key != "version" {
		t.Fatalf("observation/error = %#v/%v", observation, err)
	}
	if !slices.Equal(observation.Warnings, []string{"CNAME observation was unavailable"}) {
		t.Errorf("warnings = %v", observation.Warnings)
	}
}

func TestObserveHonorsCallerCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	analyzer, err := New(Config{LookupTimeout: time.Second, Resolver: cnameResolverFunc(
		func(ctx context.Context, _ string) (string, error) { return "", ctx.Err() },
	)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = analyzer.Observe(ctx, targetWithHTTP(nil))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Observe() error = %v, want context.Canceled", err)
	}
}

func TestObserveRejectsMissingOrMalformedReusableMetadata(t *testing.T) {
	t.Parallel()
	analyzer, err := New(Config{LookupTimeout: time.Second, Resolver: cnameResolverFunc(
		func(context.Context, string) (string, error) { return "example.test.", nil },
	)})
	if err != nil {
		t.Fatal(err)
	}
	tooManyDNSNames := make([]string, maxTLSDNSNames+1)
	for index := range tooManyDNSNames {
		tooManyDNSNames[index] = "example.test"
	}
	tests := []struct {
		name   string
		target analysis.Target
		want   error
	}{
		{name: "missing HTTP", target: analysis.Target{URL: "https://example.test/"}, want: ErrMissingHTTPMetadata},
		{name: "invalid final URL", target: analysis.Target{Prior: []analysis.Observation{{
			Source:   analysis.SourceHTTP,
			Metadata: analysis.Metadata{HTTP: &analysis.HTTPMetadata{FinalURL: "ftp://example.test/"}},
		}}}, want: ErrInvalidObservation},
		{name: "invalid TLS version", target: targetWithHTTP(&analysis.TLSMetadata{Version: 1}), want: ErrInvalidObservation},
		{name: "invalid DNS name", target: targetWithHTTP(&analysis.TLSMetadata{
			Version: tls.VersionTLS13, DNSNames: []string{"bad name.example"},
		}), want: ErrInvalidObservation},
		{name: "too many DNS names", target: targetWithHTTP(&analysis.TLSMetadata{
			Version: tls.VersionTLS13, DNSNames: tooManyDNSNames,
		}), want: ErrInvalidObservation},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := analyzer.Observe(context.Background(), testCase.target)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Observe() error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func targetWithHTTP(metadata *analysis.TLSMetadata) analysis.Target {
	return analysis.Target{
		URL: "https://example.test/",
		Prior: []analysis.Observation{{
			Source: analysis.SourceHTTP,
			Metadata: analysis.Metadata{HTTP: &analysis.HTTPMetadata{
				RequestedURL: "https://example.test/", FinalURL: "https://example.test/", TLS: metadata,
			}},
		}},
	}
}

func testSignal(signalType model.SignalType, key, value string) model.Signal {
	return model.Signal{
		Type: signalType, Source: analysis.SourceDNSTLS, Key: key, Value: value,
		URL: "https://example.test/", Confidence: 1,
	}
}
