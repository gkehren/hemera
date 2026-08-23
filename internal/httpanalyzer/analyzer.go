// Package httpanalyzer performs Hemera's bounded, passive HTTP observation.
package httpanalyzer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/networkguard"
	"github.com/gkehren/hemera/pkg/model"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/publicsuffix"
)

const (
	source = analysis.SourceHTTP

	warningHTMLIncomplete                 = "HTML observation was incomplete"
	warningHTMLResourcesIncomplete        = "static HTML resource observation was incomplete"
	warningResponseBodyTruncatedFormat    = "response body was truncated at %d bytes"
	warningDecodedHTMLTruncatedFormat     = "decoded HTML was truncated at %d bytes"
	warningHTMLResourceLimitFormat        = "HTML resource extraction stopped at %d resources"
	warningMalformedCertificateDNSNames   = "malformed TLS certificate DNS names were omitted"
	warningCertificateDNSNamesLimitFormat = "TLS certificate DNS names were truncated at %d entries"
	warningMalformedCertificateProperties = "malformed or oversized TLS certificate properties were omitted"

	maxTotalTimeout                  = 15 * time.Second
	maxConnectTimeout                = 5 * time.Second
	maxTLSHandshakeTimeout           = 5 * time.Second
	maxResponseHeaderTimeout         = 5 * time.Second
	maxRedirects                     = 10
	maxBodyBytes               int64 = 2 << 20
	maxResponseHeaderBytes           = 1 << 20
	maxHTMLResources                 = 4096
	maxUserAgentBytes                = 512
	maxCertificateNameBytes          = 2048
	maxCertificateDNSNameBytes       = 253
	maxCertificateDNSNames           = 256
)

var (
	// ErrInvalidConfig identifies an analyzer configuration outside safe bounds.
	ErrInvalidConfig = errors.New("invalid HTTP analyzer configuration")
	// ErrInvalidSignal identifies a producer bug that emitted an invalid signal.
	ErrInvalidSignal = errors.New("HTTP analyzer produced an invalid signal")
	// ErrInitialTarget identifies invalid syntax or a forbidden initial destination.
	ErrInitialTarget = errors.New("invalid or forbidden initial target")
)

// Config controls resource limits and supplies injectable network dependencies.
type Config struct {
	TotalTimeout           time.Duration
	ConnectTimeout         time.Duration
	TLSHandshakeTimeout    time.Duration
	ResponseHeaderTimeout  time.Duration
	MaxRedirects           int
	MaxBodyBytes           int64
	MaxResponseHeaderBytes int64
	MaxHTMLResources       int
	UserAgent              string
	Resolver               networkguard.Resolver
	Dialer                 networkguard.Dialer
	RootCAs                *x509.CertPool
}

// DefaultConfig returns Hemera's balanced, low-impact HTTP limits.
func DefaultConfig() Config {
	return Config{
		TotalTimeout:           maxTotalTimeout,
		ConnectTimeout:         maxConnectTimeout,
		TLSHandshakeTimeout:    maxTLSHandshakeTimeout,
		ResponseHeaderTimeout:  maxResponseHeaderTimeout,
		MaxRedirects:           maxRedirects,
		MaxBodyBytes:           maxBodyBytes,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		MaxHTMLResources:       maxHTMLResources,
		UserAgent:              "Hemera/dev (+https://github.com/gkehren/hemera)",
	}
}

// Redirect records one HTTP redirect without retaining query parameters.
type Redirect struct {
	From   string
	To     string
	Status int
}

// Result contains observations from one bounded HTTP navigation. URL fields
// are sanitized before storage so diagnostics cannot disclose query values.
// Truncation fields expose structured completion state for capability-level
// coverage evaluation; they must not be inferred from warnings.
type Result struct {
	RequestedURL string
	FinalURL     string
	StatusCode   int
	Redirects    []Redirect
	Signals      []model.Signal
	// BodyTruncated reports that raw response body bytes were bounded.
	BodyTruncated bool
	// HTMLTruncated reports that the charset-decoded HTML used for matching
	// was bounded below the raw body ceiling.
	HTMLTruncated bool
	// PageContentIncomplete reports that HTML decoding failed before page
	// content evidence could be produced completely.
	PageContentIncomplete bool
	// ResourcesIncomplete reports that static-resource extraction did not run
	// to completion because the resource ceiling was reached or parsing
	// stopped early.
	ResourcesIncomplete bool
	Warnings            []string
	TLS                 *analysis.TLSMetadata
	htmlAnalysisErr     error
}

// HTMLAnalysisError returns the detailed internal error that made HTML
// observation incomplete. Its text may contain attacker-controlled response
// data and must never be copied into an Observation warning or report.
func (r Result) HTMLAnalysisError() error {
	return r.htmlAnalysisErr
}

// Analyzer performs one safe HTTP navigation.
type Analyzer struct {
	config Config
	guard  *networkguard.Guard
}

// New validates config and constructs an analyzer.
func New(config Config) (*Analyzer, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	dialer := config.Dialer
	if dialer == nil {
		dialer = (&net.Dialer{Timeout: config.ConnectTimeout}).DialContext
	}
	guard := networkguard.New(networkguard.Config{Resolver: config.Resolver, Dialer: dialer})
	return &Analyzer{config: config, guard: guard}, nil
}

// Source returns the stable identity used for this analyzer's observations.
func (*Analyzer) Source() string {
	return source
}

// Observe adapts one HTTP navigation to the analyzer-agnostic observation
// contract consumed by scan orchestration. On success it declares
// capability-level coverage derived from structured completion state so that
// bounded evidence channels cannot produce false conclusive negatives. Failed
// navigations return an undeclared capability set; scan orchestration then
// falls back to the analyzer execution status.
func (a *Analyzer) Observe(ctx context.Context, target analysis.Target) (analysis.Observation, error) {
	result, err := a.Analyze(ctx, target.URL)
	if err != nil {
		return analysis.Observation{Source: source}, err
	}
	return observationFromResult(result), nil
}

func observationFromResult(result Result) analysis.Observation {
	redirects := make([]analysis.HTTPRedirect, 0, len(result.Redirects))
	for _, redirect := range result.Redirects {
		redirects = append(redirects, analysis.HTTPRedirect{
			From: redirect.From, To: redirect.To, Status: redirect.Status,
		})
	}
	observation := analysis.Observation{Source: source}
	observation.Signals = append([]model.Signal{}, result.Signals...)
	observation.Warnings = append([]string{}, result.Warnings...)
	observation.Capabilities = capabilityCoverage(result)
	observation.Metadata.HTTP = &analysis.HTTPMetadata{
		RequestedURL: result.RequestedURL, FinalURL: result.FinalURL,
		StatusCode: result.StatusCode, Redirects: redirects,
		BodyTruncated: result.BodyTruncated, TLS: cloneTLSMetadata(result.TLS),
	}
	return observation
}

// capabilityCoverage derives per-signal-type coverage from the structured
// completion state of one successful HTTP navigation.
func capabilityCoverage(result Result) []analysis.CapabilityCoverage {
	contentTruncated := result.BodyTruncated || result.HTMLTruncated || result.PageContentIncomplete
	resourcesTruncated := contentTruncated || result.ResourcesIncomplete
	status := func(incomplete bool) analysis.CapabilityStatus {
		if incomplete {
			return analysis.CapabilityIncomplete
		}
		return analysis.CapabilityComplete
	}
	return []analysis.CapabilityCoverage{
		{SignalType: model.SignalTypeRedirect, Status: status(false)},
		{SignalType: model.SignalTypeNetworkResponse, Status: status(false)},
		{SignalType: model.SignalTypeResponseHeader, Status: status(false)},
		{SignalType: model.SignalTypeCookie, Status: status(false)},
		{SignalType: model.SignalTypePageContent, Status: status(contentTruncated)},
		{SignalType: model.SignalTypeScriptURL, Status: status(resourcesTruncated)},
		{SignalType: model.SignalTypeIframeURL, Status: status(resourcesTruncated)},
		{SignalType: model.SignalTypeResourceHost, Status: status(resourcesTruncated)},
	}
}

// Analyze performs a single GET navigation and returns normalized observations.
func (a *Analyzer) Analyze(ctx context.Context, rawURL string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.TotalTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("HTTP analysis: %w", err)
	}

	requested, err := networkguard.ParseURL(rawURL)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInitialTarget, err)
	}
	if err := a.guard.Validate(ctx, requested); err != nil {
		if errors.Is(err, networkguard.ErrForbiddenDestination) {
			return Result{}, fmt.Errorf("%w: %w", ErrInitialTarget, err)
		}
		return Result{}, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    a.config.RootCAs,
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            a.dialContext,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    a.config.TLSHandshakeTimeout,
		ResponseHeaderTimeout:  a.config.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: a.config.MaxResponseHeaderBytes,
		MaxConnsPerHost:        1,
		MaxIdleConnsPerHost:    1,
		DisableCompression:     false,
	}
	defer transport.CloseIdleConnections()

	result := Result{RequestedURL: SanitizeURL(requested)}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			previous := req.Response
			if previous != nil {
				if err := collectResponse(&result, previous); err != nil {
					return err
				}
				result.Redirects = append(result.Redirects, Redirect{
					From: SanitizeURL(previous.Request.URL),
					To:   SanitizeURL(req.URL), Status: previous.StatusCode,
				})
				if err := appendSignal(&result, model.Signal{
					Type: model.SignalTypeRedirect, Source: source, Key: "location",
					Value: SanitizeURL(req.URL), URL: SanitizeURL(previous.Request.URL), Confidence: 1,
				}); err != nil {
					return err
				}
			}
			if len(via) > a.config.MaxRedirects {
				return networkguard.ErrTooManyRedirects
			}
			validated, err := networkguard.ParseURL(req.URL.String())
			if err != nil {
				return err
			}
			return a.guard.Validate(ctx, validated)
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requested.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", a.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("HTTP navigation: %w", err)
	}
	defer resp.Body.Close()

	if err := collectResponse(&result, resp); err != nil {
		return Result{}, err
	}
	result.FinalURL = SanitizeURL(resp.Request.URL)
	result.StatusCode = resp.StatusCode

	body, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: resp.Body}, a.config.MaxBodyBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > a.config.MaxBodyBytes {
		body = body[:a.config.MaxBodyBytes]
		result.BodyTruncated = true
		result.Warnings = append(result.Warnings, fmt.Sprintf(warningResponseBodyTruncatedFormat, a.config.MaxBodyBytes))
	}

	if isHTML(resp.Header.Get("Content-Type"), body) {
		if err := a.collectHTML(ctx, &result, resp.Request.URL, resp.Header.Get("Content-Type"), body); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return Result{}, fmt.Errorf("analyze HTML: %w", err)
			}
			if errors.Is(err, ErrInvalidSignal) {
				return Result{}, fmt.Errorf("analyze HTML: %w", err)
			}
			recordHTMLFailure(&result, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("HTTP analysis: %w", err)
	}
	return result, nil
}

func recordHTMLFailure(result *Result, err error) {
	result.htmlAnalysisErr = err
	warning := warningHTMLResourcesIncomplete
	if result.PageContentIncomplete {
		warning = warningHTMLIncomplete
	}
	appendWarningOnce(result, warning)
}

func (a *Analyzer) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.ConnectTimeout)
	defer cancel()
	return a.guard.DialContext(ctx, network, address)
}

func validateConfig(config Config) error {
	if config.TotalTimeout <= 0 || config.TotalTimeout > maxTotalTimeout {
		return fmt.Errorf("%w: total timeout must be positive and at most %s", ErrInvalidConfig, maxTotalTimeout)
	}
	if config.ConnectTimeout <= 0 || config.ConnectTimeout > maxConnectTimeout {
		return fmt.Errorf("%w: connect timeout must be positive and at most %s", ErrInvalidConfig, maxConnectTimeout)
	}
	if config.TLSHandshakeTimeout <= 0 || config.TLSHandshakeTimeout > maxTLSHandshakeTimeout {
		return fmt.Errorf("%w: TLS handshake timeout must be positive and at most %s", ErrInvalidConfig, maxTLSHandshakeTimeout)
	}
	if config.ResponseHeaderTimeout <= 0 || config.ResponseHeaderTimeout > maxResponseHeaderTimeout {
		return fmt.Errorf("%w: response header timeout must be positive and at most %s", ErrInvalidConfig, maxResponseHeaderTimeout)
	}
	if config.MaxRedirects < 0 || config.MaxRedirects > maxRedirects {
		return fmt.Errorf("%w: redirect count must be between 0 and %d", ErrInvalidConfig, maxRedirects)
	}
	if config.MaxBodyBytes <= 0 || config.MaxBodyBytes > maxBodyBytes {
		return fmt.Errorf("%w: body bytes must be positive and at most %d", ErrInvalidConfig, maxBodyBytes)
	}
	if config.MaxResponseHeaderBytes <= 0 || config.MaxResponseHeaderBytes > maxResponseHeaderBytes {
		return fmt.Errorf("%w: response header bytes must be positive and at most %d", ErrInvalidConfig, maxResponseHeaderBytes)
	}
	if config.MaxHTMLResources <= 0 || config.MaxHTMLResources > maxHTMLResources {
		return fmt.Errorf("%w: HTML resources must be positive and at most %d", ErrInvalidConfig, maxHTMLResources)
	}
	if strings.TrimSpace(config.UserAgent) == "" {
		return fmt.Errorf("%w: User-Agent is required", ErrInvalidConfig)
	}
	if len(config.UserAgent) > maxUserAgentBytes {
		return fmt.Errorf("%w: User-Agent exceeds %d bytes", ErrInvalidConfig, maxUserAgentBytes)
	}
	for i := 0; i < len(config.UserAgent); i++ {
		if (config.UserAgent[i] < 0x20 && config.UserAgent[i] != '\t') || config.UserAgent[i] == 0x7f {
			return fmt.Errorf("%w: User-Agent contains an invalid header byte", ErrInvalidConfig)
		}
	}
	return nil
}

func collectResponse(result *Result, resp *http.Response) error {
	pageURL := SanitizeURL(resp.Request.URL)
	collectTLSMetadata(result, resp.TLS)
	if err := appendSignal(result, model.Signal{
		Type: model.SignalTypeNetworkResponse, Source: source, Key: "status",
		Value: strconv.Itoa(resp.StatusCode), URL: pageURL, Confidence: 1,
	}); err != nil {
		return err
	}

	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		for _, value := range resp.Header.Values(name) {
			if strings.EqualFold(name, "Location") {
				if location, err := url.Parse(value); err == nil {
					value = SanitizeURL(resp.Request.URL.ResolveReference(location))
				} else {
					value = "[invalid URL omitted]"
				}
			} else if sensitiveHeader(name) {
				value = "[redacted]"
			}
			if err := appendSignal(result, model.Signal{
				Type: model.SignalTypeResponseHeader, Source: source, Key: http.CanonicalHeaderKey(name),
				Value: value, URL: pageURL, Confidence: 1,
			}); err != nil {
				return err
			}
		}
	}
	for _, cookie := range resp.Cookies() {
		if err := appendSignal(result, model.Signal{
			Type: model.SignalTypeCookie, Source: source, Key: cookie.Name,
			Value: "", URL: pageURL, Confidence: 1,
		}); err != nil {
			return err
		}
	}
	return nil
}

func collectTLSMetadata(result *Result, state *tls.ConnectionState) {
	if state == nil || !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		result.TLS = nil
		return
	}
	leaf := state.PeerCertificates[0]
	dnsNames := make([]string, 0, len(leaf.DNSNames))
	for _, name := range leaf.DNSNames {
		if !validCertificateDNSName(name) {
			appendWarningOnce(result, warningMalformedCertificateDNSNames)
			continue
		}
		dnsNames = append(dnsNames, name)
	}
	sort.Strings(dnsNames)
	dnsNames = compactStrings(dnsNames)
	if len(dnsNames) > maxCertificateDNSNames {
		dnsNames = dnsNames[:maxCertificateDNSNames]
		appendWarningOnce(result, fmt.Sprintf(warningCertificateDNSNamesLimitFormat, maxCertificateDNSNames))
	}
	issuer := leaf.Issuer.String()
	subject := leaf.Subject.String()
	protocol := boundedCertificateText(state.NegotiatedProtocol)
	boundedIssuer := boundedCertificateText(issuer)
	boundedSubject := boundedCertificateText(subject)
	if state.NegotiatedProtocol != protocol || issuer != boundedIssuer || subject != boundedSubject {
		appendWarningOnce(result, warningMalformedCertificateProperties)
	}
	result.TLS = &analysis.TLSMetadata{
		Version: state.Version, NegotiatedProtocol: protocol,
		CertificateIssuer:  boundedIssuer,
		CertificateSubject: boundedSubject,
		DNSNames:           append([]string{}, dnsNames...),
	}
}

func validCertificateDNSName(value string) bool {
	if value == "" || len(value) > maxCertificateDNSNameBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	name := strings.TrimSuffix(strings.ToLower(value), ".")
	labels := strings.Split(name, ".")
	for index, label := range labels {
		if index == 0 && label == "*" {
			continue
		}
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func cloneTLSMetadata(metadata *analysis.TLSMetadata) *analysis.TLSMetadata {
	if metadata == nil {
		return nil
	}
	cloned := *metadata
	cloned.DNSNames = append([]string{}, metadata.DNSNames...)
	return &cloned
}

func boundedCertificateText(value string) string {
	if len(value) > maxCertificateNameBytes || !utf8.ValidString(value) {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	return value
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	output := values[:1]
	for _, value := range values[1:] {
		if value != output[len(output)-1] {
			output = append(output, value)
		}
	}
	return output
}

func (a *Analyzer) collectHTML(ctx context.Context, result *Result, documentURL *url.URL, contentType string, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, params, err := mime.ParseMediaType(contentType); err == nil {
		if label := params["charset"]; label != "" {
			if encoding, _ := charset.Lookup(label); encoding == nil {
				result.PageContentIncomplete = true
				result.ResourcesIncomplete = true
				return fmt.Errorf("decode HTML charset: unsupported charset %q", label)
			}
		}
	}
	reader, err := charset.NewReader(bytes.NewReader(body), contentType)
	if err != nil {
		result.PageContentIncomplete = true
		result.ResourcesIncomplete = true
		return fmt.Errorf("decode HTML charset: %w", err)
	}
	utf8Body, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: reader}, a.config.MaxBodyBytes+1))
	if err != nil {
		result.PageContentIncomplete = true
		result.ResourcesIncomplete = true
		return fmt.Errorf("decode HTML charset: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(utf8Body)) > a.config.MaxBodyBytes {
		utf8Body = utf8Body[:a.config.MaxBodyBytes]
		for len(utf8Body) > 0 && !utf8.Valid(utf8Body) {
			utf8Body = utf8Body[:len(utf8Body)-1]
		}
		result.HTMLTruncated = true
		result.Warnings = append(result.Warnings, fmt.Sprintf(warningDecodedHTMLTruncatedFormat, a.config.MaxBodyBytes))
	}
	if err := appendSignal(result, model.Signal{
		Type: model.SignalTypePageContent, Source: source, Key: "body",
		Value: string(utf8Body), URL: SanitizeURL(documentURL), Confidence: 1,
	}); err != nil {
		return err
	}

	baseURL, err := firstBaseURL(ctx, utf8Body, documentURL)
	if err != nil {
		result.ResourcesIncomplete = true
		return err
	}
	limited, err := collectHTMLResources(ctx, result, utf8Body, documentURL, baseURL, a.config.MaxHTMLResources)
	if err != nil {
		result.ResourcesIncomplete = true
		return err
	}
	if limited {
		result.ResourcesIncomplete = true
		appendWarningOnce(result, fmt.Sprintf(warningHTMLResourceLimitFormat, a.config.MaxHTMLResources))
	}
	return ctx.Err()
}

func firstBaseURL(ctx context.Context, body []byte, documentURL *url.URL) (*url.URL, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("parse HTML base URL: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return documentURL, nil
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "base" {
				continue
			}
			if value, ok := tokenAttr(token, "href"); ok {
				if resolved, ok := resolveHTTPURL(documentURL, value); ok {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return resolved, nil
				}
			}
		}
	}
}

func collectHTMLResources(
	ctx context.Context,
	result *Result,
	body []byte,
	documentURL *url.URL,
	baseURL *url.URL,
	limit int,
) (bool, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	seen := make(map[string]struct{})
	resources := 0
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && !errors.Is(err, io.EOF) {
				return false, fmt.Errorf("parse HTML resources: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			return false, nil
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			var signalType model.SignalType
			switch token.Data {
			case "script":
				signalType = model.SignalTypeScriptURL
			case "iframe":
				signalType = model.SignalTypeIframeURL
			}
			if signalType == "" {
				continue
			}
			value, ok := tokenAttr(token, "src")
			if !ok {
				continue
			}
			resource, ok := resolveHTTPURL(baseURL, value)
			if !ok {
				continue
			}
			sanitized := SanitizeURL(resource)
			identity := string(signalType) + "\x00" + sanitized
			if _, duplicate := seen[identity]; duplicate {
				continue
			}
			seen[identity] = struct{}{}
			if err := appendSignal(result, model.Signal{
				Type: signalType, Source: source, Key: "src", Value: sanitized,
				URL: SanitizeURL(documentURL), Confidence: 1,
			}); err != nil {
				return false, err
			}
			resources++
			if thirdParty(documentURL.Hostname(), resource.Hostname()) {
				hostIdentity := string(model.SignalTypeResourceHost) + "\x00" + strings.ToLower(resource.Hostname())
				if _, duplicate := seen[hostIdentity]; !duplicate {
					seen[hostIdentity] = struct{}{}
					if err := appendSignal(result, model.Signal{
						Type: model.SignalTypeResourceHost, Source: source, Key: "host",
						Value: strings.ToLower(resource.Hostname()), URL: sanitized, Confidence: 1,
					}); err != nil {
						return false, err
					}
				}
			}
			if resources == limit {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				return true, nil
			}
		}
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := r.reader.Read(buffer)
	if err == nil {
		if contextErr := r.ctx.Err(); contextErr != nil {
			return count, contextErr
		}
	}
	return count, err
}

func appendSignal(result *Result, signal model.Signal) error {
	if err := signal.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignal, err)
	}
	result.Signals = append(result.Signals, signal)
	return nil
}

func tokenAttr(token html.Token, key string) (string, bool) {
	for _, attribute := range token.Attr {
		if strings.EqualFold(attribute.Key, key) {
			return strings.TrimSpace(attribute.Val), true
		}
	}
	return "", false
}

func appendWarningOnce(result *Result, warning string) {
	for _, existing := range result.Warnings {
		if existing == warning {
			return
		}
	}
	result.Warnings = append(result.Warnings, warning)
}

func resolveHTTPURL(base *url.URL, value string) (*url.URL, bool) {
	reference, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, false
	}
	resolved := base.ResolveReference(reference)
	if (resolved.Scheme != "http" && resolved.Scheme != "https") || resolved.Hostname() == "" || resolved.User != nil {
		return nil, false
	}
	resolved.Fragment = ""
	validated, err := networkguard.ParseURL(resolved.String())
	return validated, err == nil
}

func isHTML(contentType string, body []byte) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType == "text/html" || mediaType == "application/xhtml+xml" {
		return true
	}
	return strings.HasPrefix(http.DetectContentType(body), "text/html")
}

func sensitiveHeader(name string) bool {
	name = strings.ToLower(name)
	for _, fragment := range []string{"authorization", "cookie", "token", "secret", "api-key", "apikey", "authentication"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return strings.HasSuffix(name, "-key")
}

func thirdParty(pageHost, resourceHost string) bool {
	pageHost, resourceHost = strings.ToLower(pageHost), strings.ToLower(resourceHost)
	pageIP, pageErr := netip.ParseAddr(pageHost)
	resourceIP, resourceErr := netip.ParseAddr(resourceHost)
	if pageErr == nil || resourceErr == nil {
		return pageErr != nil || resourceErr != nil || pageIP.Unmap() != resourceIP.Unmap()
	}
	pageDomain, pageErr := publicsuffix.EffectiveTLDPlusOne(pageHost)
	resourceDomain, resourceErr := publicsuffix.EffectiveTLDPlusOne(resourceHost)
	if pageErr != nil || resourceErr != nil {
		return pageHost != resourceHost
	}
	return pageDomain != resourceDomain
}

// SanitizeURL removes fragments and masks all query values for safe storage and
// diagnostic output.
func SanitizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	copy := *u
	copy.User = nil
	copy.Fragment = ""
	copy.RawFragment = ""
	if copy.RawQuery != "" {
		copy.RawQuery = "redacted"
		copy.ForceQuery = false
	}
	return copy.String()
}
