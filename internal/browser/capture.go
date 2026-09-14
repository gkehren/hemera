package browser

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/net/html"
)

const (
	maxDOMBytes      = 2 << 20
	maxDOMWorkItems  = 100000
	maxCaptureItems  = 4096
	maxMetadataBytes = 8192
	// maxTimingMs bounds every captured duration. A request cannot outlive the
	// navigation window, so this generous ceiling only absorbs clock skew in
	// relative CDP timing data.
	maxTimingMs = 60000

	warningDOMLimit         = "final DOM reached the capture limit"
	warningRequestLimit     = "browser requests reached the capture limit"
	warningResponseLimit    = "browser responses reached the capture limit"
	warningCookieLimit      = "browser cookie names reached the capture limit"
	warningScriptLimit      = "browser script URLs reached the capture limit"
	warningIframeLimit      = "browser iframe URLs reached the capture limit"
	warningURLLimit         = "a browser URL exceeded the capture limit and was omitted"
	warningTransactionLimit = "browser network transactions reached the capture limit"
)

// CaptureTiming holds bounded integer millisecond durations for one browser
// request. Zero marks a phase that was not observed. Only relative durations
// are retained; absolute timestamps are discarded at the CDP boundary.
type CaptureTiming struct {
	QueueMs   int64
	DNSMs     int64
	ConnectMs int64
	TLSMs     int64
	TTFBMs    int64
	TotalMs   int64
}

// CaptureTransaction is one correlated browser request/response observation.
// Status is zero when no response was observed. It exists only between the CDP
// boundary and normalization: CDP request identifiers are used for in-memory
// correlation and are never retained.
type CaptureTransaction struct {
	Method           string
	URL              string
	Status           int64
	MIMEType         string
	ResourceType     string
	Protocol         string
	ConnectionReused bool
	WireBytes        int64
	Timing           CaptureTiming
}

// responseObservation is the minimized CDP response data the collector needs.
type responseObservation struct {
	rawURL           string
	status           int64
	mimeType         string
	resourceType     string
	protocol         string
	connectionReused bool
	requestTime      float64
	timing           CaptureTiming
}

// CaptureRequest is a minimized browser request observation.
type CaptureRequest struct {
	Method       string
	URL          string
	ResourceType string
}

// CaptureResponse is a minimized browser response observation.
type CaptureResponse struct {
	URL          string
	Status       int64
	MIMEType     string
	ResourceType string
}

// CaptureCookie is a minimized cookie observation. Values are discarded by
// the CDP boundary before this type is constructed.
type CaptureCookie struct {
	Name   string
	Domain string
}

// CaptureResult contains bounded observations from one browser target. It is
// internal to the browser integration and is not a report or detection model.
// The truncation and incomplete fields expose structured completion state per
// evidence channel so capability-level coverage never has to parse warnings
// or interpret aggregated errors.
type CaptureResult struct {
	FinalURL        string
	DOM             string
	DOMTruncated    bool
	Requests        []CaptureRequest
	Responses       []CaptureResponse
	Transactions    []CaptureTransaction
	FormSubmissions []FormSubmission
	ScriptURLs      []string
	IframeURLs      []string
	Cookies         []CaptureCookie
	Warnings        []string
	// FinalURLIncomplete reports that the navigation's final URL could not be
	// sanitized within the capture contract or was never observed, so signals
	// whose provenance URL would have come from it cannot support conclusive
	// URL predicates.
	FinalURLIncomplete bool
	// NavigationIncomplete reports that navigation did not finish cleanly, so
	// no browser channel can be treated as conclusively evaluated.
	NavigationIncomplete bool
	// DOMIncomplete reports that bounded DOM collection failed before it could
	// produce a snapshot, so every DOM-derived channel stays inconclusive.
	DOMIncomplete bool
	// CookiesIncomplete reports that cookie collection failed outright rather
	// than merely reaching its ceiling.
	CookiesIncomplete bool
	// RequestsTruncated reports that request capture reached its collection
	// ceiling or omitted an oversized request URL.
	RequestsTruncated bool
	// ResponsesTruncated reports that response capture reached its collection
	// ceiling or omitted an oversized response URL.
	ResponsesTruncated bool
	// ScriptURLsTruncated reports that script URL collection reached its
	// ceiling, was cut off by traversal truncation, or omitted an oversized
	// script URL.
	ScriptURLsTruncated bool
	// IframeURLsTruncated reports that iframe URL collection reached its
	// ceiling, was cut off by traversal truncation, or omitted an oversized
	// iframe URL.
	IframeURLsTruncated bool
	// CookiesTruncated reports that cookie collection exceeded its ceiling.
	CookiesTruncated bool
}

type boundedDOMSnapshot struct {
	DOM                string   `json:"dom"`
	ScriptURLs         []string `json:"script_urls"`
	IframeURLs         []string `json:"iframe_urls"`
	DOMTruncated       bool     `json:"dom_truncated"`
	ScriptTruncated    bool     `json:"script_truncated"`
	IframeTruncated    bool     `json:"iframe_truncated"`
	TraversalTruncated bool     `json:"traversal_truncated"`
	URLTruncated       bool     `json:"url_truncated"`
}

// Recorder owns one active capture on a Session.
type Recorder struct {
	source  captureSource
	release func(*Recorder)
	once    sync.Once
	done    chan struct{}
	result  CaptureResult
	err     error
	closed  bool
}

func newRecorder(source captureSource, release func(*Recorder)) *Recorder {
	return &Recorder{source: source, release: release, done: make(chan struct{})}
}

// Finish stops event collection and returns the final bounded snapshot. Calls
// after the first return an independent clone of the same result and error.
func (r *Recorder) Finish(ctx context.Context) (CaptureResult, error) {
	if ctx == nil {
		return CaptureResult{}, errors.New("finish browser capture: nil context")
	}
	r.once.Do(func() {
		r.result, r.err = r.source.finish(ctx)
		r.err = wrapCaptureError("finish browser capture", r.err)
		r.release(r)
		close(r.done)
	})
	<-r.done
	if r.closed {
		return CaptureResult{}, errors.Join(ErrRecorderClosed, r.err)
	}
	return cloneCaptureResult(r.result), r.err
}

// Close abandons the capture without taking a final snapshot. It is idempotent.
func (r *Recorder) Close() error {
	r.once.Do(func() {
		r.closed = true
		r.err = wrapCaptureError("close browser capture", r.source.Close())
		r.release(r)
		close(r.done)
	})
	<-r.done
	if r.closed {
		return r.err
	}
	return nil
}

func wrapCaptureError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func cloneCaptureResult(result CaptureResult) CaptureResult {
	result.Requests = slices.Clone(result.Requests)
	result.Responses = slices.Clone(result.Responses)
	result.Transactions = slices.Clone(result.Transactions)
	result.FormSubmissions = slices.Clone(result.FormSubmissions)
	result.ScriptURLs = slices.Clone(result.ScriptURLs)
	result.IframeURLs = slices.Clone(result.IframeURLs)
	result.Cookies = slices.Clone(result.Cookies)
	result.Warnings = slices.Clone(result.Warnings)
	return result
}

type captureCollector struct {
	mu           sync.Mutex
	requests     []CaptureRequest
	responses    []CaptureResponse
	transactions []CaptureTransaction
	pending      map[string]*pendingTransaction
	truncated    channelTruncation
	warnings     []string
	warned       map[string]struct{}
	progress     func(ObservationCounters)
}

// pendingTransaction correlates CDP request identifiers with their in-flight
// transaction entry. The identifier is never retained in results.
type pendingTransaction struct {
	index          int
	startTimestamp float64
}

// channelTruncation records which bounded capture channels did not run to
// completion. It is structured state; warning strings remain presentation
// diagnostics only.
type channelTruncation struct {
	requests  bool
	responses bool
	scripts   bool
	iframes   bool
	cookies   bool
}

func newCaptureCollector() *captureCollector {
	return &captureCollector{pending: make(map[string]*pendingTransaction), warned: make(map[string]struct{})}
}

// beginRequest records one request observation and starts its transaction
// correlation. The id is a CDP request identifier and timestamp a relative CDP
// monotonic time; neither is retained in results.
func (c *captureCollector) beginRequest(id, method, rawURL, resourceType string, timestamp float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cleanMethod := cleanMetadata(method)
	cleanURL, ok := c.cleanURL(rawURL)
	if ok {
		c.appendRequestLocked(CaptureRequest{
			Method: cleanMethod, URL: cleanURL, ResourceType: cleanMetadata(resourceType),
		})
	}
	if id == "" || !utf8.ValidString(rawURL) {
		return
	}
	if _, active := c.pending[id]; active {
		return
	}
	if len(c.pending) >= maxCaptureItems {
		c.warn(warningTransactionLimit)
		return
	}
	index := len(c.transactions)
	if !c.appendTransactionLocked(CaptureTransaction{
		Method: cleanMethod, URL: cleanURL, ResourceType: cleanMetadata(resourceType),
	}) {
		return
	}
	c.pending[id] = &pendingTransaction{index: index, startTimestamp: timestamp}
}

// observeResponse records one response observation and patches the correlated
// transaction with status, protocol, reuse, and timing phases.
func (c *captureCollector) observeResponse(id string, response responseObservation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.appendResponseLocked(response)
	if pending := c.pending[id]; pending != nil && pending.index < len(c.transactions) {
		c.patchTransactionLocked(&c.transactions[pending.index], response, pending.startTimestamp)
	}
}

// observeRedirect records one intermediate redirect response, closes the
// current transaction hop, and leaves the identifier free for the next hop
// that the accompanying request event opens.
func (c *captureCollector) observeRedirect(id string, response responseObservation, timestamp float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.appendResponseLocked(response)
	if pending := c.pending[id]; pending != nil && pending.index < len(c.transactions) {
		c.patchTransactionLocked(&c.transactions[pending.index], response, pending.startTimestamp)
		if totalMs := boundedDurationMs(timestamp - pending.startTimestamp); totalMs > 0 {
			c.transactions[pending.index].Timing.TotalMs = totalMs
		}
	}
	delete(c.pending, id)
}

// finishRequest patches the correlated transaction with the transferred wire
// size and total duration, then ends its correlation window.
func (c *captureCollector) finishRequest(id string, wireBytes int64, timestamp float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pending := c.pending[id]; pending != nil && pending.index < len(c.transactions) {
		entry := &c.transactions[pending.index]
		if wireBytes > 0 {
			entry.WireBytes = wireBytes
		}
		if totalMs := boundedDurationMs(timestamp - pending.startTimestamp); totalMs > 0 {
			entry.Timing.TotalMs = totalMs
		}
	}
	delete(c.pending, id)
}

// failRequest ends the correlation window of a request that never completed.
func (c *captureCollector) failRequest(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, id)
}

func (c *captureCollector) patchTransactionLocked(entry *CaptureTransaction, response responseObservation, startTimestamp float64) {
	entry.Status = response.status
	if mimeType := cleanMetadata(response.mimeType); mimeType != "" {
		entry.MIMEType = mimeType
	}
	if protocol := cleanMetadata(response.protocol); protocol != "" {
		entry.Protocol = protocol
	}
	entry.ConnectionReused = response.connectionReused
	if response.timing.DNSMs > 0 {
		entry.Timing.DNSMs = response.timing.DNSMs
	}
	if response.timing.ConnectMs > 0 {
		entry.Timing.ConnectMs = response.timing.ConnectMs
	}
	if response.timing.TLSMs > 0 {
		entry.Timing.TLSMs = response.timing.TLSMs
	}
	if response.timing.TTFBMs > 0 {
		entry.Timing.TTFBMs = response.timing.TTFBMs
	}
	if queueMs := boundedDurationMs(response.requestTime - startTimestamp); queueMs > 0 {
		entry.Timing.QueueMs = queueMs
	}
}

// boundedDurationMs converts a relative CDP duration in seconds into bounded
// integer milliseconds. Non-finite, zero, and negative values collapse to zero
// and the result never exceeds maxTimingMs.
func boundedDurationMs(seconds float64) int64 {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 {
		return 0
	}
	milliseconds := math.Round(seconds * 1000)
	if milliseconds > maxTimingMs {
		return maxTimingMs
	}
	return int64(milliseconds)
}

func (c *captureCollector) addRequest(method, rawURL, resourceType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cleanURL, status := c.classifyURL(rawURL)
	if status == urlOversizedDropped {
		c.truncated.requests = true
	}
	if status != urlAccepted {
		return
	}
	c.appendRequestLocked(CaptureRequest{
		Method: cleanMetadata(method), URL: cleanURL, ResourceType: cleanMetadata(resourceType),
	})
}

func (c *captureCollector) appendRequestLocked(request CaptureRequest) {
	if len(c.requests) >= maxCaptureItems {
		c.truncated.requests = true
		c.warn(warningRequestLimit)
		return
	}
	c.requests = append(c.requests, request)
}

// appendTransactionLocked stores one transaction observation and reports
// whether it fit within the capture budget.
func (c *captureCollector) appendTransactionLocked(transaction CaptureTransaction) bool {
	if len(c.transactions) >= maxCaptureItems {
		c.warn(warningTransactionLimit)
		return false
	}
	c.transactions = append(c.transactions, transaction)
	return true
}

func (c *captureCollector) addResponse(rawURL string, status int64, mimeType, resourceType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.appendResponseLocked(responseObservation{
		rawURL: rawURL, status: status, mimeType: mimeType, resourceType: resourceType,
	})
}

func (c *captureCollector) appendResponseLocked(response responseObservation) {
	cleanURL, urlStatus := c.classifyURL(response.rawURL)
	if urlStatus == urlOversizedDropped {
		c.truncated.responses = true
	}
	if urlStatus != urlAccepted {
		return
	}
	if len(c.responses) >= maxCaptureItems {
		c.truncated.responses = true
		c.warn(warningResponseLimit)
		return
	}
	c.responses = append(c.responses, CaptureResponse{
		URL: cleanURL, Status: response.status, MIMEType: cleanMetadata(response.mimeType),
		ResourceType: cleanMetadata(response.resourceType),
	})
}

// counterSnapshot returns a presentation-safe aggregate snapshot of the
// capture volume. The caller-provided progress callback must be invoked
// outside the collector lock, so this returns a value copy.
func (c *captureCollector) counterSnapshot() ObservationCounters {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ObservationCounters{Requests: len(c.requests), Responses: len(c.responses)}
}

func (c *captureCollector) snapshot(finalURL, dom string, cookies []CaptureCookie) CaptureResult {
	return c.snapshotInternal(finalURL, boundedDOMSnapshot{DOM: dom}, cookies, false)
}

func (c *captureCollector) snapshotBounded(finalURL string, snapshot boundedDOMSnapshot, cookies []CaptureCookie) CaptureResult {
	return c.snapshotInternal(finalURL, snapshot, cookies, true)
}

func (c *captureCollector) snapshotInternal(finalURL string, snapshot boundedDOMSnapshot, cookies []CaptureCookie, resourcesCaptured bool) CaptureResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := CaptureResult{
		Requests: slices.Clone(c.requests), Responses: slices.Clone(c.responses),
		Transactions: c.sortedTransactionsLocked(),
	}
	if cleaned, ok := c.cleanURL(finalURL); ok {
		result.FinalURL = cleaned
	} else {
		result.FinalURLIncomplete = true
	}
	if resourcesCaptured {
		result.ScriptURLs = c.cleanResourceURLs(snapshot.ScriptURLs, warningScriptLimit, &c.truncated.scripts)
		result.IframeURLs = c.cleanResourceURLs(snapshot.IframeURLs, warningIframeLimit, &c.truncated.iframes)
		if snapshot.ScriptTruncated || snapshot.TraversalTruncated {
			c.truncated.scripts = true
			c.warn(warningScriptLimit)
		}
		if snapshot.IframeTruncated || snapshot.TraversalTruncated {
			c.truncated.iframes = true
			c.warn(warningIframeLimit)
		}
		// URLTruncated is a serializer-level diagnostic for oversized resource
		// URLs. The serializer already attributes each dropped URL to its own
		// channel, so it must not widen truncation to both resource channels.
		if snapshot.URLTruncated {
			c.warn(warningURLLimit)
		}
	} else {
		result.ScriptURLs, result.IframeURLs = c.extractResourceURLs(snapshot.DOM, result.FinalURL)
	}
	if len(snapshot.DOM) > maxDOMBytes {
		result.DOM = truncateUTF8(snapshot.DOM, maxDOMBytes)
		result.DOMTruncated = true
		c.warn(warningDOMLimit)
	} else if utf8.ValidString(snapshot.DOM) {
		result.DOM = snapshot.DOM
		result.DOMTruncated = snapshot.DOMTruncated || snapshot.TraversalTruncated
		if result.DOMTruncated {
			c.warn(warningDOMLimit)
		}
	}
	result.Cookies = c.cleanCookies(cookies)
	result.RequestsTruncated = c.truncated.requests
	result.ResponsesTruncated = c.truncated.responses
	result.ScriptURLsTruncated = c.truncated.scripts
	result.IframeURLsTruncated = c.truncated.iframes
	result.CookiesTruncated = c.truncated.cookies
	result.Warnings = slices.Clone(c.warnings)
	return result
}

// sortedTransactionsLocked returns a deterministic canonical ordering of the
// captured transactions. Capture order is wall-clock dependent, so reports
// must not depend on it.
func (c *captureCollector) sortedTransactionsLocked() []CaptureTransaction {
	transactions := slices.Clone(c.transactions)
	sort.Slice(transactions, func(i, j int) bool {
		left, right := transactions[i], transactions[j]
		leftFields := [...][]string{
			{left.URL, left.Method, left.MIMEType, left.ResourceType, left.Protocol},
			{right.URL, right.Method, right.MIMEType, right.ResourceType, right.Protocol},
		}
		for index := range leftFields[0] {
			if leftFields[0][index] != leftFields[1][index] {
				return leftFields[0][index] < leftFields[1][index]
			}
		}
		leftNumbers := [...]int64{left.Status, left.WireBytes,
			left.Timing.QueueMs, left.Timing.DNSMs, left.Timing.ConnectMs,
			left.Timing.TLSMs, left.Timing.TTFBMs, left.Timing.TotalMs}
		rightNumbers := [...]int64{right.Status, right.WireBytes,
			right.Timing.QueueMs, right.Timing.DNSMs, right.Timing.ConnectMs,
			right.Timing.TLSMs, right.Timing.TTFBMs, right.Timing.TotalMs}
		for index := range leftNumbers {
			if leftNumbers[index] != rightNumbers[index] {
				return leftNumbers[index] < rightNumbers[index]
			}
		}
		if left.ConnectionReused != right.ConnectionReused {
			return !left.ConnectionReused
		}
		return false
	})
	return transactions
}

func (c *captureCollector) cleanResourceURLs(rawURLs []string, limitWarning string, truncated *bool) []string {
	cleaned := make([]string, 0, min(len(rawURLs), maxCaptureItems))
	for _, rawURL := range rawURLs {
		url, status := c.classifyURL(rawURL)
		if status == urlOversizedDropped && truncated != nil {
			*truncated = true
		}
		if status != urlAccepted {
			continue
		}
		if len(cleaned) == maxCaptureItems {
			if truncated != nil {
				*truncated = true
			}
			c.warn(limitWarning)
			continue
		}
		cleaned = append(cleaned, url)
	}
	return cleaned
}

const (
	urlAccepted = iota
	urlRejected
	urlOversizedDropped
)

// cleanURL sanitizes one raw URL, reporting whether it was accepted.
func (c *captureCollector) cleanURL(raw string) (string, bool) {
	cleaned, status := c.classifyURL(raw)
	if status != urlAccepted {
		return "", false
	}
	return cleaned, true
}

// classifyURL sanitizes one raw URL and reports whether it was accepted,
// rejected by validation, or dropped for exceeding the URL size ceiling.
func (c *captureCollector) classifyURL(raw string) (string, int) {
	if len(raw) > maxBrowserURLBytes {
		c.warn(warningURLLimit)
		return "", urlOversizedDropped
	}
	if raw == "" || !utf8.ValidString(raw) || hasUnsafeText(raw) {
		return "", urlRejected
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", urlRejected
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", urlRejected
	}
	parsed.User = nil
	parsed.Fragment = ""
	parsed.RawFragment = ""
	if parsed.RawQuery != "" || parsed.ForceQuery {
		parsed.RawQuery = "redacted"
		parsed.ForceQuery = false
	}
	cleaned := parsed.String()
	if len(cleaned) > maxBrowserURLBytes {
		c.warn(warningURLLimit)
		return "", urlOversizedDropped
	}
	return cleaned, urlAccepted
}

// sameOrigin reports whether an already-cleaned action URL targets the same
// origin as an already-cleaned page URL.
func sameOrigin(pageURL, actionURL string) bool {
	page, err := url.Parse(pageURL)
	if err != nil {
		return false
	}
	action, err := url.Parse(actionURL)
	if err != nil {
		return false
	}
	return page.Scheme == action.Scheme && page.Host == action.Host
}

func (c *captureCollector) extractResourceURLs(dom, finalURL string) ([]string, []string) {
	if !utf8.ValidString(dom) {
		return nil, nil
	}
	base, _ := url.Parse(finalURL)
	base = firstDocumentBase(dom, base)
	var scripts, iframes []string
	tokenizer := html.NewTokenizer(strings.NewReader(dom))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "script" && token.Data != "iframe" {
			continue
		}
		raw := attribute(token, "src")
		if raw == "" {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if base != nil {
			ref = base.ResolveReference(ref)
		}
		cleaned, status := c.classifyURL(ref.String())
		if token.Data == "script" {
			if status == urlOversizedDropped {
				c.truncated.scripts = true
			}
			if status != urlAccepted {
				continue
			}
			if len(scripts) == maxCaptureItems {
				c.truncated.scripts = true
				c.warn(warningScriptLimit)
				continue
			}
			scripts = append(scripts, cleaned)
		} else {
			if status == urlOversizedDropped {
				c.truncated.iframes = true
			}
			if status != urlAccepted {
				continue
			}
			if len(iframes) == maxCaptureItems {
				c.truncated.iframes = true
				c.warn(warningIframeLimit)
				continue
			}
			iframes = append(iframes, cleaned)
		}
	}
	return scripts, iframes
}

func firstDocumentBase(dom string, fallback *url.URL) *url.URL {
	tokenizer := html.NewTokenizer(strings.NewReader(dom))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			return fallback
		}
		if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "base" {
			continue
		}
		href := attribute(token, "href")
		parsed, err := url.Parse(href)
		if err != nil || href == "" {
			continue
		}
		if fallback != nil {
			parsed = fallback.ResolveReference(parsed)
		}
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			return parsed
		}
	}
}

func attribute(token html.Token, name string) string {
	for _, attr := range token.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func (c *captureCollector) cleanCookies(cookies []CaptureCookie) []CaptureCookie {
	set := make(map[CaptureCookie]struct{}, min(len(cookies), maxCaptureItems))
	for _, cookie := range cookies {
		cookie.Name = cleanMetadata(cookie.Name)
		cookie.Domain = cleanCookieDomain(cookie.Domain)
		if cookie.Name == "" || cookie.Domain == "" {
			continue
		}
		set[cookie] = struct{}{}
	}
	cleaned := make([]CaptureCookie, 0, min(len(set), maxCaptureItems))
	for cookie := range set {
		cleaned = append(cleaned, cookie)
	}
	sort.Slice(cleaned, func(i, j int) bool {
		if cleaned[i].Name != cleaned[j].Name {
			return cleaned[i].Name < cleaned[j].Name
		}
		return cleaned[i].Domain < cleaned[j].Domain
	})
	if len(cleaned) > maxCaptureItems {
		cleaned = cleaned[:maxCaptureItems]
		c.truncated.cookies = true
		c.warn(warningCookieLimit)
	}
	return cleaned
}

func cleanCookieDomain(domain string) string {
	if cleanMetadata(domain) == "" || domain != strings.ToLower(domain) {
		return ""
	}
	host := strings.TrimPrefix(domain, ".")
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return ""
	}
	if address := net.ParseIP(host); address != nil {
		return domain
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return ""
			}
		}
	}
	return domain
}

func (c *captureCollector) warn(warning string) {
	if _, ok := c.warned[warning]; ok {
		return
	}
	c.warned[warning] = struct{}{}
	c.warnings = append(c.warnings, warning)
}

func cleanMetadata(value string) string {
	if value == "" || len(value) > maxMetadataBytes || !utf8.ValidString(value) || hasUnsafeText(value) {
		return ""
	}
	return value
}

func hasUnsafeText(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}
