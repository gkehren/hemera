package browser

import (
	"context"
	"errors"
	"fmt"
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

	warningDOMLimit      = "final DOM reached the capture limit"
	warningRequestLimit  = "browser requests reached the capture limit"
	warningResponseLimit = "browser responses reached the capture limit"
	warningCookieLimit   = "browser cookie names reached the capture limit"
	warningScriptLimit   = "browser script URLs reached the capture limit"
	warningIframeLimit   = "browser iframe URLs reached the capture limit"
	warningURLLimit      = "a browser URL exceeded the capture limit and was omitted"
)

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
// The truncation fields expose structured completion state per evidence
// channel so capability-level coverage never has to parse warnings.
type CaptureResult struct {
	FinalURL     string
	DOM          string
	DOMTruncated bool
	Requests     []CaptureRequest
	Responses    []CaptureResponse
	ScriptURLs   []string
	IframeURLs   []string
	Cookies      []CaptureCookie
	Warnings     []string
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
	result.ScriptURLs = slices.Clone(result.ScriptURLs)
	result.IframeURLs = slices.Clone(result.IframeURLs)
	result.Cookies = slices.Clone(result.Cookies)
	result.Warnings = slices.Clone(result.Warnings)
	return result
}

type captureCollector struct {
	mu        sync.Mutex
	requests  []CaptureRequest
	responses []CaptureResponse
	truncated channelTruncation
	warnings  []string
	warned    map[string]struct{}
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
	return &captureCollector{warned: make(map[string]struct{})}
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
	if len(c.requests) >= maxCaptureItems {
		c.truncated.requests = true
		c.warn(warningRequestLimit)
		return
	}
	c.requests = append(c.requests, CaptureRequest{
		Method: cleanMetadata(method), URL: cleanURL, ResourceType: cleanMetadata(resourceType),
	})
}

func (c *captureCollector) addResponse(rawURL string, status int64, mimeType, resourceType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cleanURL, urlStatus := c.classifyURL(rawURL)
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
		URL: cleanURL, Status: status, MIMEType: cleanMetadata(mimeType), ResourceType: cleanMetadata(resourceType),
	})
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
	}
	if cleaned, ok := c.cleanURL(finalURL); ok {
		result.FinalURL = cleaned
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
		if snapshot.URLTruncated {
			c.truncated.scripts = true
			c.truncated.iframes = true
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
