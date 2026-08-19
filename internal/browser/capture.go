package browser

import (
	"context"
	"errors"
	"fmt"
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

// CaptureResult contains bounded observations from one browser target. It is
// internal to the browser integration and is not a report or detection model.
type CaptureResult struct {
	FinalURL     string
	DOM          string
	DOMTruncated bool
	Requests     []CaptureRequest
	Responses    []CaptureResponse
	ScriptURLs   []string
	IframeURLs   []string
	CookieNames  []string
	Warnings     []string
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
	result.CookieNames = slices.Clone(result.CookieNames)
	result.Warnings = slices.Clone(result.Warnings)
	return result
}

type captureCollector struct {
	mu        sync.Mutex
	requests  []CaptureRequest
	responses []CaptureResponse
	warnings  []string
	warned    map[string]struct{}
}

func newCaptureCollector() *captureCollector {
	return &captureCollector{warned: make(map[string]struct{})}
}

func (c *captureCollector) addRequest(method, rawURL, resourceType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cleanURL, ok := c.cleanURL(rawURL)
	if !ok {
		return
	}
	if len(c.requests) >= maxCaptureItems {
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
	cleanURL, ok := c.cleanURL(rawURL)
	if !ok {
		return
	}
	if len(c.responses) >= maxCaptureItems {
		c.warn(warningResponseLimit)
		return
	}
	c.responses = append(c.responses, CaptureResponse{
		URL: cleanURL, Status: status, MIMEType: cleanMetadata(mimeType), ResourceType: cleanMetadata(resourceType),
	})
}

func (c *captureCollector) snapshot(finalURL, dom string, cookieNames []string) CaptureResult {
	return c.snapshotInternal(finalURL, boundedDOMSnapshot{DOM: dom}, cookieNames, false)
}

func (c *captureCollector) snapshotBounded(finalURL string, snapshot boundedDOMSnapshot, cookieNames []string) CaptureResult {
	return c.snapshotInternal(finalURL, snapshot, cookieNames, true)
}

func (c *captureCollector) snapshotInternal(finalURL string, snapshot boundedDOMSnapshot, cookieNames []string, resourcesCaptured bool) CaptureResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := CaptureResult{
		Requests: slices.Clone(c.requests), Responses: slices.Clone(c.responses),
	}
	if cleaned, ok := c.cleanURL(finalURL); ok {
		result.FinalURL = cleaned
	}
	if resourcesCaptured {
		result.ScriptURLs = c.cleanResourceURLs(snapshot.ScriptURLs, warningScriptLimit)
		result.IframeURLs = c.cleanResourceURLs(snapshot.IframeURLs, warningIframeLimit)
		if snapshot.ScriptTruncated || snapshot.TraversalTruncated {
			c.warn(warningScriptLimit)
		}
		if snapshot.IframeTruncated || snapshot.TraversalTruncated {
			c.warn(warningIframeLimit)
		}
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
	result.CookieNames = c.cleanCookieNames(cookieNames)
	result.Warnings = slices.Clone(c.warnings)
	return result
}

func (c *captureCollector) cleanResourceURLs(rawURLs []string, limitWarning string) []string {
	cleaned := make([]string, 0, min(len(rawURLs), maxCaptureItems))
	for _, rawURL := range rawURLs {
		url, ok := c.cleanURL(rawURL)
		if !ok {
			continue
		}
		if len(cleaned) == maxCaptureItems {
			c.warn(limitWarning)
			continue
		}
		cleaned = append(cleaned, url)
	}
	return cleaned
}

func (c *captureCollector) cleanURL(raw string) (string, bool) {
	if len(raw) > maxBrowserURLBytes {
		c.warn(warningURLLimit)
		return "", false
	}
	if raw == "" || !utf8.ValidString(raw) || hasUnsafeText(raw) {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
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
		return "", false
	}
	return cleaned, true
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
		cleaned, ok := c.cleanURL(ref.String())
		if !ok {
			continue
		}
		if token.Data == "script" {
			if len(scripts) == maxCaptureItems {
				c.warn(warningScriptLimit)
				continue
			}
			scripts = append(scripts, cleaned)
		} else {
			if len(iframes) == maxCaptureItems {
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

func (c *captureCollector) cleanCookieNames(names []string) []string {
	set := make(map[string]struct{}, min(len(names), maxCaptureItems))
	for _, name := range names {
		name = cleanMetadata(name)
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}
	cleaned := make([]string, 0, min(len(set), maxCaptureItems))
	for name := range set {
		cleaned = append(cleaned, name)
	}
	sort.Strings(cleaned)
	if len(cleaned) > maxCaptureItems {
		cleaned = cleaned[:maxCaptureItems]
		c.warn(warningCookieLimit)
	}
	return cleaned
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
