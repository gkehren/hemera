// Package safeoutput converts internal errors and URLs into bounded,
// presentation-safe text for terminal output.
//
// Terminal presentation is a trust boundary: error strings may embed
// attacker-controlled material such as page URLs or header echoes, and raw
// bytes can alter terminal state or leak secrets that were never meant for
// display. The package provides the canonical URL-minimization policy shared
// by report rendering and one diagnostic sanitizer for CLI error paths. It
// performs no network or scanner work and must stay free of dependencies on
// analyzers and presentation packages.
package safeoutput

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxDiagnosticBytes bounds the size of a sanitized diagnostic, including
// any truncation marker.
const MaxDiagnosticBytes = 1024

// truncationMarker is appended to diagnostics cut at MaxDiagnosticBytes. Its
// length is part of the bound.
const truncationMarker = "…"

var (
	// urlPattern matches HTTP and HTTPS URLs embedded in free text. The
	// character class excludes whitespace and common delimiters so a match
	// ends before surrounding prose.
	urlPattern = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
	// csiPattern matches ANSI CSI sequences including their parameter and
	// intermediate bytes and final byte.
	csiPattern = regexp.MustCompile(`\x1b\[[0-9:;<=>?]*[ -/]*[@-~]`)
	// oscPattern matches OSC sequences terminated by BEL or ST. An
	// unterminated sequence consumes the remaining printable run, trading
	// completeness for a deterministic safety guarantee.
	oscPattern = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?`)
)

// SanitizeURL minimizes rawURL for presentation using Hemera's canonical URL
// policy: credentials and fragments are removed, any query string is replaced
// with "redacted", and scheme, host, and path are preserved. It returns an
// empty string when rawURL is empty, unparseable, not HTTP(S), or missing a
// host, so callers can fail closed instead of echoing the raw value.
func SanitizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.Fragment = ""
	parsed.RawFragment = ""
	if parsed.RawQuery != "" {
		parsed.RawQuery = "redacted"
		parsed.ForceQuery = false
	}
	return parsed.String()
}

// InvalidTargetPlaceholder is rendered when a target URL cannot be safely
// minimized for display. Callers fail closed instead of echoing raw input.
const InvalidTargetPlaceholder = "<invalid target>"

// DisplayURL returns the minimized form of rawURL for interactive display,
// following the same canonical policy as SanitizeURL and the final report.
// Values that cannot be safely parsed become InvalidTargetPlaceholder rather
// than falling back to the raw value. The transformation is idempotent.
func DisplayURL(rawURL string) string {
	if sanitized := SanitizeURL(rawURL); sanitized != "" {
		return sanitized
	}
	return InvalidTargetPlaceholder
}

// SanitizeDiagnostic converts err into bounded, single-line,
// presentation-safe text suitable for stderr. Embedded HTTP(S) URLs are
// minimized with SanitizeURL, ANSI/OSC escape sequences are removed, control
// format and bidirectional-override characters are replaced or dropped, and
// the result is truncated deterministically at MaxDiagnosticBytes while
// preserving valid UTF-8. Sanitization never changes error identity: callers
// classify exit codes from the original error with errors.Is.
func SanitizeDiagnostic(err error) string {
	if err == nil {
		return ""
	}
	return boundText(redactURLs(stripControls(err.Error())))
}

// PlainText removes ANSI escape sequences and rewrites control, format, and
// bidirectional-override characters so the result is printable Unicode plus
// normal spaces on a single line. Unlike SanitizeDiagnostic it performs no
// URL redaction and no length bounding; use it for short labels and messages
// that must never alter terminal state even when their inputs are not fully
// trusted.
func PlainText(text string) string {
	return stripControls(text)
}

// stripControls removes terminal escape sequences and rewrites control,
// format, and bidirectional-override characters so the result contains only
// printable Unicode plus normal spaces on a single line. Controls are
// stripped before URL redaction so escape bytes cannot split or disguise
// URL matches.
func stripControls(text string) string {
	text = csiPattern.ReplaceAllString(text, "")
	text = oscPattern.ReplaceAllString(text, "")
	text = strings.ReplaceAll(text, "\x1b", "")
	var builder strings.Builder
	builder.Grow(len(text))
	for _, r := range text {
		switch {
		case r < ' ' || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			builder.WriteRune(' ')
		case r >= '\u200b' && r <= '\u200f',
			r >= '\u202a' && r <= '\u202e',
			r >= '\u2066' && r <= '\u2069',
			r == '\ufeff':
			// Invisible formatting characters can spoof display order or
			// hide content; they carry no diagnostic value.
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// redactURLs replaces every embedded HTTP(S) URL with its minimized form.
// Matches that SanitizeURL rejects are dropped rather than echoed.
func redactURLs(text string) string {
	return urlPattern.ReplaceAllStringFunc(text, func(match string) string {
		return SanitizeURL(match)
	})
}

// boundText trims surrounding whitespace and enforces MaxDiagnosticBytes,
// cutting on a rune boundary and appending truncationMarker when needed so
// the result stays valid UTF-8.
func boundText(text string) string {
	text = strings.TrimSpace(text)
	if len(text) <= MaxDiagnosticBytes {
		return text
	}
	limit := MaxDiagnosticBytes - len(truncationMarker)
	for limit > 0 && !utf8.RuneStart(text[limit]) {
		limit--
	}
	return strings.TrimRight(text[:limit], " ") + truncationMarker
}
