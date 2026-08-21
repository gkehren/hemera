package safeoutput

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeURLMinimizesSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{
			name: "plain URL is preserved",
			raw:  "https://example.test/api/list",
			want: "https://example.test/api/list",
		},
		{
			name: "query is redacted",
			raw:  "https://example.test/api?token=SUPER_SECRET",
			want: "https://example.test/api?redacted",
		},
		{
			name: "credentials and fragment are removed",
			raw:  "https://user:password@example.test/path?secret=x#private",
			want: "https://example.test/path?redacted",
		},
		{name: "empty query keeps bare question mark off", raw: "https://example.test/p#", want: "https://example.test/p"},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := SanitizeURL(testCase.raw); got != testCase.want {
				t.Errorf("SanitizeURL(%q) = %q, want %q", testCase.raw, got, testCase.want)
			}
		})
	}
}

func TestSanitizeURLRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"ftp://example.test/file", "https:///no-host", "https://exa mple.test/", "not a url"} {
		if got := SanitizeURL(raw); got != "" {
			t.Errorf("SanitizeURL(%q) = %q, want empty", raw, got)
		}
	}
}

func TestSanitizeDiagnosticRedactsQueryStrings(t *testing.T) {
	t.Parallel()
	out := SanitizeDiagnostic(errors.New("fetch https://example.test/api?token=SUPER_SECRET failed"))
	if strings.Contains(out, "SUPER_SECRET") || strings.Contains(out, "token=") {
		t.Errorf("diagnostic leaks the secret: %q", out)
	}
	if !strings.Contains(out, "?redacted") {
		t.Errorf("diagnostic lacks ?redacted marker: %q", out)
	}
	if !strings.Contains(out, "https://example.test/api") {
		t.Errorf("diagnostic dropped safe scheme/host/path: %q", out)
	}
}

func TestSanitizeDiagnosticRemovesCredentialsAndFragments(t *testing.T) {
	t.Parallel()
	out := SanitizeDiagnostic(errors.New(
		"request to https://user:password@example.test/path?secret=x#private failed"))
	for _, leaked := range []string{"user:", "password", "secret=x", "#private", "private"} {
		if strings.Contains(out, leaked) {
			t.Errorf("diagnostic leaks %q: %q", leaked, out)
		}
	}
	if !strings.Contains(out, "https://example.test/path?redacted") {
		t.Errorf("diagnostic lost minimized URL: %q", out)
	}
}

func TestSanitizeDiagnosticStripsTerminalEscapes(t *testing.T) {
	t.Parallel()
	payload := "\x1b[31mRED\x1b]8;;https://evil.test\aLINK\rrewritten"
	out := SanitizeDiagnostic(errors.New(payload))
	for _, b := range []byte(out) {
		if b < 0x20 || b == 0x7f {
			t.Fatalf("diagnostic contains control byte %#02x: %q", b, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("diagnostic retains ESC: %q", out)
	}
	if strings.Contains(out, "evil.test") {
		t.Errorf("diagnostic retains OSC payload target: %q", out)
	}
	if !strings.Contains(out, "RED") || !strings.Contains(out, "rewritten") {
		t.Errorf("diagnostic lost plain text content: %q", out)
	}
}

func TestSanitizeDiagnosticCollapsesToSingleLine(t *testing.T) {
	t.Parallel()
	out := SanitizeDiagnostic(errors.New("request failed\nattacker-controlled second line\r\nthird"))
	if strings.ContainsAny(out, "\n\r") {
		t.Errorf("diagnostic spans multiple lines: %q", out)
	}
	for _, phrase := range []string{"request failed", "attacker-controlled second line", "third"} {
		if !strings.Contains(out, phrase) {
			t.Errorf("diagnostic lost %q: %q", phrase, out)
		}
	}
}

func TestSanitizeDiagnosticIsBoundedAndValidUTF8(t *testing.T) {
	t.Parallel()
	huge := errors.New("https://example.test/api?token=SUPER_SECRET " + strings.Repeat("é", MaxDiagnosticBytes))
	out := SanitizeDiagnostic(huge)
	if len(out) > MaxDiagnosticBytes {
		t.Errorf("diagnostic length = %d, want <= %d", len(out), MaxDiagnosticBytes)
	}
	if !utf8.ValidString(out) {
		t.Errorf("diagnostic is not valid UTF-8: %q", out)
	}
	if !strings.HasSuffix(out, truncationMarker) {
		t.Errorf("diagnostic lacks truncation marker: %q", out)
	}
	if strings.Contains(out, "SUPER_SECRET") {
		t.Errorf("truncated diagnostic leaked the secret prefix: %q", out)
	}
}

func TestSanitizeDiagnosticNilError(t *testing.T) {
	t.Parallel()
	if out := SanitizeDiagnostic(nil); out != "" {
		t.Errorf("SanitizeDiagnostic(nil) = %q, want empty", out)
	}
}

func TestDisplayURLFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain URL unchanged", raw: "https://example.test/path", want: "https://example.test/path"},
		{name: "query minimized", raw: "https://example.test/api?token=SUPER_SECRET#frag", want: "https://example.test/api?redacted"},
		{name: "unparseable becomes placeholder", raw: "not a url", want: InvalidTargetPlaceholder},
		{name: "empty becomes placeholder", raw: "", want: InvalidTargetPlaceholder},
		{name: "non-HTTP scheme becomes placeholder", raw: "ftp://example.test/", want: InvalidTargetPlaceholder},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := DisplayURL(testCase.raw); got != testCase.want {
				t.Errorf("DisplayURL(%q) = %q, want %q", testCase.raw, got, testCase.want)
			}
		})
	}
}

func TestDisplayURLIsIdempotent(t *testing.T) {
	t.Parallel()
	once := DisplayURL("https://example.test/api?token=SUPER_SECRET#frag")
	if twice := DisplayURL(once); twice != once {
		t.Errorf("DisplayURL not idempotent: %q -> %q", once, twice)
	}
}
