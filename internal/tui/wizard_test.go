package tui

import (
	"strings"
	"testing"
)

func TestValidateTargetURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "https URL", input: "https://example.com/path", wantErr: false},
		{name: "http URL", input: "http://example.com", wantErr: false},
		{name: "surrounding whitespace is trimmed", input: "  https://example.com  ", wantErr: false},
		{name: "empty", input: "", wantErr: true},
		{name: "blank", input: "   ", wantErr: true},
		{name: "unsupported scheme", input: "ftp://example.com", wantErr: true},
		{name: "missing host", input: "https://", wantErr: true},
		{name: "embedded credentials", input: "https://user:pass@example.com", wantErr: true},
		{
			// Loopback is syntactically valid on purpose: the wizard only
			// applies the canonical URL parser, while the public-destination
			// policy stays authoritative at scan time (covered by the
			// httpanalyzer ErrInitialTarget fixtures).
			name: "loopback passes syntactic validation", input: "http://127.0.0.1", wantErr: false,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := validateTargetURL(testCase.input)
			if gotErr := err != nil; gotErr != testCase.wantErr {
				t.Fatalf("validateTargetURL(%q) error = %v, wantErr %v", testCase.input, err, testCase.wantErr)
			}
			if !testCase.wantErr {
				return
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("error message contains newlines: %q", err.Error())
			}
		})
	}
}

// TestValidateTargetURLSanitizesEmbeddedInput proves validation messages
// stay presentation-safe even when net/url embeds fragments of the raw input
// in its parse errors: no control, escape, or bidi-override characters may
// reach the form's error rendering.
func TestValidateTargetURLSanitizesEmbeddedInput(t *testing.T) {
	t.Parallel()
	// The percent-escape is invalid so url.Parse fails and echoes the raw
	// input; the bidi override rides along inside that echoed fragment.
	input := "https://exa\u202emple.test/%zz"
	err := validateTargetURL(input)
	if err == nil {
		t.Fatalf("validateTargetURL(%q) error = nil, want error", input)
	}
	message := err.Error()
	for _, unsafe := range []string{"\x1b", "\r", "\n", "\u202e"} {
		if strings.Contains(message, unsafe) {
			t.Errorf("validation message contains %q: %q", unsafe, message)
		}
	}
	if !strings.HasPrefix(message, "invalid target URL") {
		t.Errorf("validation message lost policy wording: %q", message)
	}
}

// TestProgressModelNeutralizesUnknownSourceLabels proves the stage-label
// default branch cannot pass control bytes through to Lip Gloss even if a
// future analyzer registers an unexpected source identifier. The assertion
// targets the label value: the surrounding frame intentionally contains
// Lip Gloss's own Hemera-controlled styling sequences.
func TestProgressModelNeutralizesUnknownSourceLabels(t *testing.T) {
	t.Parallel()
	label := stageLabel("weird\x1b[31m_analyzer\r")
	for _, r := range label {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("stageLabel contains control rune %#04x: %q", r, label)
		}
	}
	if label != "weird analyzer" && label != "weird analyzer " {
		t.Fatalf("stageLabel = %q, want readable label", label)
	}

	model := newProgressModel([]string{"weird\x1b[31m_analyzer\r"}, "https://example.test/", nil)
	if content := model.View().Content; !strings.Contains(content, "weird analyzer") {
		t.Errorf("view lost sanitized label: %q", content)
	}
}

func TestAccessibleModeEnvironmentVariable(t *testing.T) {
	t.Setenv("HEMERA_ACCESSIBLE", "")
	if accessibleMode() {
		t.Fatal("accessibleMode() = true without configuration")
	}
	t.Setenv("HEMERA_ACCESSIBLE", "1")
	if !accessibleMode() {
		t.Fatal("accessibleMode() = false with HEMERA_ACCESSIBLE=1")
	}
	t.Setenv("HEMERA_ACCESSIBLE", "TRUE")
	if !accessibleMode() {
		t.Fatal("accessibleMode() = false with HEMERA_ACCESSIBLE=TRUE")
	}
}
