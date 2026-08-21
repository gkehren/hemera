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
