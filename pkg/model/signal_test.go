package model

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

func TestSignalTypeValid(t *testing.T) {
	t.Parallel()

	validTypes := []SignalType{
		SignalTypeResponseHeader,
		SignalTypeCookie,
		SignalTypeScriptURL,
		SignalTypeNetworkRequest,
		SignalTypeNetworkResponse,
		SignalTypeDOMSelector,
		SignalTypeIframeURL,
		SignalTypeJSGlobal,
		SignalTypeDNSRecord,
		SignalTypeTLSProperty,
		SignalTypeRedirect,
		SignalTypePageContent,
	}

	for _, signalType := range validTypes {
		if !signalType.Valid() {
			t.Errorf("SignalType(%q).Valid() = false, want true", signalType)
		}
	}

	for _, signalType := range []SignalType{"", "unknown"} {
		if signalType.Valid() {
			t.Errorf("SignalType(%q).Valid() = true, want false", signalType)
		}
	}
}

func TestSignalValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		signal  Signal
		wantErr error
	}{
		{
			name: "valid signal",
			signal: Signal{
				Type:       SignalTypeScriptURL,
				Source:     "http_analyzer",
				Key:        "src",
				Value:      "https://challenges.cloudflare.com/turnstile/v0/api.js",
				URL:        "https://example.com/login",
				Confidence: 0.95,
			},
		},
		{
			name: "zero confidence is valid",
			signal: Signal{
				Type:       SignalTypePageContent,
				Source:     "http_analyzer",
				Key:        "body",
				Confidence: 0,
			},
		},
		{
			name: "one confidence is valid",
			signal: Signal{
				Type:       SignalTypeCookie,
				Source:     "browser_analyzer",
				Key:        "__cf_bm",
				Confidence: 1,
			},
		},
		{
			name: "invalid type",
			signal: Signal{
				Type:       "made_up",
				Source:     "test",
				Key:        "key",
				Confidence: 0.5,
			},
			wantErr: ErrInvalidSignalType,
		},
		{
			name: "missing source",
			signal: Signal{
				Type:       SignalTypeCookie,
				Source:     "  ",
				Key:        "name",
				Confidence: 0.5,
			},
			wantErr: ErrMissingSignalSource,
		},
		{
			name: "missing key",
			signal: Signal{
				Type:       SignalTypeCookie,
				Source:     "http_analyzer",
				Key:        "\t",
				Confidence: 0.5,
			},
			wantErr: ErrMissingSignalKey,
		},
		{
			name: "negative confidence",
			signal: Signal{
				Type:       SignalTypeCookie,
				Source:     "http_analyzer",
				Key:        "name",
				Confidence: -0.1,
			},
			wantErr: ErrInvalidSignalConfidence,
		},
		{
			name: "confidence above one",
			signal: Signal{
				Type:       SignalTypeCookie,
				Source:     "http_analyzer",
				Key:        "name",
				Confidence: 1.1,
			},
			wantErr: ErrInvalidSignalConfidence,
		},
		{
			name: "NaN confidence",
			signal: Signal{
				Type:       SignalTypeCookie,
				Source:     "http_analyzer",
				Key:        "name",
				Confidence: math.NaN(),
			},
			wantErr: ErrInvalidSignalConfidence,
		},
		{
			name: "infinite confidence",
			signal: Signal{
				Type:       SignalTypeCookie,
				Source:     "http_analyzer",
				Key:        "name",
				Confidence: math.Inf(1),
			},
			wantErr: ErrInvalidSignalConfidence,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.signal.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Signal.Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignalJSON(t *testing.T) {
	t.Parallel()

	signal := Signal{
		Type:       SignalTypeDOMSelector,
		Source:     "browser_analyzer",
		Key:        "selector",
		Value:      ".cf-turnstile",
		Confidence: 1,
	}

	data, err := json.Marshal(signal)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	const want = `{"type":"dom_selector","source":"browser_analyzer","key":"selector","value":".cf-turnstile","confidence":1}`
	if got := string(data); got != want {
		t.Errorf("json.Marshal() = %s, want %s", got, want)
	}

	var decoded Signal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded != signal {
		t.Errorf("JSON round trip = %#v, want %#v", decoded, signal)
	}
}
