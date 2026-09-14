// Package model defines the shared data structures exchanged by Hemera's
// analyzers, detection rules, scoring engine, and reporters.
package model

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// SignalType identifies the kind of observable evidence carried by a Signal.
type SignalType string

const (
	SignalTypeResponseHeader     SignalType = "response_header"
	SignalTypeCookie             SignalType = "cookie"
	SignalTypeScriptURL          SignalType = "script_url"
	SignalTypeNetworkRequest     SignalType = "network_request"
	SignalTypeNetworkResponse    SignalType = "network_response"
	SignalTypeNetworkTransaction SignalType = "network_transaction"
	SignalTypeFormSubmission     SignalType = "form_submission"
	SignalTypeDOMSelector        SignalType = "dom_selector"
	SignalTypeIframeURL          SignalType = "iframe_url"
	SignalTypeJSGlobal           SignalType = "js_global"
	SignalTypeDNSRecord          SignalType = "dns_record"
	SignalTypeTLSProperty        SignalType = "tls_property"
	SignalTypeRedirect           SignalType = "redirect"
	SignalTypePageContent        SignalType = "page_content"
	SignalTypeResourceHost       SignalType = "resource_host"
)

var validSignalTypes = map[SignalType]struct{}{
	SignalTypeResponseHeader:     {},
	SignalTypeCookie:             {},
	SignalTypeScriptURL:          {},
	SignalTypeNetworkRequest:     {},
	SignalTypeNetworkResponse:    {},
	SignalTypeNetworkTransaction: {},
	SignalTypeFormSubmission:     {},
	SignalTypeDOMSelector:        {},
	SignalTypeIframeURL:          {},
	SignalTypeJSGlobal:           {},
	SignalTypeDNSRecord:          {},
	SignalTypeTLSProperty:        {},
	SignalTypeRedirect:           {},
	SignalTypePageContent:        {},
	SignalTypeResourceHost:       {},
}

var (
	ErrInvalidSignalType       = errors.New("invalid signal type")
	ErrMissingSignalSource     = errors.New("signal source is required")
	ErrMissingSignalKey        = errors.New("signal key is required")
	ErrInvalidSignalConfidence = errors.New("signal confidence must be between 0 and 1")
)

// Valid reports whether the type is part of Hemera's normalized signal model.
func (t SignalType) Valid() bool {
	_, ok := validSignalTypes[t]
	return ok
}

// Signal is a normalized observation produced by an analyzer. Confidence
// describes the analyzer's certainty in the observation, not the confidence of
// a product detection. URL is optional because not every signal is URL-scoped.
type Signal struct {
	Type       SignalType `json:"type"`
	Source     string     `json:"source"`
	Key        string     `json:"key"`
	Value      string     `json:"value"`
	URL        string     `json:"url,omitempty"`
	Confidence float64    `json:"confidence"`
}

// Validate checks the invariants shared by every normalized signal. Analyzer-
// specific constraints belong to the analyzer that creates the signal.
func (s Signal) Validate() error {
	if !s.Type.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidSignalType, s.Type)
	}
	if strings.TrimSpace(s.Source) == "" {
		return ErrMissingSignalSource
	}
	if strings.TrimSpace(s.Key) == "" {
		return ErrMissingSignalKey
	}
	if math.IsNaN(s.Confidence) || math.IsInf(s.Confidence, 0) || s.Confidence < 0 || s.Confidence > 1 {
		return fmt.Errorf("%w: %v", ErrInvalidSignalConfidence, s.Confidence)
	}

	return nil
}
