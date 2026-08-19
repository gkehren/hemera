package browser

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/pkg/model"
)

var (
	// ErrInvalidSignal identifies a browser observation that could not be
	// represented by the shared normalized signal contract.
	ErrInvalidSignal = errors.New("browser analyzer produced an invalid signal")
)

const (
	warningBrowserUnavailable = "browser observation was unavailable"
	warningBrowserIncomplete  = "browser observation was incomplete"
)

// Analyzer starts an isolated browser session and converts one bounded capture
// into normalized signals.
type Analyzer struct {
	client *Client
}

// NewAnalyzer validates the browser configuration and constructs a normalized
// observation adapter.
func NewAnalyzer(config Config) (*Analyzer, error) {
	client, err := New(config)
	if err != nil {
		return nil, err
	}
	return newAnalyzer(client), nil
}

func newAnalyzer(client *Client) *Analyzer {
	return &Analyzer{client: client}
}

// Source returns the stable identity used for browser observations.
func (*Analyzer) Source() string {
	return analysis.SourceBrowser
}

// Observe performs one sandboxed, bounded browser navigation and returns only
// normalized, minimized evidence. Browser-local failures may retain a partial
// capture for scanner failure-policy handling.
func (a *Analyzer) Observe(ctx context.Context, target analysis.Target) (analysis.Observation, error) {
	observation := analysis.Observation{Source: analysis.SourceBrowser}
	if a == nil || a.client == nil {
		observation.Warnings = []string{warningBrowserUnavailable}
		return observation, errors.New("browser client is unavailable")
	}

	result, observeErr := a.capture(ctx, target.URL)
	observation.Warnings = append([]string{}, result.Warnings...)
	signals, signalErr := normalizeCapture(result)
	observation.Signals = signals
	combinedErr := errors.Join(observeErr, signalErr)
	if combinedErr != nil {
		warning := warningBrowserUnavailable
		if len(observation.Signals) > 0 {
			warning = warningBrowserIncomplete
		}
		observation.Warnings = appendWarning(observation.Warnings, warning)
	}
	return observation, combinedErr
}

func (a *Analyzer) capture(ctx context.Context, rawURL string) (result CaptureResult, resultErr error) {
	session, err := a.client.Start(ctx)
	if err != nil {
		return CaptureResult{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, session.Close())
	}()

	recorder, err := session.BeginCapture(ctx)
	if err != nil {
		return CaptureResult{}, err
	}
	if err := session.Navigate(ctx, rawURL); err != nil {
		partial, finishErr := recorder.Finish(ctx)
		return partial, errors.Join(err, finishErr)
	}
	return recorder.Finish(ctx)
}

func normalizeCapture(result CaptureResult) ([]model.Signal, error) {
	finalURL := result.FinalURL
	signals := make([]model.Signal, 0,
		len(result.Requests)+len(result.Responses)+len(result.ScriptURLs)+
			len(result.IframeURLs)+len(result.Cookies)+1,
	)
	for _, request := range result.Requests {
		method := strings.ToUpper(strings.TrimSpace(request.Method))
		if method == "" || request.URL == "" {
			continue
		}
		signals = append(signals, model.Signal{
			Type: model.SignalTypeNetworkRequest, Source: analysis.SourceBrowser,
			Key: method, Value: request.URL, URL: finalURL, Confidence: 1,
		})
	}
	for _, response := range result.Responses {
		if response.Status <= 0 || response.URL == "" {
			continue
		}
		signals = append(signals, model.Signal{
			Type: model.SignalTypeNetworkResponse, Source: analysis.SourceBrowser,
			Key: "status", Value: strconv.FormatInt(response.Status, 10),
			URL: response.URL, Confidence: 1,
		})
	}
	if result.DOM != "" {
		signals = append(signals, model.Signal{
			Type: model.SignalTypePageContent, Source: analysis.SourceBrowser,
			Key: "dom", Value: result.DOM, URL: finalURL, Confidence: 1,
		})
	}
	for _, scriptURL := range result.ScriptURLs {
		if scriptURL == "" {
			continue
		}
		signals = append(signals, model.Signal{
			Type: model.SignalTypeScriptURL, Source: analysis.SourceBrowser,
			Key: "src", Value: scriptURL, URL: finalURL, Confidence: 1,
		})
	}
	for _, iframeURL := range result.IframeURLs {
		if iframeURL == "" {
			continue
		}
		signals = append(signals, model.Signal{
			Type: model.SignalTypeIframeURL, Source: analysis.SourceBrowser,
			Key: "src", Value: iframeURL, URL: finalURL, Confidence: 1,
		})
	}
	for _, cookie := range result.Cookies {
		if cookie.Name == "" || cookie.Domain == "" {
			continue
		}
		signals = append(signals, model.Signal{
			Type: model.SignalTypeCookie, Source: analysis.SourceBrowser,
			Key: cookie.Name, Value: cookie.Domain, URL: finalURL, Confidence: 1,
		})
	}

	sort.Slice(signals, func(i, j int) bool {
		left, right := signals[i], signals[j]
		leftRank, rightRank := browserSignalRank(left.Type), browserSignalRank(right.Type)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		leftFields := [...]string{left.Key, left.Value, left.URL}
		rightFields := [...]string{right.Key, right.Value, right.URL}
		for index := range leftFields {
			if leftFields[index] != rightFields[index] {
				return leftFields[index] < rightFields[index]
			}
		}
		return false
	})

	unique := signals[:0]
	for _, signal := range signals {
		if err := signal.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSignal, err)
		}
		if len(unique) > 0 && unique[len(unique)-1] == signal {
			continue
		}
		unique = append(unique, signal)
	}
	return unique, nil
}

func browserSignalRank(signalType model.SignalType) int {
	switch signalType {
	case model.SignalTypeNetworkRequest:
		return 0
	case model.SignalTypeNetworkResponse:
		return 1
	case model.SignalTypePageContent:
		return 2
	case model.SignalTypeScriptURL:
		return 3
	case model.SignalTypeIframeURL:
		return 4
	case model.SignalTypeCookie:
		return 5
	default:
		return 6
	}
}

func appendWarning(warnings []string, warning string) []string {
	for _, existing := range warnings {
		if existing == warning {
			return warnings
		}
	}
	return append(warnings, warning)
}
