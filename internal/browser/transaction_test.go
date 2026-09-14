package browser

import (
	"math"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
)

func monotonicAt(seconds float64) *cdp.MonotonicTime {
	timestamp := cdp.MonotonicTime(time.Unix(0, int64(seconds*float64(time.Second))))
	return &timestamp
}

func TestRecordNetworkEventCorrelatesTransaction(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	recordNetworkEvent(collector, &network.EventRequestWillBeSent{
		RequestID: "req-1",
		Request:   &network.Request{Method: "POST", URL: "https://example.test/api?token=secret"},
		Type:      network.ResourceTypeFetch,
		Timestamp: monotonicAt(10),
	})
	recordNetworkEvent(collector, &network.EventResponseReceived{
		RequestID: "req-1",
		Type:      network.ResourceTypeFetch,
		Response: &network.Response{
			URL: "https://example.test/api?token=secret", Status: 403,
			MimeType: "application/json", Protocol: "h2", ConnectionReused: true,
			Timing: &network.ResourceTiming{
				RequestTime: 10.002,
				DNSStart:    0, DNSEnd: 5,
				ConnectStart: 5, ConnectEnd: 25,
				SslStart: 25, SslEnd: 40,
				ReceiveHeadersEnd: 80,
			},
		},
	})
	recordNetworkEvent(collector, &network.EventLoadingFinished{
		RequestID: "req-1", EncodedDataLength: 734, Timestamp: monotonicAt(10.15),
	})
	result := collector.snapshot("https://example.test/", "<html></html>", nil)

	if len(result.Requests) != 1 || result.Requests[0].Method != "POST" {
		t.Fatalf("requests = %#v, want one POST request", result.Requests)
	}
	if len(result.Responses) != 1 || result.Responses[0].Status != 403 {
		t.Fatalf("responses = %#v, want one 403 response", result.Responses)
	}
	want := []CaptureTransaction{{
		Method: "POST", URL: "https://example.test/api?redacted", Status: 403,
		MIMEType: "application/json", ResourceType: "Fetch", Protocol: "h2",
		ConnectionReused: true, WireBytes: 734,
		Timing: CaptureTiming{QueueMs: 2, DNSMs: 5, ConnectMs: 20, TLSMs: 15, TTFBMs: 80, TotalMs: 150},
	}}
	if len(result.Transactions) != 1 {
		t.Fatalf("transactions = %#v, want exactly one", result.Transactions)
	}
	if got := result.Transactions[0]; got != want[0] {
		t.Errorf("transaction = %#v, want %#v", got, want[0])
	}
}

func TestRecordNetworkEventRedirectSplitsTransactionHops(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	recordNetworkEvent(collector, &network.EventRequestWillBeSent{
		RequestID: "req-1",
		Request:   &network.Request{Method: "GET", URL: "https://example.test/a"},
		Timestamp: monotonicAt(1),
	})
	recordNetworkEvent(collector, &network.EventRequestWillBeSent{
		RequestID: "req-1",
		Request:   &network.Request{Method: "GET", URL: "https://example.test/b"},
		RedirectResponse: &network.Response{
			URL: "https://example.test/a", Status: 301, Protocol: "http/1.1",
			Timing: &network.ResourceTiming{RequestTime: 1.01, ReceiveHeadersEnd: 20},
		},
		Timestamp: monotonicAt(1.2),
	})
	recordNetworkEvent(collector, &network.EventResponseReceived{
		RequestID: "req-1",
		Response:  &network.Response{URL: "https://example.test/b", Status: 200, Protocol: "http/1.1"},
	})
	recordNetworkEvent(collector, &network.EventLoadingFinished{
		RequestID: "req-1", EncodedDataLength: 10, Timestamp: monotonicAt(1.5),
	})
	result := collector.snapshot("https://example.test/b", "", nil)

	want := []CaptureTransaction{
		{
			Method: "GET", URL: "https://example.test/a", Status: 301, Protocol: "http/1.1",
			Timing: CaptureTiming{QueueMs: 10, TTFBMs: 20, TotalMs: 200},
		},
		{
			Method: "GET", URL: "https://example.test/b", Status: 200, Protocol: "http/1.1",
			WireBytes: 10, Timing: CaptureTiming{TotalMs: 300},
		},
	}
	if len(result.Transactions) != len(want) {
		t.Fatalf("transactions = %#v, want %d hops", result.Transactions, len(want))
	}
	for index, transaction := range result.Transactions {
		if transaction != want[index] {
			t.Errorf("transactions[%d] = %#v, want %#v", index, transaction, want[index])
		}
	}
}

func TestRecordNetworkEventFailedRequestKeepsPartialTransaction(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	recordNetworkEvent(collector, &network.EventRequestWillBeSent{
		RequestID: "req-1",
		Request:   &network.Request{Method: "GET", URL: "https://example.test/slow"},
		Timestamp: monotonicAt(2),
	})
	recordNetworkEvent(collector, &network.EventLoadingFailed{
		RequestID: "req-1", Timestamp: monotonicAt(2.5),
	})
	recordNetworkEvent(collector, &network.EventLoadingFinished{
		RequestID: "req-1", EncodedDataLength: 99, Timestamp: monotonicAt(3),
	})
	result := collector.snapshot("https://example.test/", "", nil)

	want := []CaptureTransaction{{Method: "GET", URL: "https://example.test/slow"}}
	if len(result.Transactions) != 1 || result.Transactions[0] != want[0] {
		t.Errorf("transactions = %#v, want %#v without late patches", result.Transactions, want)
	}
}

func TestRecordNetworkEventTransactionCaptureLimit(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	for index := 0; index <= maxCaptureItems+5; index++ {
		recordNetworkEvent(collector, &network.EventRequestWillBeSent{
			RequestID: network.RequestID(strconv.Itoa(index)),
			Request:   &network.Request{Method: "GET", URL: "https://example.test/r" + strconv.Itoa(index)},
			Timestamp: monotonicAt(float64(index)),
		})
	}
	result := collector.snapshot("https://example.test/", "", nil)
	if len(result.Transactions) != maxCaptureItems {
		t.Errorf("transactions = %d, want %d", len(result.Transactions), maxCaptureItems)
	}
	if !slices.Contains(result.Warnings, warningTransactionLimit) {
		t.Errorf("warnings = %#v, want %q", result.Warnings, warningTransactionLimit)
	}
}

func TestBoundedDurationMs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input float64
		want  int64
	}{
		{"zero", 0, 0},
		{"negative", -0.5, 0},
		{"not a number", math.NaN(), 0},
		{"positive infinity", math.Inf(1), 0},
		{"millisecond", 0.001, 1},
		{"rounds half up", 0.0015, 2},
		{"seconds", 1.25, 1250},
		{"ceiling", 120, maxTimingMs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := boundedDurationMs(test.input); got != test.want {
				t.Errorf("boundedDurationMs(%v) = %d, want %d", test.input, got, test.want)
			}
		})
	}
}

func TestRecordNetworkEventNotifiesProgressOnRequestAndResponse(t *testing.T) {
	t.Parallel()
	collector := newCaptureCollector()
	var mu sync.Mutex
	var snapshots []ObservationCounters
	collector.progress = func(counters ObservationCounters) {
		mu.Lock()
		defer mu.Unlock()
		snapshots = append(snapshots, counters)
	}
	recordNetworkEvent(collector, &network.EventRequestWillBeSent{
		RequestID: "req-1",
		Request:   &network.Request{Method: "GET", URL: "https://example.test/"},
		Timestamp: monotonicAt(1),
	})
	recordNetworkEvent(collector, &network.EventResponseReceived{
		RequestID: "req-1",
		Response:  &network.Response{URL: "https://example.test/", Status: 200},
	})
	// Non-traffic events must not notify.
	recordNetworkEvent(collector, &network.EventLoadingFinished{
		RequestID: "req-1", EncodedDataLength: 10, Timestamp: monotonicAt(2),
	})

	mu.Lock()
	defer mu.Unlock()
	want := []ObservationCounters{
		{Requests: 1, Responses: 0},
		{Requests: 1, Responses: 1},
	}
	if len(snapshots) != len(want) {
		t.Fatalf("snapshots = %#v, want %#v", snapshots, want)
	}
	for index := range want {
		if snapshots[index] != want[index] {
			t.Errorf("snapshots[%d] = %#v, want %#v", index, snapshots[index], want[index])
		}
	}
}
