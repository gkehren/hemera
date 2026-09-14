package browser

import (
	"strconv"
	"testing"

	"github.com/gkehren/hemera/internal/analysis"
)

func TestBuildNetworkMetadataAggregatesTransactions(t *testing.T) {
	t.Parallel()
	result := CaptureResult{
		FinalURL: "https://example.test/",
		Requests: []CaptureRequest{
			{Method: "GET", URL: "https://example.test/"},
			{Method: "POST", URL: "https://api.example.test/submit"},
			{Method: "POST", URL: "https://api.example.test/submit"},
		},
		Responses: []CaptureResponse{{URL: "https://example.test/", Status: 200}},
		Transactions: []CaptureTransaction{
			{
				Method: "GET", URL: "https://example.test/", Status: 200, Protocol: "h2",
				WireBytes: 1200, Timing: CaptureTiming{QueueMs: 10, TTFBMs: 100, TotalMs: 150},
			},
			{
				Method: "POST", URL: "https://api.example.test/submit", Status: 403, Protocol: "h2",
				ConnectionReused: true, WireBytes: 300, Timing: CaptureTiming{QueueMs: 30, TTFBMs: 200, TotalMs: 250},
			},
			{
				Method: "POST", URL: "https://api.example.test/submit", Protocol: "http/1.1",
			},
		},
	}
	metadata := buildNetworkMetadata(result)

	if metadata.FinalURL != "https://example.test/" || metadata.RequestCount != 3 || metadata.ResponseCount != 1 {
		t.Errorf("counts = %q %d/%d, want example.test 3/1", metadata.FinalURL, metadata.RequestCount, metadata.ResponseCount)
	}
	if metadata.WireBytesTotal != 1500 {
		t.Errorf("WireBytesTotal = %d, want 1500", metadata.WireBytesTotal)
	}
	wantPOST := []string{"https://api.example.test/submit"}
	if len(metadata.POSTEndpoints) != 1 || metadata.POSTEndpoints[0] != wantPOST[0] {
		t.Errorf("POSTEndpoints = %#v, want %q", metadata.POSTEndpoints, wantPOST)
	}
	wantProtocols := []analysis.NetworkNameCount{
		{Name: "h2", Count: 2}, {Name: "http/1.1", Count: 1},
	}
	if len(metadata.Protocols) != len(wantProtocols) || metadata.Protocols[0] != wantProtocols[0] || metadata.Protocols[1] != wantProtocols[1] {
		t.Errorf("Protocols = %#v, want %#v", metadata.Protocols, wantProtocols)
	}
	wantStatusClasses := []analysis.NetworkNameCount{
		{Name: "2xx", Count: 1}, {Name: "4xx", Count: 1},
	}
	if len(metadata.StatusClasses) != len(wantStatusClasses) || metadata.StatusClasses[0] != wantStatusClasses[0] || metadata.StatusClasses[1] != wantStatusClasses[1] {
		t.Errorf("StatusClasses = %#v, want %#v", metadata.StatusClasses, wantStatusClasses)
	}
	wantHosts := []analysis.NetworkHostTraffic{
		{Host: "api.example.test", Requests: 2, ReusedRequests: 1},
		{Host: "example.test", Requests: 1},
	}
	if len(metadata.Hosts) != len(wantHosts) || metadata.Hosts[0] != wantHosts[0] || metadata.Hosts[1] != wantHosts[1] {
		t.Errorf("Hosts = %#v, want %#v", metadata.Hosts, wantHosts)
	}
	if metadata.QueueTiming != (analysis.NetworkTimingStats{P50Ms: 10, P95Ms: 30, MaxMs: 30}) {
		t.Errorf("QueueTiming = %#v, want p50 10 p95 30 max 30", metadata.QueueTiming)
	}
	if metadata.TTFBTiming != (analysis.NetworkTimingStats{P50Ms: 100, P95Ms: 200, MaxMs: 200}) {
		t.Errorf("TTFBTiming = %#v, want p50 100 p95 200 max 200", metadata.TTFBTiming)
	}
	if len(metadata.Transactions) != 3 || metadata.Transactions[1].Status != 403 || metadata.Transactions[1].QueueMs != 30 {
		t.Errorf("Transactions = %#v, want mapped transaction detail", metadata.Transactions)
	}
	if metadata.Truncated {
		t.Error("Truncated = true, want false for an uncapped capture")
	}
}

func TestBuildNetworkMetadataFlagsTruncation(t *testing.T) {
	t.Parallel()
	result := CaptureResult{
		Warnings: []string{warningTransactionLimit},
		Transactions: []CaptureTransaction{
			{Method: "POST", URL: "https://example.test/a", Status: 200},
		},
	}
	metadata := buildNetworkMetadata(result)
	if !metadata.Truncated {
		t.Error("Truncated = false, want true when the capture hit the transaction limit")
	}

	manyPOSTs := CaptureResult{}
	for index := 0; index <= maxCaptureItems; index++ {
		manyPOSTs.Transactions = append(manyPOSTs.Transactions, CaptureTransaction{
			Method: "POST", URL: "https://example.test/p" + strconv.Itoa(index),
			Status: 200,
		})
	}
	metadata = buildNetworkMetadata(manyPOSTs)
	if !metadata.Truncated {
		t.Error("Truncated = false, want true when POST endpoints exceed the cap")
	}
	if len(metadata.POSTEndpoints) != maxCaptureItems {
		t.Errorf("POSTEndpoints = %d, want %d", len(metadata.POSTEndpoints), maxCaptureItems)
	}
}

func TestBuildNetworkMetadataEmptyCapture(t *testing.T) {
	t.Parallel()
	metadata := buildNetworkMetadata(CaptureResult{})
	if metadata.QueueTiming != (analysis.NetworkTimingStats{}) || metadata.TTFBTiming != (analysis.NetworkTimingStats{}) {
		t.Errorf("timing stats = %#v/%#v, want zeroed stats for an empty capture", metadata.QueueTiming, metadata.TTFBTiming)
	}
	if len(metadata.Transactions) != 0 || len(metadata.Hosts) != 0 || metadata.WireBytesTotal != 0 {
		t.Errorf("metadata = %#v, want empty aggregation", metadata)
	}
}
