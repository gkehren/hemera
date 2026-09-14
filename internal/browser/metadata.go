package browser

import (
	"math"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/gkehren/hemera/internal/analysis"
)

// buildNetworkMetadata derives bounded typed network diagnostics from one
// capture. It retains only aggregate counts, already-cleaned URLs, protocol
// labels, status classes, and integer millisecond durations. It never
// includes absolute timestamps, remote addresses, connection identifiers,
// headers, bodies, or POST data.
func buildNetworkMetadata(result CaptureResult) *analysis.NetworkMetadata {
	metadata := &analysis.NetworkMetadata{
		FinalURL:      result.FinalURL,
		RequestCount:  len(result.Requests),
		ResponseCount: len(result.Responses),
	}
	protocolCounts := make(map[string]int)
	statusClassCounts := make(map[string]int)
	hostTraffic := make(map[string]*analysis.NetworkHostTraffic)
	postEndpoints := make(map[string]struct{})
	var queueSamples, ttfbSamples []int64

	for _, transaction := range result.Transactions {
		if transaction.Protocol != "" {
			protocolCounts[transaction.Protocol]++
		}
		if class := networkStatusClass(transaction.Status); class != "" {
			statusClassCounts[class]++
		}
		if host := transactionHost(transaction.URL); host != "" {
			traffic := hostTraffic[host]
			if traffic == nil {
				traffic = &analysis.NetworkHostTraffic{Host: host}
				hostTraffic[host] = traffic
			}
			traffic.Requests++
			if transaction.ConnectionReused {
				traffic.ReusedRequests++
			}
		}
		if transaction.WireBytes > 0 {
			metadata.WireBytesTotal += transaction.WireBytes
		}
		if strings.EqualFold(transaction.Method, "POST") && transaction.URL != "" {
			if _, exists := postEndpoints[transaction.URL]; !exists {
				if len(postEndpoints) >= maxCaptureItems {
					metadata.Truncated = true
				} else {
					postEndpoints[transaction.URL] = struct{}{}
				}
			}
		}
		if transaction.Status > 0 {
			if transaction.Timing.QueueMs > 0 {
				queueSamples = append(queueSamples, transaction.Timing.QueueMs)
			}
			if transaction.Timing.TTFBMs > 0 {
				ttfbSamples = append(ttfbSamples, transaction.Timing.TTFBMs)
			}
		}
		metadata.Transactions = append(metadata.Transactions, analysis.NetworkTransaction{
			Method:           transaction.Method,
			URL:              transaction.URL,
			Status:           int(transaction.Status),
			Protocol:         transaction.Protocol,
			ConnectionReused: transaction.ConnectionReused,
			WireBytes:        transaction.WireBytes,
			QueueMs:          transaction.Timing.QueueMs,
			TTFBMs:           transaction.Timing.TTFBMs,
			TotalMs:          transaction.Timing.TotalMs,
		})
	}
	if slices.Contains(result.Warnings, warningTransactionLimit) {
		metadata.Truncated = true
	}

	metadata.POSTEndpoints = sortedSet(postEndpoints)
	metadata.Protocols = sortedNameCounts(protocolCounts)
	metadata.StatusClasses = sortedNameCounts(statusClassCounts)
	metadata.Hosts = sortedHostTraffic(hostTraffic)
	metadata.QueueTiming = durationStats(queueSamples)
	metadata.TTFBTiming = durationStats(ttfbSamples)
	return metadata
}

// networkStatusClass maps a response status to its bounded "Nxx" class and
// returns empty for statuses outside the 100-599 range.
func networkStatusClass(status int64) string {
	if status < 100 || status > 599 {
		return ""
	}
	return strconv.FormatInt(status/100, 10) + "xx"
}

// transactionHost returns the host of an already-cleaned capture URL. It never
// returns userinfo because cleanURL removes it.
func transactionHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func sortedSet(values map[string]struct{}) []string {
	sorted := make([]string, 0, len(values))
	for value := range values {
		sorted = append(sorted, value)
	}
	sort.Strings(sorted)
	return sorted
}

func sortedNameCounts(counts map[string]int) []analysis.NetworkNameCount {
	sorted := make([]analysis.NetworkNameCount, 0, len(counts))
	for name, count := range counts {
		sorted = append(sorted, analysis.NetworkNameCount{Name: name, Count: count})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	return sorted
}

func sortedHostTraffic(traffic map[string]*analysis.NetworkHostTraffic) []analysis.NetworkHostTraffic {
	sorted := make([]analysis.NetworkHostTraffic, 0, len(traffic))
	for _, entry := range traffic {
		sorted = append(sorted, *entry)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Host < sorted[j].Host })
	return sorted
}

// durationStats summarizes positive duration samples with nearest-rank
// percentiles. Samples with no observed duration produce zeroed statistics.
func durationStats(samples []int64) analysis.NetworkTimingStats {
	if len(samples) == 0 {
		return analysis.NetworkTimingStats{}
	}
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	return analysis.NetworkTimingStats{
		P50Ms: nearestRankPercentile(sorted, 0.50),
		P95Ms: nearestRankPercentile(sorted, 0.95),
		MaxMs: sorted[len(sorted)-1],
	}
}

func nearestRankPercentile(sorted []int64, percentile float64) int64 {
	rank := int(math.Ceil(percentile * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}
