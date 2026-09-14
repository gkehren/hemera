package scanner

import "fmt"

// ScanEventKind identifies the lifecycle phase reported by a ScanEvent.
type ScanEventKind uint8

const (
	// ScanEventStarted is emitted immediately before an analyzer runs.
	ScanEventStarted ScanEventKind = iota
	// ScanEventFinished is emitted after an analyzer outcome has been
	// classified. Status carries the canonical analyzer status.
	ScanEventFinished
	// ScanEventProgress carries a bounded live observation-counter snapshot
	// from an analyzer that owns an internal observation loop. It carries no
	// content, only aggregate counts.
	ScanEventProgress
)

// String returns the stable lowercase name of the event kind.
func (k ScanEventKind) String() string {
	switch k {
	case ScanEventStarted:
		return "started"
	case ScanEventFinished:
		return "finished"
	case ScanEventProgress:
		return "progress"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

// ObservationCounters is a presentation-safe aggregate snapshot of one
// analyzer's live observation volume. It never carries URLs, identifiers, or
// any other observed content.
type ObservationCounters struct {
	Requests  int
	Responses int
}

// ScanEvent reports one analyzer lifecycle transition or live counter update.
// Source matches the analyzer's Source() identity, Status is set when Kind is
// ScanEventFinished, and Counters is set when Kind is ScanEventProgress.
// Events carry presentation-safe state only: analyzer error details stay in
// AnalyzerResult.Err, where reporters decide what is safe to disclose, and
// never reach progress observers.
type ScanEvent struct {
	Source   string
	Kind     ScanEventKind
	Status   AnalyzerStatus
	Counters ObservationCounters
}

// ProgressFunc receives analyzer lifecycle events while a scan runs.
// Lifecycle events are invoked synchronously on the scanning goroutine;
// ScanEventProgress events may arrive concurrently from analyzer-owned
// observation goroutines. Implementors must tolerate concurrent delivery and
// must not block for long, mutate scanner state, or call back into the
// Scanner: an analyzer stalls while its progress callback runs.
type ProgressFunc func(ScanEvent)

// SetProgress attaches or replaces the scan progress observer. It must be
// called before Scan starts; Scanner does not support concurrent use.
func (s *Scanner) SetProgress(progress ProgressFunc) {
	s.progress = progress
}
