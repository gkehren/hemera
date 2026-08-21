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
)

// String returns the stable lowercase name of the event kind.
func (k ScanEventKind) String() string {
	switch k {
	case ScanEventStarted:
		return "started"
	case ScanEventFinished:
		return "finished"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

// ScanEvent reports one analyzer lifecycle transition. Source matches the
// analyzer's Source() identity and Status is set when Kind is
// ScanEventFinished. Events carry presentation-safe state only: analyzer error
// details stay in AnalyzerResult.Err, where reporters decide what is safe to
// disclose, and never reach progress observers.
type ScanEvent struct {
	Source string
	Kind   ScanEventKind
	Status AnalyzerStatus
}

// ProgressFunc receives analyzer lifecycle events while a scan runs. It is
// invoked synchronously on the scanning goroutine and must not block for long,
// mutate scanner state, or call back into the Scanner.
type ProgressFunc func(ScanEvent)

// SetProgress attaches or replaces the scan progress observer. It must be
// called before Scan starts; Scanner does not support concurrent use.
func (s *Scanner) SetProgress(progress ProgressFunc) {
	s.progress = progress
}
