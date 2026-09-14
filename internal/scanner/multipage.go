package scanner

import (
	"context"
	"errors"
	"fmt"
)

// MaxPages is the hard ceiling on user-specified pages in one multi-page scan.
// A multi-page scan is an explicit list of bounded single-page scans, never a
// crawl: configuration can only lower the number of pages, never raise it.
const MaxPages = 10

// ErrPageLimit indicates that a multi-page request exceeded MaxPages.
var ErrPageLimit = errors.New("multi-page scan exceeds the page limit")

// PageResult pairs one requested page with its complete single-page scan
// outcome. Err is non-nil when the page could not be scanned; Result is then
// the zero value and must not be read.
type PageResult struct {
	URL    string
	Result Result
	Err    error
}

// MultiResult contains the ordered outcomes of one multi-page scan.
type MultiResult struct {
	Pages []PageResult
}

// FailedPages counts pages that produced no scan result.
func (m MultiResult) FailedPages() int {
	failed := 0
	for _, page := range m.Pages {
		if page.Err != nil {
			failed++
		}
	}
	return failed
}

// ScanPages runs one complete bounded scan per requested URL, strictly
// sequentially and in the requested order. Every page receives the full
// analyzer pipeline and its own resource budgets; a page failure never blocks
// the remaining pages. Cancellation stops the scan before the next page.
// The returned error is non-nil only for orchestration-level failures such as
// cancellation; per-page failures are reported in the page results.
func (s *Scanner) ScanPages(ctx context.Context, rawURLs []string) (MultiResult, error) {
	if len(rawURLs) == 0 {
		return MultiResult{}, fmt.Errorf("%w: at least one page is required", ErrInvalidConfig)
	}
	if len(rawURLs) > MaxPages {
		return MultiResult{}, fmt.Errorf("%w: %d pages requested, ceiling is %d", ErrPageLimit, len(rawURLs), MaxPages)
	}
	multi := MultiResult{Pages: make([]PageResult, 0, len(rawURLs))}
	for _, rawURL := range rawURLs {
		if err := ctx.Err(); err != nil {
			return multi, fmt.Errorf("multi-page scan canceled before page %q: %w", rawURL, err)
		}
		result, err := s.Scan(ctx, rawURL)
		multi.Pages = append(multi.Pages, PageResult{URL: rawURL, Result: result, Err: err})
	}
	return multi, nil
}
