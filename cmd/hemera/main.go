package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/charmbracelet/x/term"
	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/browser"
	"github.com/gkehren/hemera/internal/buildversion"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/dnstls"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/report"
	"github.com/gkehren/hemera/internal/safeoutput"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/tui"
)

// version is intentionally left as a string variable so official release
// builds can override it with -ldflags "-X main.version=<version>".
var version string

// toolVersion is resolved once so every user-facing provenance field uses the
// same build identity.
var toolVersion = buildversion.Resolve(version)

const chromiumPathEnvironment = "HEMERA_CHROMIUM_PATH"

type environmentLookup func(string) string

func main() {
	os.Exit(runMain(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

type applicationRunner func(context.Context, []string, io.Writer, io.Writer) int

// runMain owns process-signal cancellation and returns only after run and all
// of its deferred analyzer cleanup have completed. main is the sole os.Exit
// caller, so no signal callback can bypass stack unwinding.
func runMain(parent context.Context, args []string, stdout, stderr io.Writer) int {
	return runMainWithRunner(parent, args, stdout, stderr, run)
}

// runMainWithRunner keeps signal ownership testable without delivering signals
// to the main test process.
func runMainWithRunner(parent context.Context, args []string, stdout, stderr io.Writer, runner applicationRunner) int {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runner(ctx, args, stdout, stderr)
}

// stdinIsTTY and stdoutIsTTY are overridable in tests.
var (
	stdinIsTTY  = func() bool { return term.IsTerminal(os.Stdin.Fd()) }
	stdoutIsTTY = func() bool { return term.IsTerminal(os.Stdout.Fd()) }
)

// runWizard and runProgressView are overridable test seams for the
// interactive terminal experience.
var (
	runWizard       = tui.RunWizard
	runProgressView = tui.RunProgress
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "scan" {
		return runScan(ctx, args[1:], stdout, stderr, nil)
	}

	if len(args) == 0 && stdinIsTTY() && stdoutIsTTY() {
		return runInteractive(ctx, stdout, stderr)
	}

	flags := flag.NewFlagSet("hemera", flag.ContinueOnError)
	flags.SetOutput(stderr)

	showVersion := flags.Bool("version", false, "print the Hemera version")
	flags.Usage = func() {
		printUsage(stderr)
	}

	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			printUsage(stdout)
			return 0
		}
	}

	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "hemera %s\n", toolVersion)
		return 0
	}

	// Stderr classification: every analyzer-, scanner-, report-, wizard-,
	// and view-derived error renders through safeoutput.SanitizeDiagnostic.
	// The remaining dynamic writes echo command-line arguments with %q,
	// which escapes control characters by construction; everything else is
	// static usage text. Raw errors cannot bypass the sanitizer here.
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "hemera: unexpected argument %q\n\n", flags.Arg(0))
		printUsage(stderr)
		return 2
	}

	printUsage(stdout)
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Hemera observes public web signals to identify protections with explainable evidence.

Usage:
  hemera scan [--format text|json] [--deep] [--mode default|deep]
              [--pages urls] [--pages-file file] [--forms] <url>
  hemera [--help] [--version]

Run without arguments in a terminal to start the interactive scan wizard.

Options:
  -h, --help  Show this help message
  --version   Print the Hemera version`)
}

type scanRunner interface {
	Scan(context.Context, string) (scanner.Result, error)
	ScanPages(context.Context, []string) (scanner.MultiResult, error)
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer, engine scanRunner) int {
	return runScanWithEnvironment(ctx, args, stdout, stderr, engine, os.Getenv)
}

func runScanWithEnvironment(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	engine scanRunner,
	getenv environmentLookup,
) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			printScanUsage(stdout)
			return 0
		}
	}
	flags := flag.NewFlagSet("hemera scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "report format: text or json")
	deep := flags.Bool("deep", false, "run deep scan with maximal observation budgets and timeouts")
	mode := flags.String("mode", "", "scan mode: default or deep")
	pages := flags.String("pages", "", "comma-separated additional http(s) page URLs to scan after the target")
	pagesFile := flags.String("pages-file", "", "file with one additional http(s) page URL per line")
	forms := flags.Bool("forms", false, "submit one eligible same-origin form per page with benign synthetic data (opt-in)")
	flags.Usage = func() { printScanUsage(stderr) }
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "hemera: unsupported report format %q\n", *format)
		printScanUsage(stderr)
		return 2
	}
	if *mode != "" && *mode != "default" && *mode != "deep" {
		fmt.Fprintf(stderr, "hemera: unsupported scan mode %q\n", *mode)
		printScanUsage(stderr)
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "hemera: scan requires exactly one target URL")
		printScanUsage(stderr)
		return 2
	}

	extraPages, errCode := collectExtraPages(*pages, *pagesFile, stderr)
	if errCode != 0 {
		printScanUsage(stderr)
		return errCode
	}

	if engine == nil {
		isDeep := *deep || *mode == "deep"
		var err error
		engine, err = newScannerEngineWithEnvironment(isDeep, *forms, nil, getenv)
		if err != nil {
			fmt.Fprintf(stderr, "hemera: configure scanner: %s\n", safeoutput.SanitizeDiagnostic(err))
			return 1
		}
	}

	if len(extraPages) == 0 {
		return runSinglePageScan(ctx, engine, flags.Arg(0), *format, stdout, stderr)
	}
	return runMultiPageScan(ctx, engine, append([]string{flags.Arg(0)}, extraPages...), *format, stdout, stderr)
}

// collectExtraPages merges --pages and --pages-file into one bounded page
// list. It enforces the MaxPages ceiling for the whole target list and never
// echoes raw file or URL content back to the terminal.
func collectExtraPages(pages, pagesFile string, stderr io.Writer) ([]string, int) {
	var extra []string
	for _, rawURL := range strings.Split(pages, ",") {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL != "" {
			extra = append(extra, rawURL)
		}
	}
	if pagesFile != "" {
		content, err := os.ReadFile(pagesFile)
		if err != nil {
			fmt.Fprintf(stderr, "hemera: read pages file: %s\n", safeoutput.SanitizeDiagnostic(err))
			return nil, 2
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			extra = append(extra, line)
		}
	}
	// The positional target adds one page on top of the extras.
	if 1+len(extra) > scanner.MaxPages {
		fmt.Fprintf(stderr, "hemera: %d pages requested, the multi-page ceiling is %d\n",
			1+len(extra), scanner.MaxPages)
		return nil, 2
	}
	return extra, 0
}

func runSinglePageScan(ctx context.Context, engine scanRunner, rawURL, format string, stdout, stderr io.Writer) int {
	result, err := engine.Scan(ctx, rawURL)
	// The application context is authoritative even if cancellation races
	// with a scanner result. Never render a concurrent success or classify a
	// concurrent target error as anything other than fatal cancellation.
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "hemera: scan canceled")
		return 1
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "hemera: scan canceled")
			return 1
		}
		fmt.Fprintf(stderr, "hemera: scan failed: %s\n", safeoutput.SanitizeDiagnostic(err))
		if errors.Is(err, httpanalyzer.ErrInitialTarget) {
			return 2
		}
		return 1
	}
	return writeScanReport(report.Build(toolVersion, result), format, stdout, stderr)
}

// runMultiPageScan scans every requested page sequentially and renders one
// aggregated report. Page-level failures never abort the remaining pages; the
// scan only fails as a whole when every page failed.
func runMultiPageScan(ctx context.Context, engine scanRunner, rawURLs []string, format string, stdout, stderr io.Writer) int {
	multi, err := engine.ScanPages(ctx, rawURLs)
	// The application context dominates concurrent page outcomes for the
	// same reason as the single-page path.
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "hemera: scan canceled")
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "hemera: scan failed: %s\n", safeoutput.SanitizeDiagnostic(err))
		if errors.Is(err, scanner.ErrPageLimit) {
			return 2
		}
		return 1
	}
	for index, page := range multi.Pages {
		if page.Err == nil {
			continue
		}
		fmt.Fprintf(stderr, "hemera: page %d (%s) failed: %s\n",
			index+1, safeoutput.DisplayURL(page.URL),
			safeoutput.SanitizeDiagnostic(page.Err))
	}
	if multi.FailedPages() == len(multi.Pages) {
		return 1
	}
	return writeScanReport(report.BuildPages(toolVersion, multi.Pages), format, stdout, stderr)
}

func writeScanReport(scanReport report.Report, format string, stdout, stderr io.Writer) int {
	var err error
	if format == "json" {
		err = report.WriteJSON(stdout, scanReport)
	} else {
		err = report.WriteText(stdout, scanReport)
	}
	if err != nil {
		fmt.Fprintf(stderr, "hemera: write report: %s\n", safeoutput.SanitizeDiagnostic(err))
		return 1
	}
	return 0
}

func newScannerEngine(deep, forms bool, progress scanner.ProgressFunc) (*scanner.Scanner, error) {
	return newScannerEngineWithEnvironment(deep, forms, progress, os.Getenv)
}

func newScannerEngineWithEnvironment(
	deep, forms bool,
	progress scanner.ProgressFunc,
	getenv environmentLookup,
) (*scanner.Scanner, error) {
	httpConfig := httpanalyzer.DefaultConfig()
	dnsConfig := dnstls.DefaultConfig()
	browserConfig := browserConfigFromEnvironment(deep, getenv)
	if forms {
		browserConfig.Forms = true
	}
	analyzer, err := httpanalyzer.New(httpConfig)
	if err != nil {
		return nil, fmt.Errorf("configure HTTP analyzer: %w", err)
	}
	dnsTLSAnalyzer, err := dnstls.New(dnsConfig)
	if err != nil {
		return nil, fmt.Errorf("configure DNS/TLS analyzer: %w", err)
	}
	if progress != nil {
		// Live counters are aggregate integers only; they never carry URLs
		// or observed content. The browser invokes this on CDP event
		// goroutines, so the observer must not block.
		browserConfig.ObservationProgress = func(counters browser.ObservationCounters) {
			progress(scanner.ScanEvent{
				Source:   analysis.SourceBrowser,
				Kind:     scanner.ScanEventProgress,
				Counters: scanner.ObservationCounters(counters),
			})
		}
	}
	browserAnalyzer, err := browser.NewAnalyzer(browserConfig)
	if err != nil {
		return nil, fmt.Errorf("configure browser analyzer: %w", err)
	}
	ruleSet, err := detectors.Load()
	if err != nil {
		return nil, fmt.Errorf("load detector rules: %w", err)
	}
	return scanner.New(scanner.Config{
		Analyzers: []scanner.AnalyzerConfig{
			{Analyzer: analyzer, FailurePolicy: scanner.FailurePolicyAbort},
			{Analyzer: dnsTLSAnalyzer, FailurePolicy: scanner.FailurePolicyContinue},
			{Analyzer: browserAnalyzer, FailurePolicy: scanner.FailurePolicyContinue},
		},
		RuleSet:  ruleSet,
		Progress: progress,
	})
}

func browserConfigFromEnvironment(deep bool, getenv environmentLookup) browser.Config {
	config := browser.DefaultConfig()
	if deep {
		config = browser.DeepConfig()
	}
	if path := getenv(chromiumPathEnvironment); path != "" {
		config.ExecutablePath = path
	}
	return config
}

// runInteractive drives the terminal experience: wizard, live progress view,
// and one styled report. It is only reached when both stdin and stdout are
// terminals. Wizard-selected additional pages run one at a time, each with
// its own progress view, and finish with a single aggregated multi-page
// report including the cross-page summary.
func runInteractive(ctx context.Context, stdout, stderr io.Writer) int {
	opts, err := runWizard(ctx)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "hemera: canceled")
			return 1
		}
		if errors.Is(err, tui.ErrAborted) {
			fmt.Fprintln(stderr, "hemera: canceled")
			return 0
		}
		fmt.Fprintf(stderr, "hemera: %s\n", safeoutput.SanitizeDiagnostic(err))
		return 1
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "hemera: canceled")
		return 1
	}
	targets := append([]string{opts.URL}, opts.Pages...)
	if len(targets) == 1 {
		return runInteractiveScan(ctx, tui.Options{URL: targets[0], Deep: opts.Deep, Forms: opts.Forms}, stdout, stderr, nil)
	}
	return runInteractiveMultiScan(ctx, opts, targets, stdout, stderr, nil)
}

// runInteractiveScan executes one wizard-selected page while rendering the
// live progress view, then prints the styled report.
func runInteractiveScan(ctx context.Context, opts tui.Options, stdout, stderr io.Writer, engine *scanner.Scanner) int {
	if engine == nil {
		var err error
		engine, err = newScannerEngine(opts.Deep, opts.Forms, nil)
		if err != nil {
			fmt.Fprintf(stderr, "hemera: configure scanner: %s\n", safeoutput.SanitizeDiagnostic(err))
			return 1
		}
	}
	outcome := runInteractivePage(ctx, engine, opts.URL, "", stdout)
	if outcome.viewErr != nil {
		fmt.Fprintf(stderr, "hemera: %s\n", safeoutput.SanitizeDiagnostic(outcome.viewErr))
		return 1
	}
	if outcome.appCanceled {
		fmt.Fprintln(stderr, "hemera: canceled")
		return 1
	}
	if outcome.canceled {
		fmt.Fprintln(stderr, "hemera: canceled")
		return 0
	}
	if outcome.err != nil {
		fmt.Fprintf(stderr, "hemera: scan failed: %s\n", safeoutput.SanitizeDiagnostic(outcome.err))
		if errors.Is(outcome.err, httpanalyzer.ErrInitialTarget) {
			return 2
		}
		return 1
	}
	fmt.Fprintln(stdout)
	if err := report.WriteStyled(stdout, report.Build(toolVersion, outcome.result)); err != nil {
		fmt.Fprintf(stderr, "hemera: write report: %s\n", safeoutput.SanitizeDiagnostic(err))
		return 1
	}
	return 0
}

// interactivePageOutcome carries the joined outcome of one interactive page.
// canceled marks a deliberate view-level user cancellation; appCanceled marks
// inherited application-context cancellation, which keeps the fatal runtime
// exit classification.
type interactivePageOutcome struct {
	result      scanner.Result
	err         error
	canceled    bool
	appCanceled bool
	viewErr     error
}

// runInteractivePage scans one page while rendering its live progress view,
// then joins the scan goroutine. It never renders a report. The pageLabel is
// an empty string for single-page scans. The msgs channel is closed only
// after the scan goroutine has joined, so no sender can race the close: all
// scanner events stop before Scan returns, and the Final message is sent by
// the scan goroutine itself.
func runInteractivePage(ctx context.Context, engine *scanner.Scanner, target, pageLabel string, stdout io.Writer) interactivePageOutcome {
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The buffer comfortably exceeds the lifecycle events of a scan, and
	// sends are additionally guarded by scanCtx so a vanished view can never
	// block the scan from finishing and unwinding. Live counter events share
	// this channel and can be more numerous; the view drains it fast enough
	// because each update is a cheap model mutation.
	msgs := make(chan tui.Msg, 32)
	sendMsg := func(msg tui.Msg) {
		select {
		case msgs <- msg:
		case <-scanCtx.Done():
		}
	}
	engine.SetProgress(func(event scanner.ScanEvent) {
		sendMsg(tui.Msg{Event: event})
	})

	// scanDone is independent of the UI channel: this function must not
	// return while the scan goroutine is alive because os.Exit would skip its
	// deferred cleanup, notably closing the sandboxed browser session.
	scanDone := make(chan tui.Outcome, 1)
	go func() {
		result, scanErr := engine.Scan(scanCtx, target)
		sendMsg(tui.Msg{Final: true, Outcome: tui.Outcome{Result: result, Err: scanErr}})
		scanDone <- tui.Outcome{Result: result, Err: scanErr}
	}()

	// Data-flow separation: the scan goroutine uses the exact user target;
	// only the presentation copy handed to the view is minimized.
	displayTarget := safeoutput.DisplayURL(target)
	runErr := runProgressView(scanCtx, stdout, engine.Sources(), displayTarget, pageLabel, msgs)
	cancel()
	outcome := <-scanDone
	engine.SetProgress(nil)
	close(msgs)

	// A non-nil view error means the progress view exited before the scan
	// outcome was delivered, so there is no report to render. The
	// view-canceled sentinel is a deliberate UI cancellation; inherited
	// application-context cancellation retains the fatal runtime exit
	// classification.
	if runErr != nil {
		if ctx.Err() != nil {
			return interactivePageOutcome{result: outcome.Result, err: outcome.Err, appCanceled: true}
		}
		if errors.Is(runErr, tui.ErrViewCanceled) {
			return interactivePageOutcome{result: outcome.Result, err: outcome.Err, canceled: true}
		}
		if errors.Is(runErr, context.Canceled) {
			return interactivePageOutcome{result: outcome.Result, err: outcome.Err, appCanceled: true}
		}
		return interactivePageOutcome{result: outcome.Result, err: outcome.Err, viewErr: runErr}
	}
	if outcome.Err != nil {
		if ctx.Err() != nil || errors.Is(outcome.Err, context.Canceled) {
			return interactivePageOutcome{result: outcome.Result, err: outcome.Err, appCanceled: true}
		}
	}
	return interactivePageOutcome{result: outcome.Result, err: outcome.Err}
}

// runInteractiveMultiScan scans every wizard-selected page sequentially with
// one engine and one live progress view per page, then renders a single
// aggregated multi-page report with the cross-page summary. A page failure
// never blocks the remaining pages; a deliberate view cancellation keeps the
// completed pages' report and exits 0, while inherited application
// cancellation keeps it as well but retains the fatal exit classification.
// A nil engine is constructed from the wizard options.
func runInteractiveMultiScan(ctx context.Context, opts tui.Options, targets []string, stdout, stderr io.Writer, engine *scanner.Scanner) int {
	if engine == nil {
		var err error
		engine, err = newScannerEngine(opts.Deep, opts.Forms, nil)
		if err != nil {
			fmt.Fprintf(stderr, "hemera: configure scanner: %s\n", safeoutput.SanitizeDiagnostic(err))
			return 1
		}
	}
	pages := make([]scanner.PageResult, 0, len(targets))
	canceled := false
	appCanceled := false
	for index, target := range targets {
		pageLabel := fmt.Sprintf("Page %d of %d", index+1, len(targets))
		outcome := runInteractivePage(ctx, engine, target, pageLabel, stdout)
		if outcome.viewErr != nil {
			fmt.Fprintf(stderr, "hemera: %s\n", safeoutput.SanitizeDiagnostic(outcome.viewErr))
			return 1
		}
		if outcome.appCanceled {
			appCanceled = true
			break
		}
		if outcome.canceled {
			canceled = true
			break
		}
		if outcome.err != nil {
			fmt.Fprintf(stderr, "hemera: page %d (%s) failed: %s\n",
				index+1, safeoutput.DisplayURL(target), safeoutput.SanitizeDiagnostic(outcome.err))
		}
		pages = append(pages, scanner.PageResult{URL: target, Result: outcome.result, Err: outcome.err})
	}

	// Separate the aggregated report from the last progress view's final
	// frame so the banner background does not visually overlap it.
	fmt.Fprintln(stdout)
	scanReport := report.BuildPages(version, pages)
	if err := report.WriteStyled(stdout, scanReport); err != nil {
		fmt.Fprintf(stderr, "hemera: write report: %s\n", safeoutput.SanitizeDiagnostic(err))
		return 1
	}
	if appCanceled {
		fmt.Fprintln(stderr, "hemera: canceled")
		return 1
	}
	if canceled {
		fmt.Fprintln(stderr, "hemera: canceled")
		return 0
	}
	failed := 0
	for _, page := range pages {
		if page.Err != nil {
			failed++
		}
	}
	if failed == len(pages) {
		return 1
	}
	return 0
}

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  hemera scan [--format text|json] [--deep] [--mode default|deep]
              [--pages urls] [--pages-file file] [--forms] <url>

Options:
  --deep        Enable deep scan with maximal observation budgets and timeouts
  --format      Report format: text (default) or json
  --mode        Scan mode: default or deep
  --pages       Comma-separated additional page URLs scanned after the target
                (bounded list of at most 10 pages total, no crawling)
  --pages-file  File with one additional page URL per line; empty lines and
                #-comments are ignored
  --forms       Submit one eligible same-origin form per page with fixed
                benign synthetic data; never credential or upload forms
  -h, --help    Show this help message`)
}
