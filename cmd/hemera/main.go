package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/x/term"
	"github.com/gkehren/hemera/internal/browser"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/dnstls"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/report"
	"github.com/gkehren/hemera/internal/safeoutput"
	"github.com/gkehren/hemera/internal/scanner"
	"github.com/gkehren/hemera/internal/tui"
)

var version = "dev"

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
		fmt.Fprintf(stdout, "hemera %s\n", version)
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
  hemera scan [--format text|json] [--deep] [--mode default|deep] <url>
  hemera [--help] [--version]

Run without arguments in a terminal to start the interactive scan wizard.

Options:
  -h, --help  Show this help message
  --version   Print the Hemera version`)
}

type scanRunner interface {
	Scan(context.Context, string) (scanner.Result, error)
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer, engine scanRunner) int {
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
		fmt.Fprintln(stderr, "hemera: scan requires exactly one URL")
		printScanUsage(stderr)
		return 2
	}

	if engine == nil {
		isDeep := *deep || *mode == "deep"
		var err error
		engine, err = newScannerEngine(isDeep, nil)
		if err != nil {
			fmt.Fprintf(stderr, "hemera: configure scanner: %s\n", safeoutput.SanitizeDiagnostic(err))
			return 1
		}
	}

	result, err := engine.Scan(ctx, flags.Arg(0))
	// The application context is authoritative even if cancellation races with
	// a scanner result. Never render a concurrent success or classify a
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
	scanReport := report.Build(version, result)
	if *format == "json" {
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

func newScannerEngine(deep bool, progress scanner.ProgressFunc) (*scanner.Scanner, error) {
	httpConfig := httpanalyzer.DefaultConfig()
	dnsConfig := dnstls.DefaultConfig()
	browserConfig := browser.DefaultConfig()
	if deep {
		browserConfig = browser.DeepConfig()
	}
	analyzer, err := httpanalyzer.New(httpConfig)
	if err != nil {
		return nil, fmt.Errorf("configure HTTP analyzer: %w", err)
	}
	dnsTLSAnalyzer, err := dnstls.New(dnsConfig)
	if err != nil {
		return nil, fmt.Errorf("configure DNS/TLS analyzer: %w", err)
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

// runInteractive drives the terminal experience: wizard, live progress view,
// styled summary, and the standard text report. It is only reached when both
// stdin and stdout are terminals.
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
	return runInteractiveScan(ctx, opts, stdout, stderr, nil)
}

// runInteractiveScan executes the wizard-selected scan while rendering the
// live progress view, then prints the styled report.
func runInteractiveScan(ctx context.Context, opts tui.Options, stdout, stderr io.Writer, engine *scanner.Scanner) int {
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The buffer comfortably exceeds the two events per analyzer that a scan
	// emits, and sends are additionally guarded by scanCtx so a vanished view
	// can never block the scan from finishing and unwinding.
	msgs := make(chan tui.Msg, 32)
	sendMsg := func(msg tui.Msg) {
		select {
		case msgs <- msg:
		case <-scanCtx.Done():
		}
	}
	if engine == nil {
		var err error
		engine, err = newScannerEngine(opts.Deep, func(event scanner.ScanEvent) {
			sendMsg(tui.Msg{Event: event})
		})
		if err != nil {
			fmt.Fprintf(stderr, "hemera: configure scanner: %s\n", safeoutput.SanitizeDiagnostic(err))
			return 1
		}
	} else {
		engine.SetProgress(func(event scanner.ScanEvent) {
			sendMsg(tui.Msg{Event: event})
		})
	}

	// Detach the observer once the scan joined so a reused Scanner can never
	// emit into the closed channel (a send on a closed channel would panic).
	defer engine.SetProgress(nil)

	// scanDone is independent of the UI channel: runInteractiveScan must not
	// return while the scan goroutine is alive because os.Exit would skip its
	// deferred cleanup, notably closing the sandboxed browser session.
	scanDone := make(chan tui.Outcome, 1)
	go func() {
		result, scanErr := engine.Scan(scanCtx, opts.URL)
		sendMsg(tui.Msg{Final: true, Outcome: tui.Outcome{Result: result, Err: scanErr}})
		close(msgs)
		scanDone <- tui.Outcome{Result: result, Err: scanErr}
	}()

	// Data-flow separation: the scan goroutine uses the exact user target;
	// only the presentation copy handed to the view is minimized.
	displayTarget := safeoutput.DisplayURL(opts.URL)
	runErr := runProgressView(scanCtx, stdout, engine.Sources(), displayTarget, msgs)
	cancel()
	outcome := <-scanDone

	// A non-nil view error means the progress view exited before the scan
	// outcome was delivered, so there is no report to render. The view-canceled
	// sentinel is a deliberate UI cancellation; inherited application-context
	// cancellation retains the fatal runtime exit classification.
	if runErr != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, "hemera: canceled")
			return 1
		}
		if errors.Is(runErr, tui.ErrViewCanceled) {
			fmt.Fprintln(stderr, "hemera: canceled")
			return 0
		}
		if errors.Is(runErr, context.Canceled) {
			fmt.Fprintln(stderr, "hemera: canceled")
			return 1
		}
		fmt.Fprintf(stderr, "hemera: %s\n", safeoutput.SanitizeDiagnostic(runErr))
		return 1
	}

	if outcome.Err != nil {
		if ctx.Err() != nil || errors.Is(outcome.Err, context.Canceled) {
			fmt.Fprintln(stderr, "hemera: canceled")
			return 1
		}
		fmt.Fprintf(stderr, "hemera: scan failed: %s\n", safeoutput.SanitizeDiagnostic(outcome.Err))
		if errors.Is(outcome.Err, httpanalyzer.ErrInitialTarget) {
			return 2
		}
		return 1
	}

	scanReport := report.Build(version, outcome.Result)
	// Separate the report from the progress view's final frame so the banner
	// background does not visually overlap it.
	fmt.Fprintln(stdout)
	if err := report.WriteStyled(stdout, scanReport); err != nil {
		fmt.Fprintf(stderr, "hemera: write report: %s\n", safeoutput.SanitizeDiagnostic(err))
		return 1
	}
	return 0
}

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  hemera scan [--format text|json] [--deep] [--mode default|deep] <url>

Options:
  --deep      Enable deep scan with maximal observation budgets and timeouts
  --format    Report format: text (default) or json
  --mode      Scan mode: default or deep
  -h, --help  Show this help message`)
}
