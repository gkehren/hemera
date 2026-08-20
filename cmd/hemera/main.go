package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gkehren/hemera/internal/browser"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/dnstls"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/report"
	"github.com/gkehren/hemera/internal/scanner"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "scan" {
		return runScan(context.Background(), args[1:], stdout, stderr, nil)
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
		engine, err = newScannerEngine(isDeep)
		if err != nil {
			fmt.Fprintf(stderr, "hemera: configure scanner: %v\n", err)
			return 1
		}
	}

	result, err := engine.Scan(ctx, flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "hemera: scan failed: %v\n", err)
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
		fmt.Fprintf(stderr, "hemera: write report: %v\n", err)
		return 1
	}
	return 0
}

func newScannerEngine(deep bool) (*scanner.Scanner, error) {
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
		RuleSet: ruleSet,
	})
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
