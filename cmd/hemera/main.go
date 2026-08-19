package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/pkg/model"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "scan" {
		analyzer, err := httpanalyzer.New(httpanalyzer.DefaultConfig())
		if err != nil {
			fmt.Fprintf(stderr, "hemera: configure HTTP analyzer: %v\n", err)
			return 1
		}
		return runScan(context.Background(), args[1:], stdout, stderr, analyzer)
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
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printUsage(stdout)
		return 0
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
  hemera scan <url>
  hemera [--help] [--version]

Options:
  -h, --help  Show this help message
  --version   Print the Hemera version

The scan output is a temporary, unstable diagnostic format.`)
}

type scanner interface {
	Analyze(context.Context, string) (httpanalyzer.Result, error)
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer, analyzer scanner) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "hemera: scan requires exactly one URL")
		fmt.Fprintln(stderr, "usage: hemera scan <url>")
		return 2
	}
	result, err := analyzer.Analyze(ctx, args[0])
	if err != nil {
		fmt.Fprintf(stderr, "hemera: scan failed: %v\n", err)
		if errors.Is(err, httpanalyzer.ErrInitialTarget) {
			return 2
		}
		return 1
	}
	printScanResult(stdout, result)
	return 0
}

func printScanResult(w io.Writer, result httpanalyzer.Result) {
	fmt.Fprintln(w, "Hemera HTTP scan diagnostic (unstable format)")
	fmt.Fprintf(w, "Requested URL: %s\n", result.RequestedURL)
	fmt.Fprintf(w, "Final URL: %s\n", result.FinalURL)
	fmt.Fprintf(w, "Status: %d\n", result.StatusCode)
	fmt.Fprintf(w, "Body truncated: %t\n", result.BodyTruncated)
	fmt.Fprintln(w, "Redirects:")
	if len(result.Redirects) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, redirect := range result.Redirects {
		fmt.Fprintf(w, "  %d %s -> %s\n", redirect.Status, redirect.From, redirect.To)
	}
	fmt.Fprintln(w, "Warnings:")
	if len(result.Warnings) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(w, "  - %s\n", warning)
	}
	fmt.Fprintln(w, "Signals:")
	for _, signal := range result.Signals {
		fmt.Fprintf(w, "  - %s %s", signal.Type, signal.Key)
		switch signal.Type {
		case model.SignalTypeScriptURL, model.SignalTypeIframeURL, model.SignalTypeResourceHost,
			model.SignalTypeRedirect, model.SignalTypeNetworkResponse:
			fmt.Fprintf(w, ": %s", signal.Value)
		case model.SignalTypePageContent:
			fmt.Fprint(w, ": [content omitted]")
		}
		if signal.URL != "" {
			fmt.Fprintf(w, " [%s]", signal.URL)
		}
		fmt.Fprintln(w)
	}
}
