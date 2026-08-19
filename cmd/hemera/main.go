package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
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
  hemera [--help] [--version]

Options:
  -h, --help  Show this help message
  --version   Print the Hemera version

The scan command is not implemented yet.`)
}
