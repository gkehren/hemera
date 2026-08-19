// Command registrygen validates pinned IANA special-purpose address registry
// snapshots and generates the deterministic runtime policy table.
package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gkehren/hemera/internal/networkguard"
)

const (
	ipv4RegistryURL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
	ipv6RegistryURL = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"
	maxSnapshotSize = 1 << 20
	minRegistrySize = 20
)

var expectedHeader = []string{
	"Address Block",
	"Name",
	"RFC",
	"Allocation Date",
	"Termination Date",
	"Source",
	"Destination",
	"Forwardable",
	"Globally Reachable",
	"Reserved-by-Protocol",
}

type options struct {
	ipv4Path string
	ipv6Path string
	output   string
	refresh  bool
}

type registryEntry struct {
	prefix            netip.Prefix
	name              string
	globallyReachable string
}

func main() {
	var opts options
	flag.StringVar(&opts.ipv4Path, "ipv4", "", "path to the pinned IANA IPv4 CSV snapshot")
	flag.StringVar(&opts.ipv6Path, "ipv6", "", "path to the pinned IANA IPv6 CSV snapshot")
	flag.StringVar(&opts.output, "output", "", "path to the generated Go source")
	flag.BoolVar(&opts.refresh, "refresh", false, "download fresh snapshots from IANA before generation")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "registrygen: %v\n", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	if opts.ipv4Path == "" || opts.ipv6Path == "" || opts.output == "" {
		return errors.New("-ipv4, -ipv6, and -output are required")
	}

	ipv4Data, err := loadSnapshot(opts.ipv4Path, ipv4RegistryURL, opts.refresh)
	if err != nil {
		return fmt.Errorf("load IPv4 registry: %w", err)
	}
	ipv6Data, err := loadSnapshot(opts.ipv6Path, ipv6RegistryURL, opts.refresh)
	if err != nil {
		return fmt.Errorf("load IPv6 registry: %w", err)
	}

	ipv4Entries, err := parseRegistry(ipv4Data, true)
	if err != nil {
		return fmt.Errorf("validate IPv4 registry: %w", err)
	}
	ipv6Entries, err := parseRegistry(ipv6Data, false)
	if err != nil {
		return fmt.Errorf("validate IPv6 registry: %w", err)
	}
	if len(ipv4Entries) < minRegistrySize || len(ipv6Entries) < minRegistrySize {
		return fmt.Errorf(
			"registry is unexpectedly small: IPv4 has %d prefixes and IPv6 has %d; want at least %d each",
			len(ipv4Entries),
			len(ipv6Entries),
			minRegistrySize,
		)
	}

	generated, err := render(append(ipv4Entries, ipv6Entries...))
	if err != nil {
		return err
	}
	if opts.refresh {
		if err := writeFileIfChanged(opts.ipv4Path, normalizeSnapshot(ipv4Data)); err != nil {
			return fmt.Errorf("write IPv4 snapshot: %w", err)
		}
		if err := writeFileIfChanged(opts.ipv6Path, normalizeSnapshot(ipv6Data)); err != nil {
			return fmt.Errorf("write IPv6 snapshot: %w", err)
		}
	}
	if err := writeFileIfChanged(opts.output, generated); err != nil {
		return fmt.Errorf("write generated policy: %w", err)
	}
	return nil
}

func loadSnapshot(path, sourceURL string, refresh bool) ([]byte, error) {
	if !refresh {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(data) > maxSnapshotSize {
			return nil, fmt.Errorf("snapshot exceeds %d bytes", maxSnapshotSize)
		}
		return normalizeSnapshot(data), nil
	}

	client := newRefreshClient(networkguard.Config{})
	response, err := client.Get(sourceURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", sourceURL, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSnapshotSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshotSize {
		return nil, fmt.Errorf("download exceeds %d bytes", maxSnapshotSize)
	}
	return normalizeSnapshot(data), nil
}

func newRefreshClient(config networkguard.Config) *http.Client {
	guard := networkguard.New(config)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = guard.DialContext
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if len(previous) >= 3 {
				return errors.New("too many redirects")
			}
			if request.URL.Scheme != "https" || request.URL.Hostname() != "www.iana.org" {
				return fmt.Errorf("refusing redirect outside https://www.iana.org: %s", request.URL)
			}
			return nil
		},
	}
}

func normalizeSnapshot(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.TrimRight(data, "\n")
	return append(data, '\n')
}

func parseRegistry(data []byte, ipv4 bool) ([]registryEntry, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, errors.New("registry contains no records")
	}
	if !slices.Equal(records[0], expectedHeader) {
		return nil, fmt.Errorf("unexpected CSV header: %q", records[0])
	}

	entries := make([]registryEntry, 0, len(records)-1)
	seen := make(map[netip.Prefix]struct{}, len(records)-1)
	for rowIndex, record := range records[1:] {
		if len(record) != len(expectedHeader) {
			return nil, fmt.Errorf("row %d has %d fields, want %d", rowIndex+2, len(record), len(expectedHeader))
		}
		name := strings.TrimSpace(record[1])
		if name == "" {
			return nil, fmt.Errorf("row %d has an empty name", rowIndex+2)
		}
		globallyReachable, err := normalizeReachability(record[8])
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", rowIndex+2, err)
		}
		blocks := strings.Split(record[0], ",")
		if len(blocks) == 0 {
			return nil, fmt.Errorf("row %d has no address block", rowIndex+2)
		}
		for _, block := range blocks {
			blockValue, err := stripOptionalFootnote(block)
			if err != nil {
				return nil, fmt.Errorf("row %d address block %q: %w", rowIndex+2, block, err)
			}
			prefix, err := netip.ParsePrefix(blockValue)
			if err != nil {
				return nil, fmt.Errorf("row %d address block %q: %w", rowIndex+2, block, err)
			}
			if prefix.Addr().Is4() != ipv4 {
				return nil, fmt.Errorf("row %d address block %q has the wrong address family", rowIndex+2, block)
			}
			if prefix != prefix.Masked() {
				return nil, fmt.Errorf("row %d address block %q is not canonical", rowIndex+2, block)
			}
			if _, exists := seen[prefix]; exists {
				return nil, fmt.Errorf("row %d duplicates address block %s", rowIndex+2, prefix)
			}
			seen[prefix] = struct{}{}
			entries = append(entries, registryEntry{
				prefix:            prefix,
				name:              name,
				globallyReachable: globallyReachable,
			})
		}
	}

	slices.SortFunc(entries, func(a, b registryEntry) int {
		if comparison := a.prefix.Addr().Compare(b.prefix.Addr()); comparison != 0 {
			return comparison
		}
		return a.prefix.Bits() - b.prefix.Bits()
	})
	return entries, nil
}

func normalizeReachability(value string) (string, error) {
	var err error
	value, err = stripOptionalFootnote(value)
	if err != nil {
		return "", err
	}
	switch value {
	case "True":
		return "true", nil
	case "False":
		return "false", nil
	case "N/A":
		return "n/a", nil
	case "":
		return "unknown", nil
	default:
		return "", fmt.Errorf("unexpected globally reachable value %q", value)
	}
}

func stripOptionalFootnote(value string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return "", nil
	}
	if len(fields) == 1 {
		return fields[0], nil
	}
	if len(fields) != 2 || !isFootnote(fields[1]) {
		return "", fmt.Errorf("unexpected annotation %q", value)
	}
	return fields[0], nil
}

func isFootnote(value string) bool {
	if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
		return false
	}
	for _, character := range value[1 : len(value)-1] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func render(entries []registryEntry) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString("// Code generated by registrygen; DO NOT EDIT.\n")
	output.WriteString("//\n")
	fmt.Fprintf(&output, "// Source: %s\n", ipv4RegistryURL)
	fmt.Fprintf(&output, "// Source: %s\n", ipv6RegistryURL)
	output.WriteString("\npackage networkguard\n\n")
	output.WriteString("import \"net/netip\"\n\n")
	output.WriteString("var ianaSpecialPurposePrefixes = []specialPurposePrefix{\n")
	for _, entry := range entries {
		fmt.Fprintf(
			&output,
			"\t{prefix: netip.MustParsePrefix(%q), name: %q, globallyReachable: %q},\n",
			entry.prefix.String(),
			entry.name,
			entry.globallyReachable,
		)
	}
	output.WriteString("}\n")

	formatted, err := format.Source(output.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated policy: %w", err)
	}
	return formatted, nil
}

func writeFileIfChanged(path string, data []byte) error {
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, data) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
