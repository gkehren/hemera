package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/gkehren/hemera/internal/networkguard"
)

const csvHeader = "Address Block,Name,RFC,Allocation Date,Termination Date,Source,Destination,Forwardable,Globally Reachable,Reserved-by-Protocol\n"

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestRefreshClientRejectsForbiddenResolutionBeforeDial(t *testing.T) {
	t.Parallel()
	dialed := false
	client := newRefreshClient(networkguard.Config{
		Resolver: resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip" || host != "www.iana.org" {
				t.Fatalf("LookupNetIP(%q, %q), want ip and www.iana.org", network, host)
			}
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}),
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
	})

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport type = %T, want *http.Transport", client.Transport)
	}
	_, err := transport.DialContext(context.Background(), "tcp", "www.iana.org:443")
	if !errors.Is(err, networkguard.ErrForbiddenDestination) {
		t.Fatalf("DialContext() error = %v, want ErrForbiddenDestination", err)
	}
	if dialed {
		t.Fatal("underlying dialer was called for a forbidden resolution")
	}
}

func TestRefreshClientPinsValidatedAddress(t *testing.T) {
	t.Parallel()
	var dialed string
	client := newRefreshClient(networkguard.Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dialer: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			clientConnection, serverConnection := net.Pipe()
			serverConnection.Close()
			return clientConnection, nil
		},
	})

	transport := client.Transport.(*http.Transport)
	connection, err := transport.DialContext(context.Background(), "tcp", "www.iana.org:443")
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if dialed != "8.8.8.8:443" {
		t.Errorf("dialed address = %q, want 8.8.8.8:443", dialed)
	}
}

func TestParseRegistryNormalizesAndSortsEntries(t *testing.T) {
	t.Parallel()
	data := csvHeader +
		"192.0.2.0/24,Documentation,[RFC5737],2010-01,N/A,False,False,False,False,False\n" +
		"\"192.0.0.170/32, 192.0.0.171/32\",NAT64 Discovery,[RFC8880],2013-02,N/A,False,False,False,False [1],True\n"

	entries, err := parseRegistry([]byte(data), true)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.0.170/32"),
		netip.MustParsePrefix("192.0.0.171/32"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	if len(entries) != len(want) {
		t.Fatalf("entry count = %d, want %d", len(entries), len(want))
	}
	for index := range want {
		if entries[index].prefix != want[index] {
			t.Errorf("entry %d prefix = %s, want %s", index, entries[index].prefix, want[index])
		}
		if entries[index].globallyReachable != "false" {
			t.Errorf("entry %d reachability = %q, want false", index, entries[index].globallyReachable)
		}
	}
}

func TestParseRegistryRejectsInvalidSnapshots(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    string
		ipv4    bool
		wantErr string
	}{
		{"unexpected header", strings.Replace(csvHeader, "Name", "Purpose", 1) + validIPv4Row(), true, "unexpected CSV header"},
		{"wrong family", csvHeader + validIPv4Row(), false, "wrong address family"},
		{"noncanonical prefix", csvHeader + strings.Replace(validIPv4Row(), "192.0.2.0/24", "192.0.2.1/24", 1), true, "not canonical"},
		{"unexpected address annotation", csvHeader + strings.Replace(validIPv4Row(), "192.0.2.0/24", "192.0.2.0/24 stale", 1), true, "unexpected annotation"},
		{"duplicate prefix", csvHeader + validIPv4Row() + validIPv4Row(), true, "duplicates address block"},
		{"unknown reachability", csvHeader + strings.Replace(validIPv4Row(), ",False,False\n", ",Sometimes,False\n", 1), true, "unexpected globally reachable value"},
		{"unexpected reachability annotation", csvHeader + strings.Replace(validIPv4Row(), ",False,False\n", ",False [old],False\n", 1), true, "unexpected annotation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseRegistry([]byte(tt.data), tt.ipv4)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseRegistry() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	t.Parallel()
	entries := []registryEntry{
		{prefix: netip.MustParsePrefix("192.0.2.0/24"), name: "Documentation", globallyReachable: "false"},
	}
	first, err := render(entries)
	if err != nil {
		t.Fatal(err)
	}
	second, err := render(entries)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("render produced different output for identical input")
	}
	if !bytes.Contains(first, []byte("Code generated by registrygen; DO NOT EDIT.")) {
		t.Fatal("render omitted generated-code marker")
	}
}

func TestCheckedInGeneratedPolicyIsCurrent(t *testing.T) {
	t.Parallel()
	ipv4Data, err := os.ReadFile("../../iana/iana-ipv4-special-registry.csv")
	if err != nil {
		t.Fatal(err)
	}
	ipv6Data, err := os.ReadFile("../../iana/iana-ipv6-special-registry.csv")
	if err != nil {
		t.Fatal(err)
	}
	ipv4Entries, err := parseRegistry(ipv4Data, true)
	if err != nil {
		t.Fatal(err)
	}
	ipv6Entries, err := parseRegistry(ipv6Data, false)
	if err != nil {
		t.Fatal(err)
	}
	want, err := render(append(ipv4Entries, ipv6Entries...))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../iana_registry_generated.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("iana_registry_generated.go is stale; run go generate ./internal/networkguard")
	}
}

func validIPv4Row() string {
	return "192.0.2.0/24,Documentation,[RFC5737],2010-01,N/A,False,False,False,False,False\n"
}
