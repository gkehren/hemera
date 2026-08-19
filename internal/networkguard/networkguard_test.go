package networkguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestParseURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{"http", "http://example.com/path", false},
		{"case-insensitive HTTPS scheme", "HTTPS://example.com/path", false},
		{"https nonstandard port", "https://example.com:8443/", false},
		{"IPv4", "http://8.8.8.8/", false},
		{"IPv6", "https://[2606:4700:4700::1111]/", false},
		{"missing scheme", "example.com", true},
		{"unsupported scheme", "ftp://example.com", true},
		{"userinfo", "https://user:pass@example.com", true},
		{"empty host", "https:///path", true},
		{"invalid port", "https://example.com:abc", true},
		{"empty port", "https://example.com:/", true},
		{"zero port", "https://example.com:0", true},
		{"large port", "https://example.com:65536", true},
		{"IPv6 zone", "http://[fe80::1%25eth0]/", true},
		{"backslash", `http://example.com\@127.0.0.1/`, true},
		{"control", "http://example.com/\npath", true},
		{"surrounding space", " https://example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseURL(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseURL(%q) error = %v, wantErr %t", tt.rawURL, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidURL) {
				t.Errorf("error = %v, want ErrInvalidURL", err)
			}
		})
	}
}

func TestAllowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		address netip.Addr
		want    bool
	}{
		{"public IPv4", netip.MustParseAddr("8.8.8.8"), true},
		{"second public IPv4", netip.MustParseAddr("1.1.1.1"), true},
		{"public IPv6", netip.MustParseAddr("2606:4700:4700::1111"), true},
		{"mapped public IPv4", netip.MustParseAddr("::ffff:8.8.8.8"), true},
		{"invalid", netip.Addr{}, false},
		{"zoned public IPv6", netip.MustParseAddr("2606:4700:4700::1111%eth0"), false},
		{"unspecified IPv4", netip.MustParseAddr("0.0.0.0"), false},
		{"private IPv4", netip.MustParseAddr("10.0.0.1"), false},
		{"carrier-grade NAT", netip.MustParseAddr("100.64.0.1"), false},
		{"loopback IPv4", netip.MustParseAddr("127.0.0.1"), false},
		{"cloud metadata IPv4", netip.MustParseAddr("169.254.169.254"), false},
		{"container metadata IPv4", netip.MustParseAddr("169.254.170.2"), false},
		{"private IPv4 second block", netip.MustParseAddr("172.16.0.1"), false},
		{"IETF protocol assignment", netip.MustParseAddr("192.0.0.8"), false},
		{"documentation IPv4", netip.MustParseAddr("192.0.2.1"), false},
		{"private IPv4 third block", netip.MustParseAddr("192.168.1.1"), false},
		{"benchmarking IPv4", netip.MustParseAddr("198.18.0.1"), false},
		{"documentation IPv4 second block", netip.MustParseAddr("198.51.100.1"), false},
		{"documentation IPv4 third block", netip.MustParseAddr("203.0.113.1"), false},
		{"multicast IPv4", netip.MustParseAddr("224.0.0.1"), false},
		{"reserved IPv4", netip.MustParseAddr("240.0.0.1"), false},
		{"limited broadcast IPv4", netip.MustParseAddr("255.255.255.255"), false},
		{"unspecified IPv6", netip.MustParseAddr("::"), false},
		{"loopback IPv6", netip.MustParseAddr("::1"), false},
		{"IPv4-compatible loopback", netip.MustParseAddr("::127.0.0.1"), false},
		{"mapped loopback IPv4", netip.MustParseAddr("::ffff:127.0.0.1"), false},
		{"IPv4-IPv6 translation", netip.MustParseAddr("64:ff9b::808:808"), false},
		{"local-use IPv4-IPv6 translation", netip.MustParseAddr("64:ff9b:1::1"), false},
		{"discard-only IPv6", netip.MustParseAddr("100::1"), false},
		{"dummy IPv6", netip.MustParseAddr("100:0:0:1::1"), false},
		{"benchmarking IPv6", netip.MustParseAddr("2001:2::1"), false},
		{"documentation IPv6", netip.MustParseAddr("2001:db8::1"), false},
		{"6to4 IPv6", netip.MustParseAddr("2002::1"), false},
		{"documentation IPv6 second block", netip.MustParseAddr("3fff::1"), false},
		{"segment-routing IPv6", netip.MustParseAddr("5f00::1"), false},
		{"unique-local IPv6", netip.MustParseAddr("fc00::1"), false},
		{"cloud metadata IPv6", netip.MustParseAddr("fd00:ec2::254"), false},
		{"link-local IPv6", netip.MustParseAddr("fe80::1"), false},
		{"site-local IPv6", netip.MustParseAddr("fec0::1"), false},
		{"multicast IPv6", netip.MustParseAddr("ff02::1"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Allowed(tt.address); got != tt.want {
				t.Errorf("Allowed(%s) = %t, want %t", tt.address, got, tt.want)
			}
		})
	}
}

func TestAllowedRejectsEveryIANASpecialPurposePrefix(t *testing.T) {
	t.Parallel()
	for _, entry := range ianaSpecialPurposePrefixes {
		entry := entry
		t.Run(entry.prefix.String(), func(t *testing.T) {
			t.Parallel()
			if entry.name == "" {
				t.Fatal("generated registry entry has an empty name")
			}
			if got := Allowed(entry.prefix.Addr()); got {
				t.Errorf("Allowed(%s) = true, want false for IANA %q prefix", entry.prefix.Addr(), entry.name)
			}
		})
	}
}

func TestAllowedRejectsPolicyOverrides(t *testing.T) {
	t.Parallel()
	representatives := map[string]string{
		"224.0.0.0/4": "224.0.0.1",
		"::/96":       "::192.0.2.1",
		"fec0::/10":   "fec0::1",
		"ff00::/8":    "ff02::1",
	}
	if got, want := len(policyOverrides), len(representatives); got != want {
		t.Fatalf("policy override count = %d, want %d documented representatives", got, want)
	}
	for _, prefix := range policyOverrides {
		address, exists := representatives[prefix.String()]
		if !exists {
			t.Fatalf("policy override %s has no regression representative", prefix)
		}
		if Allowed(netip.MustParseAddr(address)) {
			t.Errorf("Allowed(%s) = true, want false for Hemera override %s", address, prefix)
		}
	}
}

func TestValidateResolution(t *testing.T) {
	t.Parallel()
	resolverError := errors.New("DNS failed")
	tests := []struct {
		name       string
		addresses  []netip.Addr
		resolveErr error
		wantErr    error
	}{
		{"public", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil, nil},
		{"mapped public", []netip.Addr{netip.MustParseAddr("::ffff:8.8.8.8")}, nil, nil},
		{"empty", nil, nil, ErrEmptyResolution},
		{"private", []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, ErrForbiddenDestination},
		{"IPv4-compatible loopback", []netip.Addr{netip.MustParseAddr("::127.0.0.1")}, nil, ErrForbiddenDestination},
		{"deprecated site-local", []netip.Addr{netip.MustParseAddr("fec0::1")}, nil, ErrForbiddenDestination},
		{"mixed", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil, ErrForbiddenDestination},
		{"resolver error", nil, resolverError, resolverError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			guard := New(Config{Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				return tt.addresses, tt.resolveErr
			})})
			u, err := ParseURL("https://example.test/")
			if err != nil {
				t.Fatal(err)
			}
			err = guard.Validate(context.Background(), u)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBlocksAlternativePrivateIPHostname(t *testing.T) {
	t.Parallel()
	guard := New(Config{Resolver: resolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "2130706433" {
			t.Fatalf("resolver host = %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})})
	u, err := ParseURL("http://2130706433/")
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Validate(context.Background(), u); !errors.Is(err, ErrForbiddenDestination) {
		t.Fatalf("Validate() error = %v, want ErrForbiddenDestination", err)
	}
}

func TestValidateHonorsCallerCancellation(t *testing.T) {
	t.Parallel()
	guard := New(Config{Resolver: resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		return nil, ctx.Err()
	})})
	u, _ := ParseURL("https://example.test/")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := guard.Validate(ctx, u); !errors.Is(err, context.Canceled) {
		t.Fatalf("Validate() error = %v, want context.Canceled", err)
	}
}

func TestDialContextPinsValidatedAddress(t *testing.T) {
	t.Parallel()
	var dialed string
	guard := New(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dialer: func(_ context.Context, network, address string) (net.Conn, error) {
			dialed = address
			client, server := net.Pipe()
			server.Close()
			return client, nil
		},
	})
	conn, err := guard.DialContext(context.Background(), "tcp", "example.test:8443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if want := "8.8.8.8:8443"; dialed != want {
		t.Errorf("dialed %q, want %q", dialed, want)
	}
}

func TestDialContextTriesAllValidatedAddresses(t *testing.T) {
	t.Parallel()
	firstError := errors.New("first address unavailable")
	var dialed []string
	guard := New(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
		}),
		Dialer: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			if address == "8.8.8.8:443" {
				return nil, firstError
			}
			client, server := net.Pipe()
			server.Close()
			return client, nil
		},
	})
	conn, err := guard.DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got, want := len(dialed), 2; got != want {
		t.Fatalf("dial attempts = %v, want %d attempts", dialed, want)
	}
	if dialed[0] != "8.8.8.8:443" || dialed[1] != "1.1.1.1:443" {
		t.Errorf("dial attempts = %v, want resolver order", dialed)
	}
}

func TestDialContextJoinsAllDialFailures(t *testing.T) {
	t.Parallel()
	firstError := errors.New("first address unavailable")
	secondError := errors.New("second address unavailable")
	guard := New(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
		}),
		Dialer: func(_ context.Context, _, address string) (net.Conn, error) {
			if address == "8.8.8.8:80" {
				return nil, firstError
			}
			return nil, secondError
		},
	})
	_, err := guard.DialContext(context.Background(), "tcp", "example.test:80")
	if !errors.Is(err, firstError) || !errors.Is(err, secondError) {
		t.Fatalf("DialContext() error = %v, want both dial failures", err)
	}
}

func TestDialContextStopsFallbackWhenContextEnds(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	guard := New(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
		}),
		Dialer: func(_ context.Context, _, _ string) (net.Conn, error) {
			attempts++
			cancel()
			return nil, errors.New("dial interrupted")
		},
	})
	_, err := guard.DialContext(ctx, "tcp", "example.test:80")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext() error = %v, want context.Canceled", err)
	}
	if attempts != 1 {
		t.Errorf("dial attempts = %d, want 1 after cancellation", attempts)
	}
}

func TestDialContextBlocksRebinding(t *testing.T) {
	t.Parallel()
	calls := 0
	guard := New(Config{Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})})
	u, _ := ParseURL("http://example.test/")
	if err := guard.Validate(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	_, err := guard.DialContext(context.Background(), "tcp", "example.test:80")
	if !errors.Is(err, ErrForbiddenDestination) {
		t.Fatalf("DialContext() error = %v, want ErrForbiddenDestination", err)
	}
}
