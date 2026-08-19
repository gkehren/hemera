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
		address string
		want    bool
	}{
		{"8.8.8.8", true}, {"1.1.1.1", true}, {"2606:4700:4700::1111", true},
		{"0.0.0.0", false}, {"10.0.0.1", false}, {"100.64.0.1", false},
		{"127.0.0.1", false}, {"169.254.169.254", false}, {"172.16.0.1", false},
		{"192.0.0.8", false}, {"192.0.2.1", false}, {"192.168.1.1", false},
		{"198.18.0.1", false}, {"198.51.100.1", false}, {"203.0.113.1", false},
		{"224.0.0.1", false}, {"240.0.0.1", false}, {"255.255.255.255", false},
		{"::", false}, {"::1", false}, {"::127.0.0.1", false}, {"::ffff:127.0.0.1", false},
		{"64:ff9b::808:808", false}, {"64:ff9b:1::1", false}, {"100::1", false}, {"2001:db8::1", false},
		{"2001:2::1", false}, {"2002::1", false}, {"fc00::1", false},
		{"3fff::1", false}, {"5f00::1", false}, {"fe80::1", false}, {"fec0::1", false}, {"ff02::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			t.Parallel()
			if got := Allowed(netip.MustParseAddr(tt.address)); got != tt.want {
				t.Errorf("Allowed(%s) = %t, want %t", tt.address, got, tt.want)
			}
		})
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
