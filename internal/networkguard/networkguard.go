// Package networkguard validates untrusted web destinations and pins each
// connection to an address that passed Hemera's public-network policy.
package networkguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var (
	// ErrInvalidURL identifies a malformed or unsupported target URL.
	ErrInvalidURL = errors.New("invalid target URL")
	// ErrForbiddenDestination identifies an address outside the public Internet.
	ErrForbiddenDestination = errors.New("forbidden destination")
	// ErrEmptyResolution identifies a hostname that resolved to no addresses.
	ErrEmptyResolution = errors.New("hostname resolved to no addresses")
	// ErrTooManyRedirects identifies a redirect chain beyond the configured limit.
	ErrTooManyRedirects = errors.New("too many redirects")
)

// Resolver is the DNS operation required by Guard.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Dialer opens a connection to an already validated IP address and port.
type Dialer func(context.Context, string, string) (net.Conn, error)

// Config supplies the injectable network dependencies used by a Guard.
type Config struct {
	Resolver Resolver
	Dialer   Dialer
}

// Guard enforces Hemera's URL and destination policy.
type Guard struct {
	resolver Resolver
	dialer   Dialer
}

// New constructs a network guard. Nil dependencies use the standard resolver
// and a net.Dialer with its zero-value behavior.
func New(config Config) *Guard {
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := config.Dialer
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}
	return &Guard{resolver: resolver, dialer: dialer}
}

// ParseURL validates the syntax and supported features of an absolute web URL.
func ParseURL(rawURL string) (*url.URL, error) {
	if rawURL == "" || strings.TrimSpace(rawURL) != rawURL {
		return nil, fmt.Errorf("%w: URL is empty or surrounded by whitespace", ErrInvalidURL)
	}
	for _, r := range rawURL {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '\\' {
			return nil, fmt.Errorf("%w: URL contains an ambiguous character", ErrInvalidURL)
		}
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}
	if u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: an explicit host is required", ErrInvalidURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: embedded credentials are not allowed", ErrInvalidURL)
	}
	if strings.Contains(u.Hostname(), "%") {
		return nil, fmt.Errorf("%w: IPv6 zones are not allowed", ErrInvalidURL)
	}
	if _, err := url.ParseRequestURI(u.RequestURI()); err != nil {
		return nil, fmt.Errorf("%w: invalid request target", ErrInvalidURL)
	}
	if _, err := portForURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// Validate resolves and validates a parsed URL without opening a connection.
func (g *Guard) Validate(ctx context.Context, u *url.URL) error {
	_, err := g.resolve(ctx, u.Hostname())
	return err
}

// DialContext resolves the original request hostname, validates every returned
// address, and tries each validated address with the requested port until one
// connects or the context ends.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid dial address: %v", ErrInvalidURL, err)
	}
	addresses, err := g.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dialErrors := make([]error, 0, len(addresses)+1)
	for _, resolved := range addresses {
		if err := ctx.Err(); err != nil {
			dialErrors = append(dialErrors, err)
			break
		}
		pinned := net.JoinHostPort(resolved.String(), port)
		conn, err := g.dialer(ctx, network, pinned)
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("%s: %w", pinned, err))
		if err := ctx.Err(); err != nil {
			dialErrors = append(dialErrors, err)
			break
		}
	}
	return nil, fmt.Errorf("dial %s: %w", host, errors.Join(dialErrors...))
}

func (g *Guard) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		literal = literal.Unmap()
		if !Allowed(literal) {
			return nil, fmt.Errorf("%w: %s", ErrForbiddenDestination, literal)
		}
		return []netip.Addr{literal}, nil
	}

	addresses, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyResolution, host)
	}
	normalized := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || !Allowed(address) {
			return nil, fmt.Errorf("%w: %s resolved to %s", ErrForbiddenDestination, host, address)
		}
		normalized = append(normalized, address)
	}
	return normalized, nil
}

func portForURL(u *url.URL) (string, error) {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			return "443", nil
		}
		return "80", nil
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed < 1 || parsed > 65535 {
		return "", fmt.Errorf("%w: invalid port %q", ErrInvalidURL, port)
	}
	return port, nil
}

var forbiddenPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
	"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16",
	"::ffff:0:0:0/96", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)

// Allowed reports whether an address is a publicly routable destination under
// Hemera's conservative special-purpose network policy.
func Allowed(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.IsGlobalUnicast()
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
