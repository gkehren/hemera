package networkguard

import "net/netip"

type specialPurposePrefix struct {
	prefix            netip.Prefix
	name              string
	globallyReachable string
}

// policyOverrides contains conservative Hemera exclusions that are not sourced
// from the IANA IPv4 and IPv6 Special-Purpose Address Registries. Keep these
// separate so reviewers can distinguish local policy from registry data.
var policyOverrides = []netip.Prefix{
	// IPv4 multicast is outside the IPv4 Special-Purpose Address Registry.
	netip.MustParsePrefix("224.0.0.0/4"),
	// Deprecated IPv4-compatible IPv6 addresses can embed unsafe IPv4 values.
	netip.MustParsePrefix("::/96"),
	// Deprecated IPv6 site-local addresses remain unsuitable scan targets.
	netip.MustParsePrefix("fec0::/10"),
	// IPv6 multicast is outside the IPv6 Special-Purpose Address Registry.
	netip.MustParsePrefix("ff00::/8"),
}

// Allowed reports whether an address is a public destination under Hemera's
// conservative policy. IPv4-mapped IPv6 addresses are classified as IPv4.
// After that normalization, every matching IANA special-purpose prefix is
// rejected, including entries marked as globally reachable, followed by
// explicit Hemera exclusions.
func Allowed(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	for _, entry := range ianaSpecialPurposePrefixes {
		if entry.prefix.Contains(address) {
			return false
		}
	}
	for _, prefix := range policyOverrides {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.IsGlobalUnicast()
}
