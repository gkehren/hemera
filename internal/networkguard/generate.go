package networkguard

// Regenerate the embedded IANA special-purpose address policy from the
// checked-in snapshots. Runtime scans never invoke this command or access IANA.
//
//go:generate go run ./cmd/registrygen -ipv4 iana/iana-ipv4-special-registry.csv -ipv6 iana/iana-ipv6-special-registry.csv -output iana_registry_generated.go
