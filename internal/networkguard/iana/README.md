# Pinned IANA address registry snapshots

This directory vendors the CSV forms of the authoritative IANA
[IPv4 Special-Purpose Address Registry][ipv4] and
[IPv6 Special-Purpose Address Registry][ipv6]. The current snapshots were
retrieved on 2026-08-19. Runtime scans use generated Go data and never contact
IANA.

To refresh both snapshots and regenerate the embedded policy from the repository
root, run:

```sh
go run ./internal/networkguard/cmd/registrygen \
  -refresh \
  -ipv4 internal/networkguard/iana/iana-ipv4-special-registry.csv \
  -ipv6 internal/networkguard/iana/iana-ipv6-special-registry.csv \
  -output internal/networkguard/iana_registry_generated.go
```

Review the snapshot and generated-source diffs together. The generator rejects
unexpected columns, malformed or non-canonical prefixes, address-family
mismatches, duplicate prefixes, and unknown reachability values. It sorts output
deterministically. Refresh downloads disable environment proxies and use
`networkguard` to validate every DNS answer and pin each connection to an
approved public address. `go generate ./internal/networkguard` regenerates from
the checked-in snapshots without network access.

[ipv4]: https://www.iana.org/assignments/iana-ipv4-special-registry/
[ipv6]: https://www.iana.org/assignments/iana-ipv6-special-registry/
