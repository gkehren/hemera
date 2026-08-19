# Security and ethical boundaries

Hemera processes attacker-controlled URLs and web content. Safety is part of the
core architecture, even while the scanner is local, because the same components
may later be exposed through a web interface.

## Authorized, low-impact use

Users are responsible for scanning only targets they are authorized to assess.
Hemera is intended for observation and classification. It should behave like a
normal, bounded page visit and must not attempt to defeat the controls it finds.

## Mandatory URL and network controls

Before any connection, and again for every redirect or fresh DNS resolution:

- allow only `http` and `https` schemes;
- reject loopback, private, link-local, multicast, and unspecified addresses;
- reject cloud metadata endpoints and equivalent special-purpose destinations;
- handle IPv4, IPv6, alternate IP representations, and mixed DNS answers;
- mitigate DNS rebinding by validating the addresses actually used;
- bound redirect count and prevent redirects into forbidden networks;
- bound connection, response, and total scan duration;
- limit body size, decompression, concurrent requests, and browser resources.

If a hosted scanner is introduced, it also needs isolation, rate limiting,
admission controls, auditability, and a deployment-specific threat model.

### Implemented HTTP boundary

The current HTTP analyzer applies these controls to its single navigation:

- absolute `http` and `https` URLs only, with no embedded credentials, IPv6
  zones, ambiguous whitespace/control characters, or invalid ports;
- rejection of loopback, private, link-local, multicast, unspecified,
  carrier-grade NAT, documentation, benchmarking, reserved, and metadata address
  ranges for IPv4 and IPv6;
- rejection of empty and mixed public/forbidden DNS answers;
- a dedicated dial path that connects only to a validated IP and preserves the
  original hostname for TLS SNI and certificate checks;
- an analyzer-owned TLS configuration with certificate validation enabled, TLS
  1.2 or later, and only an optional root CA pool exposed for trust
  customization;
- fresh validation before redirects and fresh resolution for every connection,
  so a public-to-private DNS change is blocked;
- no use of proxy environment variables, no subresource requests, and at most
  one active connection per host;
- a 15-second total deadline, 5-second connection/TLS/header deadlines, at most
  10 redirects, 1 MiB of response headers, and 2 MiB of decompressed body data;
- a 512-byte User-Agent limit and at most 4096 unique static script or iframe
  URLs extracted from the final document;
- cancellable charset decoding and two HTML5 tokenizer passes without a DOM
  tree, preventing attacker-controlled nesting from driving recursive traversal.

Configuration can only reduce these limits; it cannot raise the safety
ceilings. Reaching the static resource limit preserves already collected
signals, stops extraction, and emits one warning.

These connection controls apply to the HTTP analyzer and to all connection state
reused by DNS/TLS observation. Browser navigation remains planned and must
establish equivalent boundaries before it is enabled.

### Implemented DNS/TLS boundary

The DNS/TLS analyzer runs only after successful HTTP observation. It reuses the
verified final connection's TLS state and never creates a second TLS connection,
so certificate observation cannot bypass address pinning, SNI, certificate
validation, or the TLS 1.2 minimum. The copied metadata is limited to the TLS
version, ALPN, leaf issuer and subject, and at most 256 DNS SANs; raw
certificates, IP SANs, and session material are not retained. Malformed DNS SANs
are omitted without rewriting their contents into a different hostname.

DNS observation performs one final-host CNAME lookup with a two-second hard
ceiling. The CLI does not accept a custom resolver, proxy, or nameserver. The
lookup records only a syntactically valid canonical DNS name and never connects
to it, so it cannot change or weaken the validated-IP dial path. Initial and
redirect targets, including private or mixed DNS address answers, are still
rejected by `internal/networkguard` before the DNS/TLS analyzer can run. A local
CNAME failure is reported as partial coverage; caller cancellation remains fatal.

DNS/TLS values are deterministic, bounded supporting evidence. Product rules
must combine weak infrastructure properties with independent product-specific
signals rather than convert a shared CNAME or certificate into a WAF or bot-
management assertion.

### Special-purpose address policy

`internal/networkguard` accepts an address only when all of these conditions
hold:

1. the address is valid, has no IPv6 zone, and Go classifies it as global
   unicast;
2. after normalizing an IPv4-mapped IPv6 address to IPv4, it is outside every
   prefix in the pinned IANA IPv4 and IPv6 Special-Purpose Address Registries;
3. it is outside every explicit Hemera policy override.

Hemera rejects every IANA special-purpose entry, including entries whose
`Globally Reachable` attribute is `True`. This deliberately conservative rule
keeps translation, anycast, protocol-assignment, and other special-purpose
infrastructure out of the scanner's destination set. IPv4-mapped IPv6 addresses
are the one representation rule: they are classified according to their
underlying IPv4 address, so mapped public IPv4 remains public while mapped
private or special-purpose IPv4 remains forbidden.

The registry-derived table retains each prefix's IANA name and normalized
`Globally Reachable` value for review. Hemera-specific exclusions are declared
separately in `policyOverrides`: IPv4 and IPv6 multicast, the deprecated IPv4-
compatible IPv6 block, and deprecated IPv6 site-local addresses. Cloud metadata
addresses remain blocked by the registry-derived link-local and unique-local
ranges rather than by hostname assumptions.

The pinned CSV snapshots and generated Go source are checked in, so normal
scans are deterministic and make no IANA or other policy-network request. See
the [snapshot maintenance instructions](../internal/networkguard/iana/README.md)
for the authoritative source URLs and the refresh command. Maintainers must
review snapshot and generated diffs together. `go generate
./internal/networkguard` regenerates offline from the pinned snapshots, package
tests verify that the generated output is current, and CI repeats generation
and rejects any diff. The opt-in refresh download disables environment proxies,
validates every IANA DNS answer with this same policy, and connects only to the
validated IP while retaining `www.iana.org` for TLS verification.

## Browser isolation

Browser analysis executes untrusted content. The implementation should use a
maintained Chromium version, preserve the browser sandbox, isolate scan state,
use a fresh profile, restrict downloads and external protocol handlers, and
terminate the browser when time or resource budgets are exceeded. Running
Chromium with its sandbox disabled is not an acceptable production default.

### Implemented browser bootstrap, navigation, and capture boundary

`internal/browser` implements process and CDP session lifecycle plus bounded
capture of the current target. It uses a locally maintained Chromium or Chrome
executable and never downloads a browser. Every session receives a new temporary
profile, runs headless, listens for CDP only on `127.0.0.1` with an
operating-system-selected port, and starts at `about:blank`. Remote CDP
attachment is not supported.

The package explicitly sets the `no-sandbox` allocator option to false. This
prevents `chromedp` from silently adding `--no-sandbox` when Hemera runs as root;
the effective Chromium command line is then read through CDP and rejected if a
launcher added any sandbox-disabling switch. Startup fails when this verification
is unavailable or the environment cannot launch Chromium with its sandbox. A
startup timeout of at most 10 seconds covers process launch and the
`Browser.getVersion` handshake. Caller cancellation, startup failure, loss of
the CDP session, and explicit close all stop the process and remove the profile;
explicit close also has a fixed shutdown deadline.

At most one recorder and one navigation are active per session. Cancellation,
explicit recorder close, CDP loss, and session shutdown all stop collection.
Requests and responses retain only cleaned HTTP(S) URLs, methods, statuses, MIME
types, and resource types. Redirect responses are recorded, but headers, bodies,
POST data,
timestamps, CDP identifiers, remote addresses, and cookie values are never
retained. Final cookie values are discarded immediately while names are sorted
and deduplicated. URL credentials and fragments are removed, queries are reduced
to `?redacted`, and invalid or non-web metadata is omitted.

The internal result has fixed per-collection and URL ceilings. A Hemera-owned
serializer runs in an isolated JavaScript world and stops appending after 2 MiB
or after 100,000 DOM node and attribute visits. It therefore never asks Chromium
or Go to construct an unbounded serialized document. The bounded snapshot
remains in memory and is not persisted or passed to a reporter; like all page
content, it must still be treated as sensitive and untrusted. Limit warnings are
generic and contain no page-controlled text.

Internal production code can now navigate an untrusted HTTP(S) target, but the
capability is not used by `hemera scan`. Chromium receives a per-session
loopback proxy and is configured without proxy bypass, direct hostname
resolution, QUIC, or non-proxied WebRTC UDP. WebSocket transports are rejected.
The proxy parses the initial target, redirects, and HTTP subresources through
the shared URL policy. It re-resolves at connection time
and passes only the validated IP to the injected dialer, preventing Chromium DNS
behavior or rebinding from selecting a forbidden address. HTTPS remains
end-to-end between Chromium and the original hostname through a validated
CONNECT tunnel; the proxy does not decrypt page traffic.

Every navigation has a total timeout, connection timeouts, request and redirect
counts, active browser-request concurrency, response-header size, total
transferred-byte, and decoded-response-byte ceilings. Directly forwarded HTTP
also has a response-header timeout. CDP pauses HTTP(S) requests before dispatch
to enforce counts and tracks each lifecycle until loading succeeds or fails.
This prevents HTTP/2 streams multiplexed through one HTTPS tunnel from bypassing
the concurrency ceiling. Decoded byte events cover compression inside opaque
HTTPS tunnels. Exceeding a budget cancels navigation and active proxy work.
Downloads are denied, cache reuse and service workers are bypassed, and no proxy
destination is available between navigations. Initial
targets with credentials, ambiguous syntax, non-HTTP(S) schemes, or forbidden
addresses fail before page loading. Browser URLs also have a fixed byte limit,
and proxy transfer accounting includes headers, uploads, downloads, and opaque
tunnel traffic.

The tagged integration test uses a checked-in synthetic browser corpus, injects
a synthetic public DNS answer, and maps only the validated dial to its loopback
`httptest` server. Its test-only loader caps files and the complete corpus,
rejects traversing paths and absolute or protocol-relative HTTP(S) asset
references, and serves only declared routes for `fixture.test`. Fake query
values, authorization data, fragments, and cookie values exercise minimization
without containing live credentials or personal data. Loopback remains
forbidden under the production policy, and no public DNS or third-party
destination is contacted. Browser observations are still internal and are not
converted to signals or reports.
External protocol handling, normalized evidence minimization, and scanner-level
aggregation remain future integration work; the current navigation method does
not authorize challenge bypass, fingerprint spoofing, or active probing.

## Explicitly prohibited capabilities

Hemera must not include features that:

- solve, bypass, or automate CAPTCHA/challenges;
- spoof browser, device, or behavioral fingerprints for evasion;
- send malicious or exploit-oriented payloads to trigger a WAF;
- provide procedural guidance for evading a detected protection;
- perform credential attacks, aggressive crawling, or denial-of-service behavior;
- turn a weak infrastructure hint into an overstated product accusation.

## Evidence handling

Reports and fixtures may contain URLs, headers, cookies, page fragments, or other
sensitive material. Implementations should minimize collection, redact secret or
session-bearing values by default, avoid persisting data unless requested, and
document what each output format records. Public test fixtures must use synthetic
or explicitly redistributable data.

The text and JSON reporters mask every query string and remove URL user
information and fragments. They may expose cookie and header names as evidence,
but never their values, and never expose collected HTML. Internally, HTTP signals
omit cookie values and redact authorization-, cookie-, token-, secret-,
authentication-, and API-key-bearing header values. Reports are produced in
memory and the scanner does not persist results. Multi-analyzer reports expose
each source's coverage status and producer-sanitized warnings, but omit retained
analyzer error details because those errors can contain attacker-controlled URLs
or other untrusted data. Analyzer warnings must never include raw attacker input
or secrets.

Detector documents are also treated as untrusted local input. JSON decoding
rejects unknown fields and unsupported versions and bounds document size, rule
count, condition depth, evidence count, and pattern length. Regular expressions
use Go's RE2 engine. Rule matching consumes already normalized signals and has no
network or browser capability.

## Reporting security issues

A private vulnerability-reporting channel will be documented before the first
public release. Until then, avoid publishing exploitable details in a public issue
and contact the repository owner through a private channel if one is available.
