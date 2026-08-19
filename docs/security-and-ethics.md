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

These controls apply to the HTTP analyzer only. Browser and separate DNS/TLS
analyzers remain planned and must establish equivalent boundaries when added.

## Browser isolation

Browser analysis executes untrusted content. The implementation should use a
maintained Chromium version, preserve the browser sandbox, isolate scan state,
use a fresh profile, restrict downloads and external protocol handlers, and
terminate the browser when time or resource budgets are exceeded. Running
Chromium with its sandbox disabled is not an acceptable production default.

### Implemented browser bootstrap boundary

`internal/browser` currently implements process and CDP session lifecycle only.
It uses a locally maintained Chromium or Chrome executable and never downloads a
browser. Every session receives a new temporary profile, runs headless, listens
for CDP only on `127.0.0.1` with an operating-system-selected port, and starts at
`about:blank`. Remote CDP attachment is not supported.

The package explicitly sets the `no-sandbox` allocator option to false. This
prevents `chromedp` from silently adding `--no-sandbox` when Hemera runs as root;
the effective Chromium command line is then read through CDP and rejected if a
launcher added any sandbox-disabling switch. Startup fails when this verification
is unavailable or the environment cannot launch Chromium with its sandbox. A
startup timeout of at most 10 seconds covers process launch and the
`Browser.getVersion` handshake. Caller cancellation, startup failure, loss of
the CDP session, and explicit close all stop the process and remove the profile;
explicit close also has a fixed shutdown deadline.

No untrusted destination is navigated in this slice, and it is not used by
`hemera scan`. Redirect revalidation, address pinning, external protocol and
download restrictions, navigation timeouts, response and resource limits, and
evidence minimization must be implemented before browser navigation is enabled.

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
memory and the scanner does not persist results.

Detector documents are also treated as untrusted local input. JSON decoding
rejects unknown fields and unsupported versions and bounds document size, rule
count, condition depth, evidence count, and pattern length. Regular expressions
use Go's RE2 engine. Rule matching consumes already normalized signals and has no
network or browser capability.

## Reporting security issues

A private vulnerability-reporting channel will be documented before the first
public release. Until then, avoid publishing exploitable details in a public issue
and contact the repository owner through a private channel if one is available.
