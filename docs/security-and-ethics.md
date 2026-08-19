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

## Browser isolation

Browser analysis executes untrusted content. The implementation should use a
maintained Chromium version, preserve the browser sandbox, isolate scan state,
use a fresh profile, restrict downloads and external protocol handlers, and
terminate the browser when time or resource budgets are exceeded. Running
Chromium with its sandbox disabled is not an acceptable production default.

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

## Reporting security issues

A private vulnerability-reporting channel will be documented before the first
public release. Until then, avoid publishing exploitable details in a public issue
and contact the repository owner through a private channel if one is available.
