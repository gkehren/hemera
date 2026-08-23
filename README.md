# Hemera

Hemera is an open-source web protection scanner. Given a URL, it observes the
publicly visible HTTP, DNS, TLS, DOM, and browser-network signals and produces an
explainable report about the protections that may be present: CDN/reverse proxy,
WAF, bot management, CAPTCHA/challenge, client-side fingerprinting, and related
security services.

> Hemera is in early development. Safe HTTP scanning, normalized HTTP signal
> collection, detector rule matching, correlation-aware confidence scoring,
> initial Turnstile and reCAPTCHA detectors, text/JSON reports, deterministic
> multi-analyzer orchestration, bounded DNS/TLS supporting signals, and
> sandboxed Chromium/CDP navigation are implemented. Browser observations are
> normalized and included in the same rule and scoring pass as HTTP and DNS/TLS
> evidence. Broader detector coverage is not available yet.

## What Hemera aims to provide

- Passive or low-impact analysis of a complete HTTP/HTTPS URL.
- Evidence-backed detections instead of opaque vendor labels.
- A confidence score that exposes grouped positive, missing, ambiguous, and
  conflicting signals without treating correlated observations as independent
  proof.
- Human-readable CLI output and a versioned, deterministic JSON format for
  automation. Its compatibility policy remains experimental before the first
  stable Hemera release.
- Data-driven detector rules that can evolve independently from the analyzers.
- Reproducible fixtures and regression tests focused on false positives.

The current human-readable report is designed for direct inspection. For
example, a page containing the documented Turnstile script and widget marker
produces this shape (the target below is illustrative):

```text
$ hemera scan https://protected.example/
Hemera scan report
Target: https://protected.example/
Final URL: https://protected.example/
HTTP status: 200

Detections:
  Cloudflare Turnstile  75.0  HIGH
    + turnstile-client-script: script_url https://challenges.cloudflare.com/turnstile/v0/api.js (raw 75.0; group static_integration)
    + turnstile-html-marker: page_content (raw 30.0; group static_integration)
    = group static_integration: 75.0 (105.0 raw; selected turnstile-client-script)
```

## Installation

### Using Go install (Go 1.26+)

```sh
go install github.com/gkehren/hemera/cmd/hemera@latest
```

### From source

```sh
git clone https://github.com/gkehren/hemera.git
cd hemera
go build -o hemera ./cmd/hemera
```

See the [Installation and usage guide](docs/installation-and-usage.md) for
detailed setup instructions, Chromium configuration, and troubleshooting.

## Quick start

Launch Hemera without arguments in a terminal for the interactive experience:
it asks for the scan mode and target URL, shows live analyzer progress, and
finishes with a styled full report in the same visual language:

```sh
hemera
```

Run a human-readable scan against a target directly:

```sh
hemera scan https://example.com/
```

Generate a machine-readable JSON V6 report for automation:

```sh
hemera scan --format json https://example.com/
```

Filter active detections with `jq`:

```sh
hemera scan --format json https://example.com/ \
  | jq '.detections[] | select(.detected == true) | {rule_id, name, score, level}'
```

The interactive wizard requires a terminal on both stdin and stdout. Piped or
scripted invocations always get the classic non-interactive behavior, so CI and
automation are unaffected. Set `HEMERA_ACCESSIBLE=1` to run the wizard in
huh's accessible, screen-reader-friendly mode.

During an active scan, `Ctrl+C` and supported process-termination signals cancel
the shared scan context. Hemera waits for bounded analyzer and Browser cleanup
before exiting; classic or externally canceled scans return exit code `1`, while
the interactive view's own `Ctrl+C` action remains a successful user cancel
with exit code `0`.

## Project principles

1. **Explainability first.** Every detection must be tied to observable evidence.
2. **Precision over coverage.** A small set of reliable detectors is preferable
   to a large catalogue of approximate signatures.
3. **Safe by design.** URL validation, redirect revalidation, resource limits,
   and private-network protections are core requirements.
4. **Passive observation only.** Hemera does not bypass CAPTCHA, solve challenges,
   spoof fingerprints, probe WAFs with attack payloads, or scan aggressively.
5. **Automation-friendly.** The CLI, JSON schema, rules, and fixtures should be
   deterministic and suitable for CI and other tools.

## Detector coverage

Hemera ships built-in detector rules with explicit product-level separation across 7 vendor families:

- **Cloudflare:**
  - `cloudflare.proxy` (Reverse Proxy / CDN edge infrastructure);
  - `cloudflare.challenge_page` (Managed challenge pages, security error codes, and challenge interstitials);
  - `cloudflare.bot_protection` (Bot Protection / Bot Fight Mode JavaScript detection telemetry);
  - `cloudflare.turnstile` (Turnstile client challenge widget).
- **Google:**
  - `google.recaptcha` (Standard and Enterprise reCAPTCHA client integrations).
- **Amazon Web Services (AWS):**
  - `aws.cloudfront` (Amazon CloudFront edge CDN infrastructure);
  - `aws.waf` (AWS WAF JavaScript SDK, action headers, and block pages).
- **DataDome:**
  - `datadome.bot_protection` (DataDome bot management client tag, headers, and challenge interstitials).
- **Akamai:**
  - `akamai.edge` (Akamai Edge reverse proxy infrastructure);
  - `akamai.bot_manager` (Akamai Bot Manager JavaScript sensors and telemetry cookies).
- **hCaptcha:**
  - `hcaptcha.challenge` (hCaptcha client API script and challenge widget).
- **Arkose Labs:**
  - `arkoselabs.matchkey` (Arkose MatchKey / FunCAPTCHA client API script and enforcement challenge).

Vendor infrastructure alone does not imply that a specific product is enabled.
For example, detecting `aws.cloudfront` or `akamai.edge` never automatically
produces an `aws.waf` or `akamai.bot_manager` detection.

## Architecture

```text
Target URL -> scanner orchestration ┬-> HTTP analyzer -----┐
                                    ├-> DNS/TLS analyzer --┼-> normalized signals
                                    └-> browser analyzer --┘          |
                                                                     v
                            report <- confidence engine <- rule engine
```

Hemera is implemented in Go. Analyzers emit a shared signal model; the
scanner validates and aggregates those signals in configured analyzer order.
The data-driven rule engine and scoring layer consume only the aggregate signals
without depending on `net/http`, DNS/TLS, or Chromium implementation types.

## Current scan pipeline

Hemera performs one bounded passive HTTP navigation, bounded DNS/TLS
observation, and one sandboxed browser navigation:

```sh
go run ./cmd/hemera scan https://example.com/
go run ./cmd/hemera scan --format json https://example.com/
```

The scan validates the initial destination and every redirect, blocks private
and special-purpose networks using pinned IANA registry data plus conservative
local exclusions, ignores environment proxy settings, and does not load page
subresources. Runtime scans never download registry data. The scan reports HTTP
status, redirects, response-header names, cookie names, and statically referenced
scripts, iframes, and third-party hosts. Query values, cookie values, sensitive
header values, and HTML content are not printed.

HTTP configuration can tighten but cannot raise the built-in safety ceilings:
15 seconds total, 5 seconds for connection, TLS, and response headers, 10
redirects, 1 MiB of response headers, 2 MiB of decompressed body data, and 4096
unique script or iframe URLs. Static HTML extraction uses two cancellable HTML5
tokenizer passes and does not construct a DOM tree. TLS uses certificate
validation, hostname-derived SNI, and TLS 1.2 or later.

The browser analyzer runs after HTTP and DNS/TLS with a non-fatal failure
policy. After the page load event, it keeps the complete validated network
boundary active until 250 ms of network quiet or a hard 1.5-second post-load
deadline. Delayed requests, cookies, scripts, iframes, and DOM mutations within
that window are included in the final snapshot. Continuous traffic and long
polling cannot extend the window. Configuration can lower these values but
cannot exceed three seconds post-load or one second idle. A missing or unusable
local Chromium installation produces an explicit failed browser coverage entry while
preserving HTTP and DNS/TLS results. An unsafe initial HTTP target remains fatal
and stops the pipeline before Chromium starts.

Detection results distinguish `not_detected` from `insufficient_coverage` when
a signal capability required by a rule predicate was incompletely observed —
because its analyzer was partial, failed, absent, or hit a bounded-capture
ceiling such as a truncated response body or DOM snapshot. Rules remain coupled
only to normalized source names and signal types, not analyzer implementations.

The default text report and versioned JSON report contain scored product
detections with the evidence that contributed to them. The JSON contract is
documented in [JSON report schema V6](docs/report-schema.md). The JSON schema is
experimental while Hemera is pre-release: intentional breaking changes require
a documented `schema_version` increment, but historical schemas are not yet
promised long-term support. Text output is intended for people and may evolve
for readability; automation should consume JSON. A non-2xx response and a
truncated body are successful observations; DNS, connection, TLS, timeout, read,
and unsafe-redirect failures are reported as scan failures.

Only scan public targets that you are authorized to assess.

## Current DNS/TLS observation

After a successful HTTP navigation, Hemera performs one bounded lookup for the
final host's canonical CNAME and emits it only when it differs from the requested
host. For HTTPS targets it also emits the negotiated TLS version and ALPN, plus
the verified leaf certificate's issuer, subject, and up to 256 sorted DNS SANs.
TLS data comes from the existing HTTP connection; Hemera does not create a
second TLS connection or handshake for observation.

The DNS/TLS analyzer has a two-second lookup ceiling and runs with a `continue`
policy. A CNAME lookup failure therefore leaves reusable TLS evidence available
and marks that analyzer as partial. The CNAME lookup cannot initiate a connection
to its answer, while all HTTP resolution and dialing remains protected by the
same pinned-address network policy. Intermediate CNAME hops, IP addresses, ASN
data, and non-DNS certificate SANs are not collected.

DNS and TLS properties are supporting evidence. They may strengthen a detector
when combined with independent product-specific observations, but vendor
infrastructure alone must not assert that a WAF or bot-management product is
enabled.

## Current rule engine

Hemera has a strict, versioned JSON schema for data-driven detector rules and an
engine for deterministic matching and explainable confidence scoring. It
supports weighted `all`/`any` evidence, negative and ambiguous observations,
correlation groups aggregated by their maximum contribution, minimum independent
evidence, dependencies, and cross-rule conflict penalties. Scores are bounded
confidence indicators, not calibrated probabilities.

`hemera scan` evaluates the embedded rules once after aggregating HTTP, DNS/TLS,
and browser signals, then passes the scored results to the selected reporter.
See the [detector rule schema V2](docs/detector-rules.md) and
[detector family support standard](docs/detector-support-standard.md) for the
implemented contract, built-in rules, quality criteria, and scoring semantics.

## Development

Hemera requires Go 1.26 or later. Because it processes untrusted network input,
build it with the latest supported Go patch release. From the repository root:

```sh
go run ./cmd/hemera --help
go run ./cmd/hemera scan https://example.com/
go test ./...
```

GitHub Actions runs formatting, vetting, unit and race tests, vulnerability
scanning, and a CLI build on Linux. A dedicated Ubuntu 24.04 job also runs the
hermetic Chromium integration tests with and without the race detector, using
the preinstalled sandboxed Google Chrome. The workflow also runs tests and a CLI
build on macOS and Windows; browser integration CI on those platforms remains
planned.

The internal browser package uses `chromedp` but does not download a browser. It
can record bounded, minimized CDP network events and snapshot the current
target's final DOM, script and iframe URLs, and cookie names plus validated
domains. Cookie values are discarded immediately. The browser
analyzer converts this raw result to normalized, deterministic signals; only
evidence selected by detector rules can enter reports. Its opt-in integration
tests require a locally installed Chromium or Chrome that can run with its
sandbox enabled:

```sh
go test -tags=browser_integration ./internal/browser ./internal/scanner
```

Set `HEMERA_CHROMIUM_PATH` to select a specific executable. The integration test
uses the versioned synthetic corpus in `internal/browser/testdata`, injected DNS
and dialing dependencies, and a loopback `httptest` server reached only through
the same validated proxy boundary used in production. The manifest-driven
dynamic and negative scenarios use a fresh Chromium profile, declare every
allowed route, express only semantic traffic dependencies as a partial order,
and never contact a live page or third-party asset. Dynamic fixtures use
explicit network completion handshakes instead of assuming JavaScript timers
finish before the post-load idle window. The scanner fixture additionally
proves combined HTTP, DNS, and browser scoring without contacting public DNS or
a third party.

Internal navigation accepts only HTTP(S) targets and sends Chromium traffic
through a per-session loopback proxy. The proxy applies the shared public-address
policy to the IP used for every upstream connection, including redirects and
subresources. Navigation is limited to 15 seconds, 256 requests by default, 10
redirects, independent 16 MiB ceilings for transferred and decoded response
data, and 16 concurrent browser request lifecycles. The concurrency limit is
enforced through CDP even when HTTPS requests share one multiplexed tunnel.
Configuration may lower these defaults and may raise request or concurrency
counts only to the documented hard ceilings of 4096 and 32. Browser URLs are
limited to 8192 bytes.
Downloads, cache reuse, service workers, direct DNS resolution, and QUIC are
disabled for the bounded navigation. WebRTC is restricted from non-proxied UDP.
WebSocket transports are rejected. Dedicated/shared workers and service workers
are fail-closed before their code can issue child-target traffic; their startup
requests remain subject to the normal budgets. Popup attempts fail the
navigation before a child page can load. Chromium's effective command line is
validated at runtime for the exact Hemera proxy, bypass, resolver, QUIC, WebRTC,
and sandbox invariants.

## Documentation

The repository roadmap is the authoritative source for implementation order and
status

- [Documentation index](docs/README.md)
- [Installation and usage guide](docs/installation-and-usage.md)
- [Vision, direction, and objectives](docs/vision-and-goals.md)
- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Security and ethical boundaries](docs/security-and-ethics.md)
- [Detector rule schema V2](docs/detector-rules.md)
- [Detector family support standard](docs/detector-support-standard.md)
- [Regression corpus and accuracy standards](docs/regression-and-accuracy.md)
- [Detector limitations and operational boundaries](docs/detector-limitations.md)
- [JSON report schema V6](docs/report-schema.md)

## Contributing

Formal contribution instructions are not available yet. Early feedback on the
scope, signal model, confidence model, detector format, and safety assumptions is
welcome.

## License

A license has not been selected yet. Until a license file is added, no rights are
granted to copy, modify, or redistribute the code.
