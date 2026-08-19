# Hemera

Hemera is an open-source web protection scanner. Given a URL, it observes the
publicly visible HTTP, DNS, TLS, DOM, and browser-network signals and produces an
explainable report about the protections that may be present: CDN/reverse proxy,
WAF, bot management, CAPTCHA/challenge, client-side fingerprinting, and related
security services.

> Hemera is in early development. Safe HTTP scanning, normalized HTTP signal
> collection, detector rule matching, correlation-aware confidence scoring,
> initial Turnstile and reCAPTCHA detectors, text/JSON reports, deterministic
> multi-analyzer orchestration, and internal sandboxed Chromium/CDP session
> startup are implemented. Browser page analysis, DNS and TLS analyzers, and
> broader detector coverage are not available yet.

## What Hemera aims to provide

- Passive or low-impact analysis of a complete HTTP/HTTPS URL.
- Evidence-backed detections instead of opaque vendor labels.
- A confidence score that exposes grouped positive, missing, ambiguous, and
  conflicting signals without treating correlated observations as independent
  proof.
- Human-readable CLI output and a stable JSON format for automation.
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

## Initial detector coverage

Hemera currently ships two product-specific static HTML detectors:

- Cloudflare Turnstile;
- Google reCAPTCHA, including the documented standard and Enterprise client
  script locations.

The official client script is strong evidence. Static widget or inline-call
markers are supporting evidence and do not reach the detection threshold alone.
All observations from the same static integration share one evidence group, so
seeing both a client script and its HTML marker explains the integration without
inflating its confidence above the strongest observation. Complementary future
HTTP, DNS/TLS, or browser evidence can use distinct groups and raise the score.
These rules identify client integration visible in the final HTML; they do not
execute JavaScript or distinguish reCAPTCHA v2, v3, invisible, and Enterprise as
separate products. Turnstile evidence does not imply that Cloudflare proxy, WAF,
or Bot Management is enabled.

Later detector families are planned around:

- Cloudflare (CDN/proxy, Turnstile, and sufficiently reliable challenge or bot
  management signals);
- Google reCAPTCHA (v2, invisible, v3, and Enterprise where distinguishable);
- AWS WAF;
- Akamai protections and Bot Manager;
- DataDome;
- hCaptcha and Arkose Labs, subject to signature quality.

Vendor infrastructure alone must not imply that a specific product is enabled.
For example, detecting Cloudflare must not automatically produce a Cloudflare Bot
Management detection.

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

## Current HTTP scan

Hemera can perform one bounded, passive HTTP navigation:

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

The default text report and versioned JSON report contain scored product
detections with the evidence that contributed to them. The JSON contract is
documented in [JSON report schema V3](docs/report-schema.md). A non-2xx response
and a truncated body are successful observations; DNS, connection, TLS,
timeout, read, and unsafe-redirect failures are reported as scan failures.

Only scan public targets that you are authorized to assess.

## Current rule engine

Hemera has a strict, versioned JSON schema for data-driven detector rules and an
engine for deterministic matching and explainable confidence scoring. It
supports weighted `all`/`any` evidence, negative and ambiguous observations,
correlation groups aggregated by their maximum contribution, minimum independent
evidence, dependencies, and cross-rule conflict penalties. Scores are bounded
confidence indicators, not calibrated probabilities.

`hemera scan` evaluates the embedded rules after HTTP analysis and passes the
scored results to the selected reporter. See the
[detector rule schema V2](docs/detector-rules.md) for the implemented contract,
built-in rules, and scoring semantics.

## Development

Hemera requires Go 1.26 or later. Because it processes untrusted network input,
build it with the latest supported Go patch release. From the repository root:

```sh
go run ./cmd/hemera --help
go run ./cmd/hemera scan https://example.com/
go test ./...
```

GitHub Actions runs formatting, vetting, unit and race tests, vulnerability
scanning, and a CLI build on Linux. It also runs tests and a CLI build on macOS
and Windows.

The internal browser package uses `chromedp` but does not download a browser.
Its opt-in integration test requires a locally installed Chromium or Chrome that
can run with its sandbox enabled:

```sh
go test -tags=browser_integration ./internal/browser
```

Set `HEMERA_CHROMIUM_PATH` to select a specific executable. The current CLI does
not start Chromium; browser navigation and signal capture remain planned.

## Documentation

The repository roadmap is the authoritative source for implementation order and
status

- [Documentation index](docs/README.md)
- [Vision, direction, and objectives](docs/vision-and-goals.md)
- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Security and ethical boundaries](docs/security-and-ethics.md)

## Contributing

Formal contribution instructions are not available yet. Early feedback on the
scope, signal model, confidence model, detector format, and safety assumptions is
welcome.

## License

A license has not been selected yet. Until a license file is added, no rights are
granted to copy, modify, or redistribute the code.
