# Hemera

Hemera is an open-source web protection scanner. Given a URL, it observes the
publicly visible HTTP, DNS, TLS, DOM, and browser-network signals and produces an
explainable report about the protections that may be present: CDN/reverse proxy,
WAF, bot management, CAPTCHA/challenge, client-side fingerprinting, and related
security services.

> Hemera is in early development. Safe HTTP scanning, normalized HTTP signal
> collection, detector rule matching, confidence scoring V1, initial Turnstile
> and reCAPTCHA detectors, and text/JSON reports are implemented. Browser, DNS,
> and TLS analyzers and broader detector coverage are not available yet.

## What Hemera aims to provide

- Passive or low-impact analysis of a complete HTTP/HTTPS URL.
- Evidence-backed detections instead of opaque vendor labels.
- A confidence score that exposes positive, missing, ambiguous, and conflicting
  signals.
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
  Cloudflare Turnstile  100.0  VERY HIGH
    + turnstile-client-script: script_url https://challenges.cloudflare.com/turnstile/v0/api.js (75.0)
    + turnstile-html-marker: page_content (30.0)
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
Target URL -> URL validation ┬-> HTTP analyzer -----┐
                             ├-> DNS/TLS analyzer --┼-> normalized signals
                             └-> browser analyzer --┘          |
                                                              v
                     report <- confidence engine <- rule engine
```

Hemera is implemented in Go. Analyzers emit a shared signal model; the
data-driven rule engine consumes those signals without depending on `net/http`
or Chromium directly.

## Current HTTP scan

Hemera can perform one bounded, passive HTTP navigation:

```sh
go run ./cmd/hemera scan https://example.com/
go run ./cmd/hemera scan --format json https://example.com/
```

The scan validates the initial destination and every redirect, blocks private
and special-purpose networks, ignores environment proxy settings, and does not
load page subresources. It reports HTTP status, redirects, response-header names,
cookie names, and statically referenced scripts, iframes, and third-party hosts.
Query values, cookie values, sensitive header values, and HTML content are not
printed.

The default text report and versioned JSON report contain scored product
detections with the evidence that contributed to them. The JSON contract is
documented in [JSON report schema V1](docs/report-schema.md). A non-2xx response
and a truncated body are successful observations; DNS, connection, TLS,
timeout, read, and unsafe-redirect failures are reported as scan failures.

Only scan public targets that you are authorized to assess.

## Current rule engine

Hemera has a strict, versioned JSON schema for data-driven detector rules and an
engine for deterministic matching and explainable confidence scoring. It
supports weighted `all`/`any` evidence, negative and ambiguous observations,
minimum evidence, dependencies, and cross-rule conflict penalties.

`hemera scan` evaluates the embedded rules after HTTP analysis and passes the
scored results to the selected reporter. See the
[detector rule schema V1](docs/detector-rules.md) for the implemented contract,
built-in rules, and scoring semantics.

## Development

Hemera requires Go 1.24 or later. From the repository root:

```sh
go run ./cmd/hemera --help
go run ./cmd/hemera scan https://example.com/
go test ./...
```

## Documentation

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
