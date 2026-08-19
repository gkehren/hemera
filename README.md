# Hemera

Hemera is an open-source web protection scanner. Given a URL, it observes the
publicly visible HTTP, DNS, TLS, DOM, and browser-network signals and produces an
explainable report about the protections that may be present: CDN/reverse proxy,
WAF, bot management, CAPTCHA/challenge, client-side fingerprinting, and related
security services.

> Hemera is in early development. The Go module, bootstrap CLI, and normalized
> signal model are implemented; scanning and detection are not available yet.

## What Hemera aims to provide

- Passive or low-impact analysis of a complete HTTP/HTTPS URL.
- Evidence-backed detections instead of opaque vendor labels.
- A confidence score that exposes positive, missing, ambiguous, and conflicting
  signals.
- Human-readable CLI output and a stable JSON format for automation.
- Data-driven detector rules that can evolve independently from the analyzers.
- Reproducible fixtures and regression tests focused on false positives.

A future scan should look like this:

```text
$ hemera scan https://example.com/login

PROTECTIONS
Cloudflare CDN             100%  VERY HIGH
Cloudflare Turnstile        98%  VERY HIGH
Cloudflare Bot Management   71%  MEDIUM

EVIDENCE — Cloudflare Turnstile
+ Network request: challenges.cloudflare.com/turnstile/...
+ Script: turnstile/v0/api.js
+ DOM: .cf-turnstile
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

## Initial scope

The first detector families are planned around:

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

## Planned architecture

```text
Target URL -> URL validation ┬-> HTTP analyzer -----┐
                             ├-> DNS/TLS analyzer --┼-> normalized signals
                             └-> browser analyzer --┘          |
                                                              v
                     report <- confidence engine <- rule engine
```

Go is the planned implementation language. Analyzers will emit a shared signal
model; a data-driven rule engine will consume those signals without depending on
`net/http` or Chromium directly.

## Development

Hemera requires Go 1.24 or later. From the repository root:

```sh
go run ./cmd/hemera --help
go test ./...
```

The bootstrap CLI currently exposes help and version information. The `scan`
command will be introduced by a later Milestone 0 step.

## Documentation

- [Documentation index](docs/README.md)
- [Vision, direction, and objectives](docs/vision-and-goals.md)
- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Security and ethical boundaries](docs/security-and-ethics.md)

## Contributing

The repository is not ready for implementation contributions yet. Early feedback
on the scope, signal model, confidence model, detector format, and safety
assumptions is welcome. Contribution instructions will be added when the initial
Go module and test conventions are in place.

## License

A license has not been selected yet. Until a license file is added, no rights are
granted to copy, modify, or redistribute the code.
