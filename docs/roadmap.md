# Roadmap

This document is the authoritative source for Hemera's implementation order and
status. Checkboxes describe verified repository state, not intent;
implementation status is maintained only here.

The roadmap favors working vertical slices and testable detector quality. Its
ordering follows the project priorities: safety, accuracy, explainability,
reproducibility, extensibility, then usability. The post-Milestone 0 realignment
is tracked in [issue #1](https://github.com/gkehren/hemera/issues/1).

## Milestone 0 — Local core

- [x] Initialize the Go module and CLI entry point.
- [x] Define and test the normalized `Signal` model.
- [x] Implement safe URL validation and redirect validation.
- [x] Implement the HTTP analyzer.
- [x] Define, validate, and document the detector rule schema.
- [x] Implement deterministic rule matching and initial confidence scoring,
  including positive, missing, negative, ambiguous, dependency, and directional
  conflict semantics.
- [x] Render CLI and JSON reports.
- [x] Add initial Cloudflare Turnstile and reCAPTCHA rules.
- [x] Add deterministic positive, negative, ambiguity, and regression fixtures.

**Exit criterion:** a local scan can safely collect HTTP signals and explain the
result of at least two fixture-backed detector families.

## Milestone 0.5 — Core hardening

This deliberately small milestone protects the core architecture before browser
navigation and multi-source signal collection are connected to the scanner. It
does not add protection vendors. The Chromium process/CDP bootstrap landed early,
but it does not navigate or produce signals and does not remove these
prerequisites.

- [x] Prevent correlated observations from being counted as independent proof
  in confidence scores ([issue #2](https://github.com/gkehren/hemera/issues/2)).
- [x] Decouple scanner orchestration from `httpanalyzer.Result` and define
  deterministic multi-analyzer aggregation and partial-failure semantics
  ([issue #3](https://github.com/gkehren/hemera/issues/3)).
- [x] Define the DNS/TLS observation contract and its place in the shared
  analyzer pipeline before implementing collection in Milestone 1
  ([issue #4](https://github.com/gkehren/hemera/issues/4)).
- [x] Make the special-purpose network policy maintainable against IANA registry
  changes ([issue #5](https://github.com/gkehren/hemera/issues/5)).
- [x] Add baseline GitHub Actions CI before browser navigation enters the scan
  pipeline:
  - Linux: format verification, `go vet ./...`, `go test ./...`,
    `go test -race ./...`, `govulncheck ./...`, and a CLI build.
  - macOS and Windows: `go test ./...` and a CLI build.
- [x] Clarify that JSON report-schema compatibility remains experimental until
  the first stable release
  ([issue #6](https://github.com/gkehren/hemera/issues/6)).
- [x] Synchronize roadmap status with the rule, scoring, schema-documentation,
  and fixture capabilities already implemented in Milestone 0.

**Exit criterion:** the analyzer aggregation, scoring semantics, network policy,
compatibility policy, and automated core regression checks are explicit and
protected before untrusted browser navigation is integrated into `hemera scan`.

## Milestone 1 — Multi-source observation

Target flow:

```text
HTTP --------┐
DNS/TLS -----┼--> normalized signals --> rules --> scoring --> report
Browser -----┘
```

- [x] Integrate a sandboxed local Chromium process through a mature CDP client.
- [x] Implement bounded DNS/TLS observation and normalized `dns_record` and
  `tls_property` signals, reusing validated HTTP/TLS state where practical
  ([issue #4](https://github.com/gkehren/hemera/issues/4)).
- [x] Capture browser network traffic, final DOM, scripts, iframes, and dynamic
  cookies.
- [x] Enforce browser destination validation, navigation timeouts, and resource
  limits.
- [x] Add browser fixtures that do not depend on live third-party pages.
- [x] Add browser-specific CI incrementally as deterministic navigation fixtures
  become available. The initial Linux job runs standard and race tests.
- [x] Aggregate HTTP, DNS/TLS, and browser observations into one deterministic
  report without coupling detector rules to an analyzer implementation.
- [x] Harden bounded post-load observation, Chromium security invariants,
  child-target behavior, cookie provenance, and coverage-aware reporting
  ([issue #7](https://github.com/gkehren/hemera/issues/7)).
- [x] Eliminate browser integration ordering and post-load fixture races, add
  bounded CDP diagnostics, and verify repeated standard and race runs
  ([issue #15](https://github.com/gkehren/hemera/issues/15)).

**Exit criterion:** browser-only, DNS/TLS-only, and HTTP evidence can participate
in detections without coupling detector rules to a specific analyzer, while
bounded post-load activity and incomplete source coverage remain explicit.

## Milestone 2 — Detector quality and coverage

The existing Turnstile and reCAPTCHA fixtures already cover positive, negative,
ambiguous, and false-positive-oriented regression cases. This is a regression
baseline, not yet a broad measurement of false-positive and false-negative rates.

- [x] Define and enforce a support standard for every detector family, including
  where applicable:
  - positive fixtures;
  - hard negatives and ambiguous cases;
  - known false positives and false negatives;
  - documented evidence rationale;
  - documented score and threshold rationale;
  - explicit vendor-level versus product-level separation.
- [x] Complete general Cloudflare coverage with product-level separation.
- [x] Add AWS WAF, DataDome, and Akamai detectors.
- [x] Evaluate hCaptcha and Arkose Labs signatures.
- [x] Expand the regression corpus, measure false positives, and record known
  false negatives.
- [x] Document the limitations of every supported detector.

**Exit criterion:** at least five protection families meet the documented
evidence, fixture, rationale, and regression-measurement standards.

## Milestone 3 — Public open-source release

The detector schema is already documented. This milestone adds the contributor
and release guarantees needed for a public project; baseline CI belongs to
Milestone 0.5 rather than this release phase.

- [x] Publish installation and usage examples.
- [ ] Document the detector contribution workflow.
- [ ] Add a contribution guide and code of conduct.
- [ ] Publish a private security-reporting process.
- [ ] Select and add an open-source license.
- [ ] Adopt and document stable public compatibility guarantees for rules,
  reports, and the CLI before the first stable release, including any supported
  historical-schema lifecycle.
- [ ] Produce reproducible Linux, macOS, and Windows release binaries and a
  multi-platform release pipeline.
- [ ] Publish a container image if it adds practical value.
- [ ] Consider a public detector benchmark or redistributable corpus once its
  provenance and maintenance model are clear.

**Exit criterion:** an external developer can install, evaluate, extend, test,
and contribute to Hemera using repository documentation alone, and users can
obtain reproducible releases with explicit compatibility and security-support
policies.

## Later opportunities

- Local web interface and HTML report
- Local scan history and report comparison
- Plugin system
- SARIF or another automation export where useful
- Community-maintained fixture corpus

These are stretch goals. They should not delay safety, core detection quality,
or reproducible releases.
