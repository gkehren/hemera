# Roadmap

The roadmap favors working vertical slices and testable detector quality. Items
are intentionally unchecked while the repository remains in its design phase.

## Milestone 0 — Local core

- [x] Initialize the Go module and CLI entry point.
- [x] Define and test the normalized `Signal` model.
- [x] Implement safe URL validation and redirect validation.
- [x] Implement the HTTP analyzer.
- [x] Define and validate the detector rule schema.
- [x] Implement rule matching and confidence scoring V1.
- [x] Render CLI and JSON reports.
- [x] Add initial Cloudflare Turnstile and reCAPTCHA rules.
- [x] Add unit tests and deterministic fixtures.

**Exit criterion:** a local scan can safely collect HTTP signals and explain the
result of at least two fixture-backed detector families.

## Milestone 1 — Browser analysis

- [ ] Integrate Chromium through a mature CDP client.
- [ ] Capture browser network traffic, final DOM, scripts, iframes, and dynamic
  cookies.
- [ ] Enforce navigation timeouts and resource limits.
- [ ] Add browser fixtures that do not depend on live third-party pages.
- [ ] Merge HTTP and browser signals into one deterministic report.

**Exit criterion:** browser-only evidence can participate in detections without
coupling rules to Chromium.

## Milestone 2 — Detection coverage

- [ ] Complete general Cloudflare coverage with product-level separation.
- [ ] Add AWS WAF, DataDome, and Akamai detectors.
- [ ] Evaluate hCaptcha and Arkose Labs signatures.
- [ ] Add explicit negative and conflicting evidence support.
- [ ] Measure false positives and record known false negatives.
- [ ] Document the limitations of every detector.

**Exit criterion:** at least five protection families meet documented evidence
and regression-test standards.

## Milestone 3 — Open-source quality

- [ ] Publish installation and usage examples.
- [ ] Document the detector schema and contribution workflow.
- [ ] Add a contribution guide, code of conduct, and selected open-source license.
- [ ] Run CI for supported platforms.
- [ ] Produce reproducible Linux, macOS, and Windows release binaries.
- [ ] Publish a container image if it adds practical value.

**Exit criterion:** an external developer can install, evaluate, extend, test,
and contribute to Hemera using repository documentation alone.

## Later opportunities

- Local web interface and HTML report
- Local scan history and report comparison
- Plugin system
- SARIF or another automation export where useful
- Public detector benchmark
- Community-maintained fixture corpus

These are stretch goals. They should not delay safety, core detection quality, or
the stable CLI/JSON experience.
