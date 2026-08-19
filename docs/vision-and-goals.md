# Vision, direction, and objectives

## Vision

Hemera should make web-protection fingerprinting understandable. A user supplies
a complete URL; Hemera observes the page passively or with low impact, classifies
the visible protections, and explains each result with the signals that produced
it.

The project is an open-source technical and portfolio project. Its purpose is to
demonstrate thoughtful engineering across Go, HTTP/TLS/DNS, browser automation,
security tooling, testing, and extensible architecture. Turning Hemera into a
SaaS is not an objective.

## Product direction

Project decisions should follow this order of priority:

1. **Safety:** scanning an untrusted URL must not expose the host or a future web
   service to SSRF, unbounded resource use, or unsafe browser behavior.
2. **Accuracy:** a detector should be added only when its signatures can be
   justified and tested. Precision is more valuable than vendor count.
3. **Explainability:** a score without its supporting and conflicting evidence is
   incomplete.
4. **Reproducibility:** fixtures and deterministic rules should make regressions
   visible and results reviewable.
5. **Extensibility:** analyzers, normalized signals, rules, scoring, and reporting
   should remain separate so each can evolve without tightly coupling the rest.
6. **Usability:** installation and CLI usage should remain simple, while
   versioned, deterministic JSON output supports automation and gains a stable
   compatibility policy at the first stable release.

## Primary objectives

- Provide a cross-platform CLI distributed as a straightforward Go binary.
- Analyze HTTP responses and rendered browser behavior.
- Detect at least five protection families with documented limitations.
- Attach positive, missing, negative, and conflicting evidence to detections.
- Produce an explainable confidence score from 0 to 100.
- Offer readable terminal output and a versioned JSON representation, with
  explicit experimental pre-release and stable-release compatibility policies.
- Support data-driven detector definitions and a documented contribution path.
- Maintain a regression corpus that measures known false positives and false
  negatives.
- Produce reproducible releases for Linux, macOS, and Windows.

## Target users

- Developers who want to understand which visible protection layers a page uses.
- Security and platform engineers performing authorized, low-impact inventory.
- Researchers and contributors experimenting with transparent fingerprint rules.
- CI or local tooling that consumes structured scan results.

## Initial protection categories

- CDN / reverse proxy
- WAF
- Bot management
- CAPTCHA / challenge
- Client-side fingerprinting signal
- Third-party security service

The first planned families are Cloudflare, Google reCAPTCHA, AWS WAF, Akamai,
DataDome, hCaptcha, and Arkose Labs. Coverage depends on signature specificity;
the list is not a release promise.

## Non-goals

Hemera must not:

- bypass or solve CAPTCHA and browser challenges;
- falsify browser or device fingerprints;
- generate attack payloads to provoke a WAF;
- provide evasion or bypass guidance;
- crawl or scan a target aggressively;
- infer a specific product solely from weak infrastructure metadata;
- prioritize monetization over open-source engineering quality.

## Definition of done

The original project goal is reached when Hemera has:

- a simple, documented CLI installation and usage flow;
- HTTP and browser-based analysis;
- at least five well-tested protection families;
- evidence-backed, explainable confidence scores;
- regression tests and documented detector limitations;
- clear instructions for adding a detector;
- reproducible multi-platform releases;
- enough documentation for an external developer to evaluate and contribute.

## Decision test

When a proposed feature does not improve safety, accuracy, explainability,
reproducibility, extensibility, or CLI usability, it is probably outside the
current project direction and should be deferred.
