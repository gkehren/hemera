# Architecture

## Overview

Hemera separates observation from detection. Protocol- and browser-specific
analyzers collect facts, normalize them as signals, and pass them to a rule
engine. The scoring layer then evaluates the matched, missing, ambiguous, and
conflicting evidence before reporters render the result.

```mermaid
flowchart TD
    URL[Target URL] --> Validate[URL validation]
    Validate --> HTTP[HTTP analyzer]
    Validate --> DNS[DNS / TLS analyzer]
    Validate --> Browser[Chromium / CDP analyzer]
    HTTP --> Signals[Normalized signal collector]
    DNS --> Signals
    Browser --> Signals
    Signals --> Rules[Detection rule engine]
    Rules --> Score[Confidence engine]
    Score --> Report[CLI text / JSON reporters]
```

## Components

### URL validation

Validation is a mandatory boundary before every request and after every redirect.
It should accept only HTTP/HTTPS, resolve hosts under controlled rules, reject
loopback/private/link-local/metadata targets, and enforce redirect, response-size,
and time limits. See [Security and ethical boundaries](security-and-ethics.md).

The implemented `internal/networkguard` package validates absolute HTTP/HTTPS
URLs, resolves names through an injectable resolver, rejects mixed public and
forbidden DNS answers, and composes the validated IP with the requested port for
an injectable dialer. The HTTP transport therefore cannot silently resolve a
different address. When DNS returns several public addresses, the dial path tries
them in resolver order under the same context. Resolution and policy checks occur
during initial validation, before each redirect, and again for every new
connection. TLS continues to use the original hostname for SNI and certificate
validation. The analyzer owns the TLS configuration, enforces TLS 1.2 or later,
and accepts only an optional root CA pool for deterministic trust customization;
callers cannot disable certificate verification.

### HTTP analyzer

The low-cost first pass collects status codes, redirect chains, response headers,
cookies, initial HTML, statically visible scripts and iframes, and third-party
hostnames.

This pass is implemented in `internal/httpanalyzer`. It performs one GET
navigation, ignores environment proxies, and does not fetch subresources. The
complete operation is limited to 15 seconds; connection, TLS handshake, and
response-header waits are each limited to 5 seconds. It permits at most 10
redirects, 1 MiB of response headers, and 2 MiB of decompressed body data.
These are hard ceilings: configuration may lower but cannot raise them. The
User-Agent is limited to 512 bytes, the transport permits one active connection
per host, and static extraction stops after 4096 unique script or iframe URLs.
Intermediate and final HTTP responses produce normalized signals.

Only the final body is analyzed as HTML. Charset decoding and two streaming
HTML5 tokenizer passes from `golang.org/x/net` first select the first valid
HTTP(S) `<base href>`, then extract scripts and iframes in document order. The
analyzer does not build a DOM tree. Decoding and both passes observe the scan
context. Cancellation and deadlines remain fatal; non-security HTML decoding or
tokenization errors become warnings without discarding HTTP signals.

The analyzer records cookie names without values and redacts sensitive response
headers. Stored and displayed URL observations mask query values. A body prefix
at the size limit remains analyzable and is reported as truncated. Unsupported
HTML charsets and parser failures become warnings without discarding HTTP
signals; connection, TLS, timeout, header, and body-read failures remain fatal.

### DNS / TLS analyzer

This analyzer may collect CNAME records, relevant provider or ASN hints, and TLS
certificate properties such as issuer and SANs. These are generally supporting
signals and should not independently prove that a precise bot-management product
is active.

### Browser analyzer

A sandboxed Chromium instance observed through the Chrome DevTools Protocol can
collect the final DOM, network requests and responses, XHR/fetch traffic, dynamic
scripts and iframes, JavaScript-created cookies, browser redirects, visible
challenges, and a small set of relevant JavaScript globals. Navigation remains
normal: the analyzer must not implement bypass behavior.

### Signal model

Every analyzer emits the common model implemented in `pkg/model`:

```go
type Signal struct {
	Type       SignalType `json:"type"`
	Source     string     `json:"source"`
	Key        string     `json:"key"`
	Value      string     `json:"value"`
	URL        string     `json:"url,omitempty"`
	Confidence float64    `json:"confidence"`
}
```

Signal types include response headers, cookies, script URLs, network
requests/responses, DOM selectors, iframe URLs, JavaScript globals, DNS records,
TLS properties, redirects, page content, and statically referenced third-party
resource hosts. A `resource_host` signal means that HTML referenced a host; it
does not mean Hemera contacted that host.

`Type`, `Source`, and `Key` are required. `Confidence` is finite and bounded
between 0 and 1; it represents certainty in the observation, not the final
confidence of a product detection. `URL` is optional because some observations
are not URL-scoped. The model exposes `Validate` so producers can enforce these
shared invariants before signals enter the detection pipeline.

The rule engine must depend on this model, not directly on Chromium or
`net/http`. This boundary enables deterministic fixture tests without live scans.

### Detection rules

Rules are data-driven through the strict, versioned JSON schema implemented in
`internal/rules` and documented in
[Detector rule schema V1](detector-rules.md). The schema expresses:

- positive and negative signals;
- `AND` and `OR` combinations;
- minimum evidence requirements and weighted signals;
- ambiguity penalties and product conflicts;
- dependencies between related vendor and product detections.

Conditions form bounded `all` and `any` trees over normalized signal fields.
Text predicates support exact, contains, prefix, suffix, and RE2 regular
expression operations. Documents and references are validated before matching;
matching retains positive, missing, negative, and ambiguous evidence in stable
rule and predicate order. A vendor-level result never automatically implies a
product-level result.

`internal/detectors` embeds the validated V1 rules shipped with the binary.
Milestone 0 includes product-specific rules for Cloudflare Turnstile and Google
reCAPTCHA. They use documented client-script URLs as decisive evidence and
static HTML markers only as supporting evidence.

### Confidence engine

The V1 model is deliberately simple and is implemented in `internal/scoring`:

```text
score = weighted positive evidence
      - conflicting evidence
      - ambiguity penalty
```

The bounded 0–100 result should be labeled consistently:

| Score | Level | Meaning |
| --- | --- | --- |
| 90–100 | Very High | Several independent, product-specific signals |
| 75–89 | High | Detection is very probable |
| 50–74 | Medium | Meaningful evidence with real ambiguity |
| 25–49 | Low | Weak signals; do not present as certain |
| 0–24 | Not detected | Insufficient evidence |

Each evidence contribution is multiplied by the producing signal's observation
confidence. Scores are clamped to 0–100. Directional cross-rule conflicts apply
fixed penalties when the referenced rule is a matching candidate with non-zero
effective confidence. Dependencies are acyclic and must be detected; a missing
dependency blocks detection while the pre-dependency evidence score remains
available for explanation.

Bayesian scoring, calibration on a labeled corpus, or learned weights can be
considered later; none is part of V1.

### Scan orchestration and reporting

`internal/scanner` is the thin application boundary that runs the HTTP analyzer
and sends normalized signals to the rule and scoring packages. It owns neither
network policy nor presentation.

`internal/report` converts scanner results into a secret-minimized report model.
The CLI renders that model as text by default or as stable, versioned JSON with
`--format json`. Both formats explain detected and non-detected rules. They omit
HTML and header/cookie values and sanitize every emitted URL. The JSON contract
is documented in [JSON report schema V1](report-schema.md). An exportable local
HTML report remains a later goal.

## Proposed repository layout

```text
cmd/hemera/               CLI entry point
internal/scanner/         scan orchestration
internal/detectors/       embedded detector rules
internal/httpanalyzer/    HTTP collection
internal/browser/         Chromium/CDP collection
internal/dns/             DNS and TLS collection
internal/signals/         normalization
internal/rules/           rule loading and matching
internal/scoring/         confidence calculation
internal/report/          safe text and JSON renderers
pkg/model/                intentionally public models, if needed
detectors/                data-driven signatures
testdata/                 fixtures, captures, and expected results
docs/                     project and contributor documentation
```

This is a starting boundary map, not a requirement to create empty packages.
Packages should be introduced as working vertical slices need them.
