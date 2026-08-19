# Detector rule schema V2

Hemera detector rules are strict, versioned JSON documents. The implementation
lives in `internal/rules`; matching consumes only normalized `pkg/model.Signal`
values and has no access to HTTP, DNS, TLS, Chromium, or reporters.

The V2 engine is implemented and `hemera scan` evaluates the built-in rules
embedded by `internal/detectors`. The resulting scores and evidence are exposed
through the text and JSON reporters. V1 documents remain readable with their
original additive positive-evidence semantics; correlation metadata requires V2.

## Built-in detectors

Milestone 0 ships two `captcha_challenge` product rules:

| Rule ID | Product | Decisive static evidence | Supporting evidence |
| --- | --- | --- | --- |
| `cloudflare.turnstile` | Cloudflare Turnstile | Documented `challenges.cloudflare.com/turnstile/v0/api.js` script | `cf-turnstile` HTML marker |
| `google.recaptcha` | Google reCAPTCHA | Documented Google or `recaptcha.net` `api.js`/`enterprise.js` script | `g-recaptcha` marker and static `grecaptcha.render`/`execute` call |

The decisive script contributes the 75-point detection threshold. Supporting
markers cannot produce a detection by themselves, which limits false positives
from documentation, copied markup, or dormant code. The script and markers share
the `static_integration` evidence group, whose contribution is their maximum
rather than their sum. A static-only integration therefore remains `high` at 75
instead of becoming `very_high` through correlated markup. A Turnstile result
describes only the product integration; it is not evidence that Cloudflare
proxy, WAF, or Bot Management is active. The reCAPTCHA rule does not yet classify
v2, v3, invisible, and Enterprise separately.

The signatures follow the vendors' documented client integrations:

- [Cloudflare Turnstile client-side rendering](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/)
- [Google reCAPTCHA v2 display](https://developers.google.com/recaptcha/docs/display)
- [Google reCAPTCHA v3](https://developers.google.com/recaptcha/docs/v3)
- [Google reCAPTCHA Enterprise web integration](https://docs.cloud.google.com/recaptcha/docs/instrument-web-pages)

Checked-in synthetic fixtures cover positive, negative, ambiguous, and
regression cases. They run through the real HTTP analyzer without contacting
the referenced third parties. Every supported detector must comply with the
[detector family support standard](detector-support-standard.md).

## Document structure

```json
{
  "schema_version": 2,
  "rules": [
    {
      "id": "example.challenge",
      "name": "Example Challenge",
      "description": "Synthetic schema example.",
      "category": "captcha_challenge",
      "vendor": "Example",
      "product": "Challenge",
      "minimum_evidence": 2,
      "minimum_score": 60,
      "match": {
        "all": [
          {
            "signal": {
              "id": "challenge-script",
              "group": "static_integration",
              "description": "Product-specific script URL",
              "type": "script_url",
              "value": {
                "contains": "/challenge.js",
                "case_insensitive": true
              },
              "weight": 45
            }
          },
          {
            "any": [
              {
                "signal": {
                  "id": "challenge-frame",
                  "group": "browser_dom",
                  "type": "iframe_url",
                  "value": {
                    "prefix": "https://challenge.example/"
                  },
                  "weight": 40
                }
              },
              {
                "signal": {
                  "id": "challenge-cookie",
                  "group": "cookies",
                  "type": "cookie",
                  "key": {
                    "exact": "example_challenge"
                  },
                  "weight": 30
                }
              }
            ]
          }
        ]
      },
      "negative_evidence": [
        {
          "id": "origin-marker",
          "type": "response_header",
          "key": {
            "exact": "X-Origin",
            "case_insensitive": true
          },
          "weight": 20
        }
      ],
      "ambiguous_evidence": [
        {
          "id": "generic-proxy",
          "type": "response_header",
          "key": {
            "exact": "Via",
            "case_insensitive": true
          },
          "weight": 10
        }
      ],
      "requires": [
        "example.vendor"
      ],
      "conflicts": [
        {
          "rule_id": "other.challenge",
          "penalty": 25
        }
      ]
    },
    {
      "id": "example.vendor",
      "name": "Example Vendor",
      "category": "cdn_reverse_proxy",
      "vendor": "Example",
      "minimum_evidence": 1,
      "minimum_score": 50,
      "match": {
        "signal": {
          "id": "example-server",
          "group": "response_headers",
          "type": "response_header",
          "key": {
            "exact": "Server",
            "case_insensitive": true
          },
          "value": {
            "contains": "example",
            "case_insensitive": true
          },
          "weight": 50
        }
      }
    },
    {
      "id": "other.challenge",
      "name": "Other Challenge",
      "category": "captcha_challenge",
      "vendor": "Other",
      "product": "Challenge",
      "minimum_evidence": 1,
      "minimum_score": 60,
      "match": {
        "signal": {
          "id": "other-frame",
          "group": "browser_dom",
          "type": "iframe_url",
          "value": {
            "prefix": "https://challenge.other.example/"
          },
          "weight": 60
        }
      }
    }
  ]
}
```

The example is intentionally synthetic and is not a supported detector.

## Rule fields

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Unique lowercase identifier using letters, digits, `.`, `_`, or `-`. |
| `name` | Yes | Human-readable detection name. |
| `description` | No | Contributor-facing explanation of the rule. |
| `category` | Yes | One of the supported categories listed below. |
| `vendor` | Yes | Vendor or project represented by the rule. |
| `product` | No | Specific product. Omit it for a vendor-level rule. |
| `minimum_evidence` | Yes | Minimum number of distinct matched positive evidence groups. |
| `minimum_score` | Yes | Detection threshold from 25 through 100. |
| `match` | Yes | Positive signal condition tree. |
| `negative_evidence` | No | Matching signals whose weighted confidence is subtracted. |
| `ambiguous_evidence` | No | Matching signals whose weighted confidence is subtracted as ambiguity. |
| `requires` | No | Rules that must be detected before this rule can be detected. |
| `conflicts` | No | Directional fixed penalties activated by another candidate rule. |

V1 and V2 categories are `cdn_reverse_proxy`, `waf`, `bot_management`,
`captcha_challenge`, `client_fingerprinting`, and `third_party_security`.

Dependencies must reference rules in the same document and must form an acyclic
graph. A rule cannot both require and conflict with the same rule. A vendor-level
detection never creates a product detection: product rules require their own
positive evidence, and should declare a vendor dependency when that relationship
is necessary.

## Conditions and signal predicates

Every condition contains exactly one of:

- `signal`: one weighted signal predicate;
- `all`: a non-empty list in which every child must match;
- `any`: a non-empty list in which at least one child must match.

When several branches of a satisfied `any` condition match, all matched evidence
is retained for explanation. Only the strongest weighted observation in each
evidence group contributes to the score. Evidence identifiers must be unique
within a rule. A predicate selects the matching signal with the highest
observation confidence. Equal-confidence signals use a lexical comparison of
their normalized fields, so signal order cannot change the selected observation.

A positive signal predicate requires `id`, `type`, `weight`, and at least one of
`source`, `key`, `value`, or `url`. Its optional `group` is a lowercase
identifier with the same syntax as an evidence ID. When omitted, the evidence ID
forms its own independent group. Correlated predicates should explicitly share a
group such as `static_integration`; complementary channels can use groups such as
`browser_network`, `browser_dom`, `response_headers`, `cookies`, `dns`, or `tls`.
Group names describe scoring semantics rather than analyzer implementation and
are local to one rule.

Grouping is supported only for positive evidence. Negative and ambiguous
evidence remains additive and specifying `group` on either list is rejected.
Signal types must be valid normalized `SignalType` values. Weights are finite
numbers greater than zero and at most 100.

### DNS/TLS supporting evidence

The implemented DNS/TLS analyzer emits `dns_record` with key `cname` and
`tls_property` with keys `version`, `alpn`, `certificate_issuer`,
`certificate_subject`, or `certificate_dns_name`. Infrastructure properties are
generally weak, shared evidence. Give them their own correlation groups and
combine them with independent product-specific observations. For example:

```json
{
  "all": [
    {
      "signal": {
        "id": "documented-product-script",
        "group": "static_integration",
        "type": "script_url",
        "value": { "exact": "https://vendor.example/product.js" },
        "weight": 70
      }
    },
    {
      "signal": {
        "id": "supporting-edge-cname",
        "group": "dns",
        "type": "dns_record",
        "key": { "exact": "cname" },
        "value": { "suffix": ".edge.vendor.example" },
        "weight": 15
      }
    }
  ]
}
```

The CNAME alone contributes only 15 points and the `all` condition prevents it
from asserting the product without the documented integration. A shared vendor
CNAME or certificate must never be assigned enough weight to independently
claim that a particular WAF or bot-management product is active. Put correlated
certificate fields in one `tls` group so issuer, subject, and SAN variants do not
manufacture independent certainty.

### Browser evidence

The browser analyzer emits normalized signals under `browser_analyzer` in a
stable channel order:

- `network_request`: the uppercase HTTP method is the key and the cleaned
  request URL is the value;
- `network_response`: the key is `status`, the value is the decimal status, and
  the cleaned response URL is the signal URL;
- `page_content`: the key is `dom` and the bounded final DOM is the internal
  value;
- `script_url` and `iframe_url`: the key is `src` and the cleaned resource URL
  is the value;
- `cookie`: the cookie name is the key and the validated cookie domain is the
  value. A leading dot, when Chromium supplies one, is retained. Cookie values
  are discarded at the CDP boundary and never enter a signal.

Exact duplicates are removed and normalized fields are sorted before matching.
MIME and CDP resource types remain internal capture metadata and are not part of
this first normalized contract. Reporters never expose `page_content` or cookie
values. The built-in Turnstile and reCAPTCHA rules remain explicitly scoped to
`http_analyzer`; browser signatures require their own fixture-backed evidence
and scoring rationale before becoming supported detectors.

For example, a browser rule can match a request and its status-bearing response
without depending on internal MIME or resource-type fields:

```json
{
  "all": [
    {
      "signal": {
        "id": "challenge-request",
        "group": "browser_network",
        "type": "network_request",
        "source": { "exact": "browser_analyzer" },
        "key": { "exact": "POST" },
        "value": { "exact": "https://api.example/challenge" },
        "weight": 35
      }
    },
    {
      "signal": {
        "id": "challenge-response",
        "group": "browser_network",
        "type": "network_response",
        "source": { "exact": "browser_analyzer" },
        "key": { "exact": "status" },
        "value": { "exact": "403" },
        "url": { "exact": "https://api.example/challenge" },
        "weight": 35
      }
    }
  ]
}
```

Cookie-domain predicates can distinguish the same name set by the scanned host
from one set by a third-party frame. Malformed or unsafe domains are omitted
instead of rewritten into evidence. Reporters still suppress cookie domains.

Use distinct groups such as `browser_dom` or `browser_network` only for genuinely
independent evidence. A script URL present in both static HTML and browser
traffic is correlated observation of the same integration and must not be
counted twice merely because two analyzers observed it. Such predicates must
share one group even when their `source` predicates differ. A contributor who
uses separate groups must document why the observations represent genuinely
independent facts; analyzer identity alone is not that rationale. Regression
tests verify that identical HTTP and browser script observations contribute the
maximum of one shared group rather than two additive proofs.

### Coverage-sensitive negative results

Rules remain independent of Go analyzer implementations. The scanner derives
mandatory coverage from exact signal `source` predicates: `all` combines source
requirements, while `any` requires only sources common to every alternative.
Dependencies also contribute their source requirements. When a rule is not
detected and a mandatory source is partial, failed, or absent, report V4 emits
`insufficient_coverage` instead of `not_detected`. A partial source can still
produce a positive detection when its retained signals satisfy the rule.

Each selected signal field contains exactly one text operation:

- `exact`;
- `contains`;
- `prefix`;
- `suffix`;
- `regex`.

`case_insensitive` is optional and defaults to `false`. Regular expressions use
Go's bounded-backtracking-free RE2 syntax. Empty operands, invalid expressions,
unknown JSON fields, duplicate JSON object keys, duplicate rule or evidence
identifiers, unsupported schema versions, excessive nesting, and broken
cross-rule references are rejected.

## Matching and scoring

Matching retains positive, negative, ambiguous, and missing positive evidence so
later reporters can explain the outcome. A rule becomes a scoring candidate only
when its positive condition passes and at least `minimum_evidence` distinct
positive groups match. Correlated predicates therefore cannot satisfy an
independence requirement by themselves.

V2 calculates:

```text
raw evidence contribution = weight × observation confidence
group contribution = max(raw contribution for matched evidence in group)
positive = sum(group contributions)
negative = sum(negative weight × observation confidence)
ambiguous = sum(ambiguous weight × observation confidence)

evidence score = clamp(positive - negative - ambiguous
                       - active cross-rule penalties, 0, 100)
```

A cross-rule penalty is active when the referenced rule's positive condition and
minimum evidence match with non-zero effective confidence. This uses observed
conflicting evidence even if the referenced rule later misses its own score
threshold or dependency. Zero-confidence observations never activate a conflict.

Per-group maximum aggregation is deterministic, keeps every raw match available
for explanation, and bounds duplicate or correlated observations without hiding
them. If two predicates in a group have the same effective contribution, the
first predicate in rule order is selected for attribution; the group score does
not depend on that tie-break. Distinct groups remain additive, so complementary
runtime or protocol evidence can raise a static-only `high` result to
`very_high`.

The rule is detected when its evidence score reaches `minimum_score` and all
declared dependencies are detected. A missing dependency blocks the result and
sets its final score to zero while preserving `evidence_score` for explanation.

| Final score | Level |
| --- | --- |
| 90–100 | `very_high` |
| 75–89.999… | `high` |
| 50–74.999… | `medium` |
| 25–49.999… | `low` |
| 0–24.999… | `not_detected` |

The normalized signal's `confidence` is certainty in one observation. The final
detection confidence score measures the strength of grouped rule evidence after
penalties and dependencies. Neither value is a calibrated statistical
probability; a score of 82 means `82/100 — high`, not an estimated 82% chance that
the product is present.

## Resource limits and compatibility

Rule documents are limited to 1 MiB, 1,000 rules, 256 evidence predicates per
rule, 16 condition levels, and 2,048 bytes per text operand. These bounds make
local rule loading predictable and prevent pathological documents from consuming
unbounded memory or evaluation time.

`schema_version` is required. The current version is 2. The decoder also accepts
V1 documents, but V1 positive predicates cannot declare `group`, every predicate
contributes independently, and `minimum_evidence` counts matched predicates.
This preserves the contract understood by existing V1 decoders and scorers
instead of silently reinterpreting a V1 document.

V2 adds positive-evidence correlation groups, maximum-per-group aggregation, and
distinct-group `minimum_evidence`. A document using `group` must therefore set
`schema_version` to 2. Unknown versions are rejected rather than interpreted
approximately. Any future incompatible change requires another version.
