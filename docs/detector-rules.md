# Detector rule schema V1

Hemera detector rules are strict, versioned JSON documents. The implementation
lives in `internal/rules`; matching consumes only normalized `pkg/model.Signal`
values and has no access to HTTP, DNS, TLS, Chromium, or reporters.

The V1 engine is implemented, but no built-in vendor detector is shipped yet and
`hemera scan` does not run rules. Detector files, CLI integration, and stable
report JSON belong to later roadmap steps.

## Document structure

```json
{
  "schema_version": 1,
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
| `category` | Yes | One of the V1 categories listed below. |
| `vendor` | Yes | Vendor or project represented by the rule. |
| `product` | No | Specific product. Omit it for a vendor-level rule. |
| `minimum_evidence` | Yes | Minimum number of matched positive predicates. |
| `minimum_score` | Yes | Detection threshold from 25 through 100. |
| `match` | Yes | Positive signal condition tree. |
| `negative_evidence` | No | Matching signals whose weighted confidence is subtracted. |
| `ambiguous_evidence` | No | Matching signals whose weighted confidence is subtracted as ambiguity. |
| `requires` | No | Rules that must be detected before this rule can be detected. |
| `conflicts` | No | Directional fixed penalties activated by another candidate rule. |

V1 categories are `cdn_reverse_proxy`, `waf`, `bot_management`,
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

When several branches of a satisfied `any` group match, all their independent
evidence contributes to the score. Evidence identifiers must be unique within a
rule. A predicate selects the matching signal with the highest observation
confidence; document and signal order break ties deterministically.

A signal predicate requires `id`, `type`, `weight`, and at least one of `source`,
`key`, `value`, or `url`. Its type must be a valid normalized `SignalType`.
Weights are finite numbers greater than zero and at most 100.

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
when its positive condition and `minimum_evidence` both pass.

V1 calculates:

```text
positive = sum(positive weight × observation confidence)
negative = sum(negative weight × observation confidence)
ambiguous = sum(ambiguous weight × observation confidence)

evidence score = clamp(positive - negative - ambiguous
                       - active cross-rule penalties, 0, 100)
```

A cross-rule penalty is active when the referenced rule's positive condition and
minimum evidence match with non-zero effective confidence. This uses observed
conflicting evidence even if the referenced rule later misses its own score
threshold or dependency. Zero-confidence observations never activate a conflict.

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

Scores are deliberately simple in V1. They are not calibrated probabilities.

## Resource limits and compatibility

Rule documents are limited to 1 MiB, 1,000 rules, 256 evidence predicates per
rule, 16 condition levels, and 2,048 bytes per text operand. These bounds make
local rule loading predictable and prevent pathological documents from consuming
unbounded memory or evaluation time.

`schema_version` is required. Incompatible schema changes require a new version;
unknown versions are rejected rather than interpreted approximately.
