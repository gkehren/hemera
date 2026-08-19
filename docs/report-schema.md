# JSON report schema V2

`hemera scan --format json <url>` writes one JSON document to stdout. Input and
scan errors are written to stderr and do not enter the JSON document. The
top-level `schema_version` is the compatibility boundary; it is currently `2`.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Report contract version. |
| `tool_version` | string | Hemera binary version. |
| `requested_url` | string | Initial URL with query values masked. |
| `final_url` | string | Final URL with query values masked. |
| `http` | object | Final status, truncation, redirects, and warnings. |
| `detections` | array | One explained result for every embedded rule, in rule order. |

The `http` object contains `status_code`, `body_truncated`, `redirects`, and
`warnings`. Redirect objects contain `from`, `to`, and `status`.

Each detection contains identity fields, `detected`, the matching gates,
`evidence_score`, final `score`, `level`, grouped positive/negative/ambiguous
evidence, `positive_evidence_groups`, missing evidence and dependencies, and
applied conflict penalties.

Every evidence item includes its rule identifier, signal type/source/key,
observation confidence, weight, `raw_contribution`, and `contribution`. Positive
evidence also includes `group`. `raw_contribution` is the predicate's weighted
observation before correlation. `contribution` is the amount actually included
in scoring: it is zero for a correlated positive predicate that was not the
maximum in its group, and remains the signed weighted penalty for negative or
ambiguous evidence.

Each `positive_evidence_groups` entry contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Rule-local correlation group identifier. |
| `evidence_ids` | string array | All matched positive predicates in the group. |
| `selected_evidence_id` | string | Predicate providing the maximum contribution. |
| `raw_contribution` | number | Sum of raw matched contributions, for explanation only. |
| `contribution` | number | Maximum contribution actually added to the positive score. |

The sum of positive group `contribution` values, less negative, ambiguous, and
conflict contributions, produces `evidence_score` after clamping for a scoring
candidate. When the positive condition or `minimum_evidence` gate fails, group
and evidence contributions are zero while `raw_contribution` still explains the
partial matches. A missing dependency sets final `score` to zero without erasing
`evidence_score`. Scores are confidence indicators on a 0–100 scale, not
calibrated probabilities.

## Data minimization

Reporters never include page content or response-header and cookie values.
Resource URLs are restricted to HTTP/HTTPS and have user information, fragments,
and query values removed or masked. Empty arrays are encoded as `[]`, not
`null`, to keep automation deterministic.

## Compatibility

Fields documented here use `snake_case`. Report V2 was introduced because
correlation changes the meaning of positive evidence `contribution`: in V1 every
matched predicate exposed its weighted value, while V2 exposes zero for a
non-selected correlated predicate and retains that weighted value in
`raw_contribution`. V2 also adds positive evidence `group` and
`positive_evidence_groups`.

Consumers must dispatch on `schema_version` instead of interpreting V2 as V1.
The current CLI emits V2; it does not offer a V1 output mode. Additive V2 fields
may be introduced only when existing consumers can safely ignore them. Removing
a field, changing its meaning or type, or changing the interpretation of existing
values requires a new `schema_version` and migration documentation.
