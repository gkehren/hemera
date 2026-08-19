# JSON report schema V3

`hemera scan --format json <url>` writes one JSON document to stdout. Input and
scan errors are written to stderr and do not enter the JSON document. The
top-level `schema_version` is the compatibility boundary; it is currently `3`.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Report contract version. |
| `tool_version` | string | Hemera binary version. |
| `requested_url` | string | Initial URL with query values masked. |
| `final_url` | string or null | Final observed HTTP URL with query values masked, or `null` when unavailable. |
| `http` | object or null | Final HTTP status, truncation, redirects, and warnings, or `null` when unavailable. |
| `analyzers` | array | Ordered analyzer coverage and sanitized warnings. |
| `detections` | array | One explained result for every embedded rule, in rule order. |

When HTTP metadata is available, the `http` object contains `status_code`,
`body_truncated`, `redirects`, and `warnings`. Redirect objects contain `from`,
`to`, and `status`. If no HTTP analyzer ran or an analyzer configured to continue
failed before producing HTTP metadata, both `http` and `final_url` are `null`;
the report never substitutes status `0` or an empty final URL.

Each `analyzers` entry contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `source` | string | Stable analyzer identity. |
| `status` | string | `complete`, `partial`, or `failed`. |
| `warnings` | string array | Producer-sanitized source-local warnings. |

Analyzer entries retain scanner configuration order. `complete` means the
analyzer returned without an error, even if it emitted warnings. `partial` means
an explicitly non-fatal local error left usable signals or typed metadata;
`failed` means that no usable observation was returned. Analyzer error text is
not serialized because it may contain attacker-controlled URLs or other
untrusted data. Fatal analyzer failures and caller cancellation produce no JSON
report and remain CLI errors on stderr.

HTTP analyzer warnings are mirrored in `http.warnings` so navigation diagnostics
remain colocated with the HTTP metadata as well as the generic coverage entry.
The current CLI emits `http_analyzer` followed by `dns_tls_analyzer`. A failed
CNAME lookup makes the latter `partial` when reused TLS signals remain, or
`failed` when no signal was available. DNS/TLS signal values appear only when a
detector matched them as evidence; the report does not otherwise add a raw
network-observation inventory.

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

Reporters never include page content, response-header and cookie values, or raw
analyzer error details. Analyzer producers must not place attacker-controlled
content or secrets in warning strings. Resource URLs are restricted to HTTP/HTTPS
and have user information, fragments, and query values removed or masked. Empty
arrays are encoded as `[]`, not `null`, to keep automation deterministic.
Matched DNS names and bounded TLS properties may be included as explanatory
evidence. Their producers reject control characters and bound certificate-derived
values before they reach reporting.

## Compatibility

Fields documented here use `snake_case`. Report V3 adds the required `analyzers`
array so partial multi-analyzer coverage is explicit and deterministic. It also
allows `final_url` and `http` to be `null` when HTTP observations are unavailable;
V2 always emitted a string and object because it only supported HTTP scans. V2
consumers must not interpret V3 as V2. Detection and scoring fields retain their
V2 semantics.

Report V2 was introduced because correlation changed the meaning of positive
evidence `contribution`: in V1 every matched predicate exposed its weighted
value, while V2 exposes zero for a non-selected correlated predicate and retains
that weighted value in `raw_contribution`. V2 also added positive evidence
`group` and `positive_evidence_groups`.

Consumers must dispatch on `schema_version`. The current CLI emits V3; it does
not offer an older output mode. Additive V3 fields may be introduced only when
existing consumers can safely ignore them. Removing a field, changing its
meaning or type, or changing the interpretation of existing values requires a
new `schema_version` and migration documentation.
