# JSON report schema V1

`hemera scan --format json <url>` writes one JSON document to stdout. Input and
scan errors are written to stderr and do not enter the JSON document. The
top-level `schema_version` is the compatibility boundary; it is currently `1`.

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
evidence, missing evidence and dependencies, and applied conflict penalties.
Evidence includes its rule identifier, signal type/source/key, observation
confidence, weight, and signed score contribution.

## Data minimization

Reporters never include page content or response-header and cookie values.
Resource URLs are restricted to HTTP/HTTPS and have user information, fragments,
and query values removed or masked. Empty arrays are encoded as `[]`, not
`null`, to keep automation deterministic.

## Compatibility

Fields documented here use `snake_case`. Additive V1 fields may be introduced
only when existing consumers can safely ignore them. Removing a field, changing
its meaning or type, or changing the interpretation of existing values requires
a new `schema_version` and migration documentation.
