# JSON report schema V6

`hemera scan --format json <url>` writes one JSON document to stdout. Input and
scan errors are written to stderr and do not enter the JSON document. The
top-level `schema_version` is mandatory and is currently `6`.

> **Compatibility status: experimental.** Hemera has not published its first
> stable release. JSON is the versioned automation interface, but the current
> schema does not yet carry a permanent public compatibility or support promise.
> Consumers must inspect `schema_version` rather than assume a particular shape.

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
The current CLI emits `http_analyzer`, `dns_tls_analyzer`, then
`browser_analyzer`. A failed CNAME lookup makes DNS/TLS `partial` when reused TLS
signals remain, or `failed` when no signal was available. A browser startup or
navigation failure is likewise `partial` when normalized signals survived and
`failed` otherwise. Both analyzers use a continue policy, while HTTP and caller
cancellation remain fatal. DNS/TLS and browser signal values appear only when a
detector matched them as evidence; the report does not otherwise add a raw
network-observation inventory. `final_url` remains the final HTTP URL rather
than a browser redirect field.

Each detection contains identity fields, `detected`, `status`,
`incomplete_sources`, the matching gates, `evidence_score`, final `score`,
`level`, grouped positive/negative/ambiguous evidence,
`positive_evidence_groups`, missing evidence and dependencies, and applied
conflict penalties.

`status` is one of `detected`, `not_detected`, or `insufficient_coverage`.
`not_detected` is emitted only when observation coverage was sufficient to
conclusively prove that the detection criteria (`minimum_score`,
`minimum_evidence`, and prerequisites) could not be satisfied.
`insufficient_coverage` means the rule was not detected, but the upper bound of
potential evidence achievable from incomplete observation capabilities could
have satisfied `minimum_score`, `minimum_evidence`, and prerequisites;
`incomplete_sources` lists the stable source identities of those incomplete
capabilities. A detected rule remains `detected` when retained evidence is
sufficient even if another part of an analyzer result was partial. The
`detected` boolean remains for convenient positive-result filtering, but
consumers must use `status` to distinguish a conclusive negative from
unavailable coverage.

Coverage completeness is evaluated per capability, not per analyzer. Analyzers
declare structured per-`SignalType` observation completeness derived from
bounded capture state; analyzer-wide success does not imply that every
detector-relevant signal capability is complete. An analyzer that declares any
capability coverage is capability-aware: signal types it does not declare are
never treated as complete, so an unobserved channel cannot inherit an
analyzer's execution success. For example, a response body
truncated at the HTTP ceiling leaves page-content and static-resource
capabilities incomplete while response headers remain complete, so a rule whose
decisive marker could sit beyond the truncation point becomes
`insufficient_coverage` instead of a false `not_detected`, while a rule that
depends only on complete headers stays conclusive. Incomplete capabilities that
a rule does not depend on never downgrade it.

Observation capabilities are derived per `SignalType` and explicit source
constraints in rule condition trees. Condition trees evaluate tri-state coverage
(`matched`, `not_matched`, `unknown`) taking into account scoring thresholds:
- An `all` condition short-circuits to conclusively `not_matched` when any branch
  is conclusively false, even if other branches are unknown.
- An `any` condition retains potential evidence from unknown branches even when
  a supporting branch matched; if the observed match is below `minimum_score` and
  an unknown branch could reach the threshold, coverage evaluates to
  `insufficient_coverage`.
- If the upper bound of achievable score or evidence groups cannot reach
  `minimum_score` or `minimum_evidence` (e.g. unknown evidence is in the same
  correlation group and cannot exceed the group's already observed maximum),
  coverage evaluates to `not_detected`.
- Rule dependencies propagate coverage uncertainty: if a required prerequisite
  is `insufficient_coverage`, dependent rules that could otherwise detect also
  become `insufficient_coverage`.

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
values before they reach reporting. Browser cookie signals internally use the
signal value for a validated cookie domain, never a cookie value; reporters
omit that provenance together with page content. Browser request and resource
URLs are sanitized again by the reporter before selected evidence is serialized.

## Compatibility

### Before the first stable release

The report is versioned from the beginning so consumers can reject or adapt to
incompatible output. During pre-release development:

- `schema_version` remains present in every JSON report;
- deterministic serialization and golden-fixture coverage remain required;
- additive changes are preferred when consumers can safely ignore them;
- field removal, type changes, and semantic changes are allowed only when an
  architecture requirement justifies them;
- every breaking change increments `schema_version` and updates this document,
  golden fixtures, and migration notes where useful;
- Hemera does not promise indefinite support or an output mode for historical
  pre-release schemas.

This policy permits deliberate schema evolution; it does not permit silently
changing the meaning of an existing schema version or making gratuitous breaking
changes.

### Schema history

Report V6 refines `status` and `incomplete_sources` from analyzer-level to
capability-level coverage. Analyzers now declare structured per-`SignalType`
observation completeness derived from bounded capture state, so a successful
analyzer observation with a truncated evidence channel (bounded HTTP body or
resource extraction, bounded browser DOM, request, response, script, iframe, or
cookie capture) no longer produces a false conclusive `not_detected` for
evidence beyond the truncation point; such rules become
`insufficient_coverage`. Incomplete capabilities that a rule does not depend on
do not downgrade it, and retained decisive evidence still detects. V5 consumers
must not interpret V6 as V5.

Report V5 refines detection `status` and `incomplete_sources` with score-aware,
capability-based condition coverage. An incomplete analyzer no longer causes
false `not_detected` when supporting evidence is observed alongside unobserved
decisive branches, and does not cause false `insufficient_coverage` when missing
sources could not reach the detection score or group threshold. V4 consumers
must not interpret V5 as V4.

Report V4 added detection `status` and `incomplete_sources`. This was a semantic
change because an unavailable mandatory observation source was no longer
presented as a definitive negative result. V3 consumers must not interpret V4
as V3.

Fields documented here use `snake_case`. Report V3 added the required `analyzers`
array so partial multi-analyzer coverage is explicit and deterministic. It also
allowed `final_url` and `http` to be `null` when HTTP observations are unavailable;
V2 always emitted a string and object because it only supported HTTP scans. V2
consumers must not interpret V3 as V2. Detection and scoring fields retain their
V2 semantics.

Report V2 was introduced because correlation changed the meaning of positive
evidence `contribution`: in V1 every matched predicate exposed its weighted
value, while V2 exposes zero for a non-selected correlated predicate and retains
that weighted value in `raw_contribution`. V2 also added positive evidence
`group` and `positive_evidence_groups`.

Consumers must dispatch on `schema_version`. The current CLI emits V6; it does
not offer an older output mode. An incompatible future report requires a new
`schema_version` even during pre-release development.

### First stable release

Before Hemera's first stable release, the project will define stronger public
compatibility guarantees for reports, rules, and the CLI. That policy will keep
schema-version dispatch and documented migrations for breaking report changes.
It will also define the support lifecycle for historical stable schemas if the
CLI supports more than one. This issue intentionally does not choose that
lifecycle in advance.

## Text output

The default text report is designed for people, not parsers. Its wording,
spacing, and presentation may change for readability without a JSON
`schema_version` increment. Scripts and integrations should use
`--format json` and dispatch on the reported schema version.
