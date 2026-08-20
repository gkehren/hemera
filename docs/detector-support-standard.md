# Detector family support standard

This document defines the mandatory support standard for all detector families
in Hemera. A detector family or rule is considered **supported** only when it
satisfies every requirement defined here and passes the automated enforcement
suite in `internal/detectors`.

## Purpose and principles

Hemera prioritizes **safety, detection accuracy, and explainability** over raw
coverage. A detector must never be added based on casual observation or
unverified heuristics. Every supported rule must be backed by reproducible
synthetic fixtures, clear evidence rationale, justified scoring thresholds, and
an explicit separation between vendor infrastructure and specific security
products.

## The 6 pillars of the support standard

Every supported detector family must fulfill the following six criteria:

```mermaid
flowchart TD
    subgraph SupportStandard["Detector Family Support Standard"]
        P1["1. Positive Fixtures<br/>Synthetic, hermetic &ge; threshold"]
        P2["2. Hard Negatives & Ambiguities<br/>Dormant code, docs, noise &lt; threshold"]
        P3["3. Known FPs & FNs<br/>Documented trade-offs & limitations"]
        P4["4. Evidence Rationale<br/>Decisive vs supporting signals & correlation groups"]
        P5["5. Scoring & Threshold Rationale<br/>Weights, minimum_score & minimum_evidence"]
        P6["6. Vendor vs Product Separation<br/>Infrastructure does not imply product"]
    end
```

### 1. Positive fixtures

- **Hermetic & synthetic:** Every rule must be accompanied by at least one
  synthetic positive test fixture in `internal/scanner/testdata/` (or
  `internal/browser/testdata/` for browser-specific rules). Fixtures must never
  depend on live third-party endpoints, external DNS, or remote CDNs.
- **Decisive verification:** The positive fixture must achieve a detection score
  equal to or exceeding `minimum_score`, produce the expected confidence level
  (e.g., `high` or `very_high`), and match all expected decisive evidence IDs.
- **Multi-source corroboration:** Where a rule supports multiple observation
  channels (HTTP, DNS/TLS, Browser), test fixtures must exercise both
  single-source and multi-source scenarios.

### 2. Hard negatives and ambiguous cases

- **Clean / unrelated pages:** Every rule must be tested against clean pages and
  pages containing unrelated security services to ensure the rule score remains
  0 (`not_detected`).
- **Ambiguous & supporting markers:** Fixtures must include scenarios where only
  supporting evidence is present (e.g., HTML class names or div markers without
  the decisive client script). The resulting score must strictly remain below
  `minimum_score` (`not_detected`).
- **Documentation & code snippet regression:** Fixtures must include pages that
  discuss or quote product markers in plain text or documentation (e.g. blog
  posts or tutorials), verifying that text tokens do not inadvertently trigger
  high-confidence detections.
- **Conflicting products:** Where applicable, ambiguous or competing signatures
  from other vendors must be tested to verify conflict penalties or directional
  disambiguation.

### 3. Known false positives and false negatives

- **Precision over recall:** Hemera explicitly favors low false-positive rates
  over broad recall. It is better to return `not_detected` on an obscured or
  heavily customized integration than to falsely claim a product is active on an
  innocent site.
- **Documented false positives:** Document any edge cases where non-product
  behavior could match rule patterns (e.g., custom reverse proxies reusing
  headers, static documentation sites).
- **Documented false negatives:** Document scenarios where the product is
  present but intentionally not detected (e.g., self-hosted script reverse
  proxies, dynamically loaded scripts rendered only after user interaction
  beyond the post-load window, custom CNAME white-labeling).

### 4. Documented evidence rationale

- **Vendor documentation provenance:** Every signal pattern must trace to
  official vendor documentation, public integration guides, or verified
  technical specifications. All built-in evidence items are cataloged in
  `internal/detectors/provenance.json` and validated by CI
  (`TestBuiltInRulesProvenanceAndRationale`).
- **Decisive vs. supporting evidence:**
  - **Decisive evidence:** A signal unique and specific enough to prove the
    product's presence (e.g., an official vendor API script URL from a dedicated
    domain). A decisive signal with observation confidence 1.0 reaches the
    `minimum_score` threshold.
  - **Supporting evidence:** A signal that indicates potential integration or
    provides corroboration but is not unique enough on its own (e.g., generic
    CSS class names, inline helper calls, shared CNAMEs, standard response
    headers). Supporting signals have weights below `minimum_score`.
- **Correlation group rationale:** Correlated signals that observe the same
  underlying integration fact from different angles or across multiple
  analyzers (e.g., static HTML script tag vs. browser network request for the
  same script) must share a correlation `group` (e.g., `static_integration`,
  `browser_network`). Within a group, only the maximum contribution is counted,
  preventing duplicate proof of the same fact.

### 5. Documented score and threshold rationale

- **Threshold levels:**
  - `minimum_score: 75` (`high`): Standard threshold for a single decisive
    product integration.
  - `minimum_score: 90` (`very_high`): Reserved for detections requiring
    corroboration across multiple independent evidence groups.
  - `minimum_score: 50` (`medium`): Used for vendor-level infrastructure or
    meaningful evidence with inherent ambiguity.
- **Evidence weights:**
  - Decisive signals: weight &ge; `minimum_score` (typically 75).
  - Supporting signals: weight 15–40 (strictly &lt; `minimum_score`).
  - Ambiguity and negative penalties: subtracted from positive contributions to
    suppress ambiguous or contradicted results.
- **Minimum evidence count:** `minimum_evidence` defines how many distinct
  evidence groups must match. For rules requiring multi-source corroboration,
  `minimum_evidence` must be &ge; 2.

### 6. Explicit vendor-level versus product-level separation

- **Vendor &ne; Product:** Infrastructure observations (such as `Server:
  cloudflare`, `Server: awselb`, CNAME to `.edgekey.net`, or vendor TLS
  certificates) prove only that a CDN, reverse proxy, or cloud hosting provider
  is present. They **never** prove that a specific WAF, Bot Management, or
  CAPTCHA product is active.
- **Rule categorization:**
  - Vendor-level infrastructure rules belong to `cdn_reverse_proxy` or
    `third_party_security` and have an empty `product` field.
  - Product-specific rules belong to `captcha_challenge`, `waf`, `bot_management`,
    or `client_fingerprinting` and must declare the specific `product` name.
- **Dependencies (`requires`):** Product rules that only function behind a
  specific vendor's infrastructure may declare a formal dependency on the
  vendor rule using `requires: ["<vendor>.<infrastructure>"]`. However, the
  product rule must still require its own product-specific positive evidence.

---

## Supported detector families

The following detector families currently meet the support standard:

### 1. Cloudflare Reverse Proxy (`cloudflare.proxy`)

- **Category:** `cdn_reverse_proxy`
- **Vendor:** `Cloudflare`
- **Product:** (Vendor-level infrastructure)
- **Rule ID:** `cloudflare.proxy`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `cloudflare-server-header` | `response_headers` | `response_header` | `Server: cloudflare` | 75 | Decisive | Standard Cloudflare edge proxy server banner. |
| `cloudflare-ray-header` | `response_headers` | `response_header` | `cf-ray` | 75 | Decisive | Unique Ray ID assigned by Cloudflare edge for request tracking. |
| `cloudflare-cache-header` | `response_headers` | `response_header` | `cf-cache-status` | 35 | Supporting | Edge caching diagnostic header. |
| `cloudflare-cname` | `dns` | `dns_record` | `cname` suffix `.cloudflare.net` or `.cdn.cloudflare.net` | 30 | Supporting | Canonical DNS edge routing record. |
| `cloudflare-cert-issuer` | `tls` | `tls_property` | `certificate_issuer` contains `Cloudflare` | 20 | Supporting | Universal SSL certificate issuer. |
| `cloudflare-clearance-cookie` | `cookies` | `cookie` | `cf_clearance` | 25 | Supporting | Edge clearance cookie. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- Either decisive header (`Server: cloudflare` or `cf-ray`) independently reaches 75 points.
- Supporting DNS/TLS and caching signals provide corroboration if headers are stripped.
- All response headers share the `response_headers` group so their contribution is `max(75, 75, 35) = 75`.

#### Vendor vs. product separation

- Detection of Cloudflare Reverse Proxy indicates edge infrastructure routing only. It does **not** imply that Cloudflare WAF, Cloudflare Bot Management, or Cloudflare Turnstile is active.

#### Fixture coverage

- **Positive:** `cloudflare-proxy-positive.html` &mdash; returns `Server: cloudflare` and `cf-ray` (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean page (`score: 0`, `detected: false`).
- **Ambiguous / supporting:** `ambiguous-markers.html` with `cf-cache-status: HIT` &mdash; (`score: 35`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Custom reverse proxies mirroring `Server: cloudflare` or proxying through Cloudflare without edge termination.
- **Known false negatives:** Complete white-labeling stripping `Server` and `cf-ray` headers on custom enterprise plans.

---

### 2. Cloudflare Challenge Page (`cloudflare.challenge_page`)

- **Category:** `captcha_challenge`
- **Vendor:** `Cloudflare`
- **Product:** `Challenge Page`
- **Rule ID:** `cloudflare.challenge_page`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `cloudflare-challenge-mitigated-header` | `response_headers` | `response_header` | `cf-mitigated: challenge` | 75 | Decisive | Cloudflare challenge mitigation header emitted on challenge responses ([Cloudflare docs](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)). |
| `cloudflare-challenge-script` | `static_integration` | `script_url` | `^https?://[^/]+/cdn-cgi/challenge-platform/h/[a-z]/orchestrate/chl_page/v1` | 75 | Decisive | Managed challenge orchestration script URL. |
| `cloudflare-challenge-error-header` | `response_headers` | `response_header` | `cf-error-code` | 35 | Supporting | Security error code header emitted on challenge or block responses. |
| `cloudflare-challenge-block-marker` | `static_integration` | `page_content` | `Attention Required! \| Cloudflare`, `Sorry, you have been blocked`, `cf-error-details`, or `cf-wrapper` | 35 | Supporting | Cloudflare block or error page DOM marker. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- `requires`: `["cloudflare.proxy"]` &mdash; Challenge pages are served by Cloudflare reverse proxy edge infrastructure.
- Either decisive signal (`cf-mitigated: challenge` or the orchestration script URL) reaches 75 points (`high`).
- Supporting error codes and block page markup provide 35 points each. Even when both are present on a generic block page without `cf-mitigated`, their sum is 70 points (`medium`), which remains below `minimum_score: 75` (`not_detected`).

#### Vendor vs. product separation & anti-overclaim

- Detection of Cloudflare Challenge Page indicates that a Cloudflare managed or interstitial challenge page was returned. It does **not** assert whether the challenge was triggered by WAF custom rules, Bot Fight Mode, Rate Limiting, DDoS protection, or Under Attack Mode.
- Generic Cloudflare security block / error pages (e.g. error 1020 "Sorry, you have been blocked") do **not** trigger `cloudflare.challenge_page`.

#### Fixture coverage

- **Positive:** `cloudflare-challenge-page.html` &mdash; 403 status with `cf-mitigated: challenge` and challenge orchestration script (`score: 100`, `level: very_high`, `detected: true`).
- **Hard negative (Clean origin):** `negative.html` &mdash; clean / unrelated page (`score: 0`, `detected: false`).
- **Hard negative (Block / error page):** `cloudflare-block-page.html` &mdash; 403 status with `cf-error-code: 1020` and block markup (`score: 70`, `level: medium`, `detected: false`).
- **Ambiguous (HTML markers only):** `ambiguous-markers.html` with proxy headers &mdash; (`score: 35`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Documentation pages quoting Cloudflare block page HTML verbatim without active challenge headers.
- **Known false negatives:** Silent protection rules that allow or log traffic without issuing a challenge or block page.

---

### 3. Cloudflare Bot Protection (`cloudflare.bot_protection`)

- **Category:** `bot_management`
- **Vendor:** `Cloudflare`
- **Product:** `Bot Protection`
- **Rule ID:** `cloudflare.bot_protection`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `cloudflare-bot-telemetry-script` | `static_integration` | `script_url` | `^https?://[^/]+/cdn-cgi/challenge-platform/scripts/jsd/(?:main\|api)\.js` | 75 | Decisive | JavaScript Detections (JSD) telemetry script used by Cloudflare Bot Fight Mode, Super Bot Fight Mode, and Bot Management ([Cloudflare docs](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/)). |
| `cloudflare-bot-cookie` | `cookies` | `cookie` | `__cf_bm` | 40 | Supporting | Bot score tracking cookie set on requests ([Cloudflare docs](https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/)). |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- `requires`: `["cloudflare.proxy"]` &mdash; Bot Protection operates on Cloudflare proxy infrastructure.
- The JSD telemetry script provides 75 points (`high`).
- The `__cf_bm` cookie alone provides 40 points (`low`), resulting in `not_detected` without telemetry script.

#### Vendor vs. product separation & anti-overclaim

- Requires both `cloudflare.proxy` presence and specific bot telemetry evidence. It proves that Cloudflare Bot Protection / JavaScript Detections are active, but does **not** overclaim enterprise-tier `Bot Management` entitlement over `Bot Fight Mode`.

#### Fixture coverage

- **Positive (Automated snippet):** `cloudflare-bot-protection-positive.html` &mdash; proxied page with `__cf_bm` cookie and `/cdn-cgi/challenge-platform/scripts/jsd/main.js` (`score: 100`, `level: very_high`, `detected: true`).
- **Positive (Manual API script):** `cloudflare-bot-protection-api.html` &mdash; proxied page with `/cdn-cgi/challenge-platform/scripts/jsd/api.js` (`score: 75`, `level: high`, `detected: true`).
- **Hard negative (Clean origin):** `negative.html` &mdash; clean page without telemetry or cookie (`score: 0`, `detected: false`).
- **Ambiguous (Cookie only):** `cloudflare-proxy-positive.html` with `__cf_bm` cookie only &mdash; (`score: 40`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Stale `__cf_bm` cookies after bot protection is disabled.
- **Known false negatives:** API endpoints protected by server-side bot heuristics without client-side JavaScript injection.

---

### 4. Cloudflare Turnstile (`cloudflare.turnstile`)

- **Category:** `captcha_challenge`
- **Vendor:** `Cloudflare`
- **Product:** `Turnstile`
- **Rule ID:** `cloudflare.turnstile`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `turnstile-client-script` | `static_integration` | `script_url` | `^https://challenges\.cloudflare\.com/turnstile/v0/api\.js` | 75 | Decisive | Documented Cloudflare Turnstile JavaScript API script location ([Cloudflare docs](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/)). |
| `turnstile-html-marker` | `static_integration` | `page_content` | `cf-turnstile` marker | 30 | Supporting | Standard container class name used for explicit and implicit widget rendering. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- The decisive script alone provides 75 points, meeting the `high` threshold.
- The HTML marker provides 30 points (`low`). When present alone, the rule score
  is 30, resulting in `not_detected`.
- Both signals share the `static_integration` correlation group. When both the
  script and HTML marker are present, the group contribution is `max(75, 30) =
  75`, correctly preventing static markup from inflating confidence to
  `very_high`.

#### Vendor vs. product separation

- Detection of Cloudflare Turnstile indicates client-side challenge integration
  only. It does **not** imply that Cloudflare CDN, Cloudflare WAF, or Cloudflare
  Bot Management is active on the origin domain.

#### Fixture coverage

- **Positive:** `turnstile-positive.html` &mdash; contains the official script
  and widget container (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean / unrelated page (`score: 0`,
  `detected: false`).
- **Ambiguous marker:** `ambiguous-markers.html` &mdash; contains `cf-turnstile`
  marker without script (`score: 30`, `level: low`, `detected: false`).
- **Documentation regression:** `documentation-regression.html` &mdash; mentions
  Turnstile in text without script (`score: 30`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Negligible. Text discussions without script tags
  only match the supporting marker (score 30 &lt; 75).
- **Known false negatives:** Custom self-hosted proxy scripts that mirror
  `api.js` to a first-party path without referencing
  `challenges.cloudflare.com`.

---

### 5. Google reCAPTCHA (`google.recaptcha`)

- **Category:** `captcha_challenge`
- **Vendor:** `Google`
- **Product:** `reCAPTCHA`
- **Rule ID:** `google.recaptcha`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `recaptcha-client-script` | `static_integration` | `script_url` | `^https://www\.(google\.com\|recaptcha\.net)/recaptcha/(api\|enterprise)\.js` | 75 | Decisive | Documented reCAPTCHA v2, v3, and Enterprise client API script locations ([Google docs](https://developers.google.com/recaptcha/docs/display), [Enterprise docs](https://docs.cloud.google.com/recaptcha/docs/instrument-web-pages)). |
| `recaptcha-html-marker` | `static_integration` | `page_content` | `g-recaptcha` marker | 30 | Supporting | Standard widget container class name for v2/Enterprise widgets. |
| `recaptcha-inline-call` | `static_integration` | `page_content` | `grecaptcha\.(execute\|render)\(` | 35 | Supporting | Client-side JavaScript API invocation pattern. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- The decisive script provides 75 points (`high`).
- Supporting markers provide 30 or 35 points (`low`). When present without the
  script, the score remains 30–35, resulting in `not_detected`.
- All three signals share the `static_integration` correlation group. When all
  signals match, the group contribution is `max(75, 30, 35) = 75`, preventing
  markup redundancy from inflating confidence to `very_high`.

#### Vendor vs. product separation

- Detection of Google reCAPTCHA indicates client-side CAPTCHA integration only.
  It does **not** imply that Google Cloud Armor, Google Cloud CDN, or other
  Google infrastructure is protecting the domain.

#### Fixture coverage

- **Positive (Standard):** `recaptcha-positive.html` &mdash; standard
  `google.com/recaptcha/api.js` script with `g-recaptcha` container (`score: 75`,
  `level: high`, `detected: true`).
- **Positive (Enterprise / Alternate Host):**
  `recaptcha-enterprise-regression.html` &mdash; `recaptcha.net/recaptcha/enterprise.js`
  integration (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean / unrelated page (`score: 0`,
  `detected: false`).
- **Ambiguous markers:** `ambiguous-markers.html` &mdash; contains `g-recaptcha`
  and inline `grecaptcha.render` without script (`score: 35`, `level: low`,
  `detected: false`).
- **Documentation regression:** `documentation-regression.html` &mdash; mentions
  reCAPTCHA in text without script (`score: 30`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Negligible. Static markers without the official API
  script reach at most score 35.
- **Known false negatives:** Custom self-hosted proxy scripts forwarding
  reCAPTCHA calls; dynamically loaded scripts injected via complex tag managers
  not present in initial HTML.
- **Current limitation:** Does not yet distinguish reCAPTCHA v2, v3, invisible,
  and Enterprise as separate product sub-rules.

---

### 6. Amazon CloudFront (`aws.cloudfront`)

- **Category:** `cdn_reverse_proxy`
- **Vendor:** `AWS`
- **Product:** (Vendor-level infrastructure)
- **Rule ID:** `aws.cloudfront`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `aws-cf-id-header` | `response_headers` | `response_header` | `x-amz-cf-id` | 75 | Decisive | Unique CloudFront request ID header assigned to every request ([AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/UnderstandingAttributesOfRequestAndResponse.html)). |
| `aws-cf-pop-header` | `response_headers` | `response_header` | `x-amz-cf-pop` | 75 | Decisive | CloudFront Edge POP identifier header. |
| `aws-cf-server-header` | `response_headers` | `response_header` | `Server: CloudFront` | 75 | Decisive | Standard CloudFront edge server banner. |
| `aws-cf-cache-header` | `response_headers` | `response_header` | `x-cache` contains `cloudfront` | 35 | Supporting | CloudFront edge caching diagnostic header. |
| `aws-cf-cname` | `dns` | `dns_record` | `cname` suffix `.cloudfront.net` | 30 | Supporting | Canonical CloudFront distribution CNAME record. |
| `aws-cf-cert-issuer` | `tls` | `tls_property` | `certificate_issuer` contains `Amazon` | 20 | Supporting | Amazon Trust Services TLS certificate issuer. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- Any decisive header (`x-amz-cf-id`, `x-amz-cf-pop`, `Server: CloudFront`) independently satisfies the 75-point threshold.
- All response headers share the `response_headers` group so their contribution is `max(75, 75, 75, 35) = 75`.

#### Vendor vs. product separation

- Detection of Amazon CloudFront indicates edge infrastructure routing only. It does **not** imply that AWS WAF or Shield Advanced is active on the distribution.

#### Fixture coverage

- **Positive:** `aws-cloudfront-positive.html` &mdash; returns `Server: CloudFront` and `x-amz-cf-id` (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean page (`score: 0`, `detected: false`).
- **Ambiguous / supporting:** `ambiguous-markers.html` &mdash; contains `x-cache: Hit from cloudfront` (`score: 35`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Reverse proxies forwarding `x-amz-cf-id` from upstream S3/CloudFront origins without edge termination.
- **Known false negatives:** Custom distributions with stripped `Server` and diagnostic headers.

---

### 7. AWS WAF (`aws.waf`)

- **Category:** `waf`
- **Vendor:** `AWS`
- **Product:** `AWS WAF`
- **Rule ID:** `aws.waf`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `aws-waf-sdk-script` | `static_integration` | `script_url` | `^https://[a-f0-9]+\.(awswaf\|waf\.aws\.amazon)\.com/` | 75 | Decisive | Documented AWS WAF JavaScript SDK client integration URL ([AWS docs](https://docs.aws.amazon.com/waf/latest/developerguide/waf-javascript-sdk.html)). |
| `aws-waf-action-header` | `response_headers` | `response_header` | `x-amzn-waf-action` | 75 | Decisive | AWS WAF rule action header emitted on challenge or block responses. |
| `aws-waf-errortype-header` | `response_headers` | `response_header` | `x-amzn-errortype` contains `WAF` | 35 | Supporting | AWS WAF error type header on blocked requests; supporting diagnostic signal. |
| `aws-waf-block-page` | `static_integration` | `page_content` | `405 Method Not Allowed.*AWS WAF` or `<title>403 Forbidden</title>.*AWS WAF` | 75 | Decisive | Standard AWS WAF default block page HTML content. |
| `aws-waf-token-cookie` | `cookies` | `cookie` | `aws-waf-token` | 40 | Supporting | AWS WAF client token cookie. |
| `aws-waf-marker` | `static_integration` | `page_content` | `aws-waf-` or `AwsWafIntegration` | 30 | Supporting | Client-side SDK configuration marker. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- The official SDK script, action header, or block page independently reaches 75 points (`high`).
- The `aws-waf-token` cookie alone provides 40 points (`low`), resulting in `not_detected` without decisive evidence.

#### Vendor vs. product separation

- Detection of AWS WAF requires explicit WAF SDK scripts, action headers, or block page DOM markers. `aws.cloudfront` alone never triggers `aws.waf`.

#### Fixture coverage

- **Positive:** `aws-waf-positive.html` &mdash; contains official SDK script and token cookie (`score: 100`, `level: very_high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean page (`score: 0`, `detected: false`).
- **Ambiguous / supporting:** `aws-cloudfront-positive.html` with token cookie alone (`score: 40`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Documentation pages describing AWS WAF error structures.
- **Known false negatives:** Passive WAF rules configured in `Count` mode without client-side token or mitigation headers.

---

### 8. DataDome (`datadome.bot_protection`)

- **Category:** `bot_management`
- **Vendor:** `DataDome`
- **Product:** `DataDome`
- **Rule ID:** `datadome.bot_protection`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `datadome-js-tag` | `static_integration` | `script_url` | `^https://js\.datadome\.co/(?:v[0-9]+\.[0-9]+\.[0-9]+/)?tags\.js(?:\?redacted)?$` | 75 | Decisive | Documented DataDome client-side JavaScript tag URL, supporting both unversioned and semver-versioned `vX.Y.Z/tags.js` paths ([DataDome docs](https://docs.datadome.co/docs/javascript-tag)). |
| `datadome-header` | `response_headers` | `response_header` | `x-datadome` | 75 | Decisive | DataDome protection status response header (`x-datadome: protected` or `x-datadome: bypass`). |
| `datadome-response-header` | `response_headers` | `response_header` | `x-datadome-response` | 75 | Decisive | DataDome mitigation response header emitted on challenge responses. |
| `datadome-interstitial-url` | `static_integration` | `iframe_url` | `^https://(?:[a-z0-9-]+\.)+captcha-delivery\.com/` | 75 | Decisive | DataDome interstitial response page iframe URL across official subdomains (`*.captcha-delivery.com`) for CAPTCHA, Device Check, and Block pages ([DataDome changelog](https://docs.datadome.co/changelog/change-needed-for-users-of-csp-directive-frame-src)). |
| `datadome-interstitial-script` | `static_integration` | `script_url` | `^https://ct\.captcha-delivery\.com/` | 75 | Decisive | DataDome response page script URL on documented script host `ct.captcha-delivery.com` ([DataDome docs](https://docs.datadome.co/docs/javascript-tag)). |
| `datadome-cookie` | `cookies` | `cookie` | `datadome` | 40 | Supporting | DataDome tracking cookie. |
| `datadome-marker` | `static_integration` | `page_content` | `window\.datadomeOptions` or `datadome\.init` | 35 | Supporting | Client-side tag initialization configuration. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- The official JavaScript tag (unversioned or semver-versioned), `x-datadome` header, or challenge iframe reaches 75 points (`high`).
- The `datadome` cookie alone provides 40 points (`low`), resulting in `not_detected` without decisive evidence.

#### Vendor vs. product separation

- DataDome is a standalone bot management product that can be deployed across any origin, CDN, or cloud provider without infrastructure dependency.

#### Fixture coverage

- **Positive:** `datadome-positive.html` &mdash; contains unversioned `js.datadome.co/tags.js` and `x-datadome: protected` (`score: 100`, `level: very_high`, `detected: true`).
- **Positive:** `datadome-versioned-positive.html` &mdash; contains versioned `js.datadome.co/v5.1.13/tags.js` (`score: 75`, `level: high`, `detected: true`).
- **Positive:** `datadome-interstitial-positive.html` &mdash; contains challenge delivery iframe on alternate host `ct.captcha-delivery.com` (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean page (`score: 0`, `detected: false`).
- **Hard negative:** `adversarial-lookalike-domains.html` &mdash; lookalike domains such as `captcha-delivery.com.attacker.example`, apex `captcha-delivery.com`, and invalid semver versions `v5.1/tags.js` / `v5.1.13.7/tags.js` (`score: 0`, `detected: false`).
- **Ambiguous / supporting:** `datadome cookie ambiguity` &mdash; `datadome` cookie alone (`score: 40`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Negligible.
- **Known false negatives:**
  - First-Party JS Tag integrations (`https://<first_party_domain>/tags.js` or `https://<first_party_domain>/vX.Y.Z/tags.js`) and first-party reverse-proxy aliases are known false negatives for script-URL matching. Detection may still succeed when another decisive signal is present (such as `x-datadome` response headers or challenge interstitials); the `datadome` cookie remains supporting evidence only and cannot trigger detection alone.
  - API-only protections using server-side SDKs without client-side JavaScript tags or response headers.

---

### 9. Akamai Edge (`akamai.edge`)

- **Category:** `cdn_reverse_proxy`
- **Vendor:** `Akamai`
- **Product:** (Vendor-level infrastructure)
- **Rule ID:** `akamai.edge`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `akamai-ghost-server-header` | `response_headers` | `response_header` | `Server: AkamaiGHost` or `Server: Ghost` | 75 | Decisive | Akamai Global Host (GHost) edge server banner ([Akamai community](https://community.akamai.com/)). |
| `akamai-transformed-header` | `response_headers` | `response_header` | `x-akamai-transformed` | 75 | Decisive | Akamai Edge optimization and transformation header. |
| `akamai-cname` | `dns` | `dns_record` | `cname` suffix `.edgekey.net`, `.edgesuite.net`, `.akamaiedge.net` | 75 | Decisive | Canonical Akamai edge hostname routing domains. |
| `akamai-request-id-header` | `response_headers` | `response_header` | `x-akamai-request-id` | 35 | Supporting | Edge request tracing identifier. |
| `akamai-cacheable-header` | `response_headers` | `response_header` | `x-check-cacheable` | 25 | Supporting | Akamai diagnostic caching header. |
| `akamai-session-info-header` | `response_headers` | `response_header` | `x-akamai-session-info` | 25 | Supporting | Akamai Property Manager user-defined variable and debugging response header ([Akamai TechDocs](https://techdocs.akamai.com/property-mgr/docs/user-defined-vars)). |
| `akamai-cert-issuer` | `tls` | `tls_property` | `certificate_issuer` contains `Akamai` | 20 | Supporting | Akamai Edge TLS certificate authority. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- `Server: AkamaiGHost`, `x-akamai-transformed`, or canonical CNAME routing independently reaches 75 points (`high`).

#### Vendor vs. product separation

- Detection of Akamai Edge indicates edge reverse proxy routing only. It does **not** imply that Akamai Bot Manager is active. Generic Property Manager variable headers (`x-akamai-session-info`) and generic Edge Diagnostics Reference Error strings (`Reference #18...` / Global Request Number) are infrastructure diagnostics and do not trigger product-level security detections.

#### Fixture coverage

- **Positive:** `akamai-edge-positive.html` &mdash; returns `Server: AkamaiGHost` and `x-akamai-transformed` (`score: 75`, `level: high`, `detected: true`).
- **Positive:** `akamai edge with session info` &mdash; returns `Server: AkamaiGHost` and `x-akamai-session-info` (`score: 75`, `level: high`, `detected: true`).
- **Positive:** `akamai edge reference error` &mdash; returns `Server: AkamaiGHost` and Reference Error block page (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean page (`score: 0`, `detected: false`).
- **Ambiguous / supporting:** `ambiguous-markers.html` &mdash; contains `x-check-cacheable: YES` (`score: 25`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Reverse proxies mirroring `Server: AkamaiGHost`.
- **Known false negatives:** Custom enterprise setups stripping `Server` and `x-akamai-transformed` headers.

---

### 10. Akamai Bot Manager (`akamai.bot_manager`)

- **Category:** `bot_management`
- **Vendor:** `Akamai`
- **Product:** `Bot Manager`
- **Rule ID:** `akamai.bot_manager`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `akamai-bm-sensor-script` | `static_integration` | `script_url` | `(?:^\|/)(_sec/verify\.js\|akam/13/\|akamai/bmp/)` | 75 | Decisive | Akamai Bot Manager client-side JavaScript sensor script URL ([Akamai docs](https://techdocs.akamai.com/bot-manager/docs/javascript-sensor)). |
| `akamai-bm-cookie` | `cookies` | `cookie` | `ak_bmsc`, `bm_sv`, `bm_sz` | 40 | Supporting | Akamai Bot Manager telemetry and session score cookies. |
| `akamai-bm-abck-cookie` | `cookies` | `cookie` | `_abck` | 40 | Supporting | Akamai Bot Manager sensor challenge tracking cookie. |
| `akamai-bm-marker` | `static_integration` | `page_content` | `window\._sec` or `akamai\.bmp` | 35 | Supporting | Client-side sensor initialization markup. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- `requires`: `["akamai.edge"]` &mdash; Bot Manager runs on Akamai edge infrastructure.
- The sensor script provides 75 points (`high`).
- Tracking cookies (`_abck`, `ak_bmsc`) provide 40 points (`low`), resulting in `not_detected` without the sensor script.

#### Vendor vs. product separation

- Requires both `akamai.edge` and Bot Manager-specific sensor scripts. An Akamai-proxied origin without Bot Manager does not trigger `akamai.bot_manager`.

#### Fixture coverage

- **Positive:** `akamai-bot-manager-positive.html` &mdash; proxied page with `/_sec/verify.js` and `_abck` cookie (`score: 100`, `level: very_high`, `detected: true`).
- **Hard negative:** `akamai-edge-positive.html` &mdash; proxied page with `_abck` cookie alone (`score: 40`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Negligible.
- **Known false negatives:** API endpoints protected by server-side Bot Manager without client-side sensor script injection.

---

### 11. hCaptcha (`hcaptcha.challenge`)

- **Category:** `captcha_challenge`
- **Vendor:** `hCaptcha`
- **Product:** `hCaptcha`
- **Rule ID:** `hcaptcha.challenge`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `hcaptcha-client-script` | `static_integration` | `script_url` | `^https://(?:js\.|assets\.)?hcaptcha\.com/(?:1/api\.js|c/)` | 75 | Decisive | Documented official hCaptcha client-side API script URL ([hCaptcha docs](https://docs.hcaptcha.com/configuration)). |
| `hcaptcha-challenge-iframe` | `static_integration` | `iframe_url` | `^https://(?:newassets\.)?hcaptcha\.com/captcha/` | 75 | Decisive | Official hCaptcha interactive challenge widget iframe URL. |
| `hcaptcha-html-marker` | `static_integration` | `page_content` | `h-captcha` | 30 | Supporting | Standard widget container class name. |
| `hcaptcha-inline-call` | `static_integration` | `page_content` | `hcaptcha\.(execute\|render\|reset)\(` | 35 | Supporting | Client-side JavaScript API invocation pattern. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- The official client script or challenge iframe provides 75 points (`high`).
- Supporting HTML markers and inline API invocations provide 30 or 35 points (`low`), resulting in `not_detected` without the official script.

#### Vendor vs. product separation

- Detection of hCaptcha indicates client-side CAPTCHA challenge integration only and does not imply underlying hosting, WAF, or CDN protections.

#### Fixture coverage

- **Positive:** `hcaptcha-positive.html` &mdash; contains official script and `h-captcha` container (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean page (`score: 0`, `detected: false`).
- **Ambiguous / supporting:** `ambiguous-markers.html` &mdash; contains `h-captcha` marker and `hcaptcha.render()` call without script (`score: 35`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Negligible. Static markup alone yields score 35.
- **Known false negatives:** Custom self-hosted proxy scripts forwarding hCaptcha verification payloads.

---

### 12. Arkose MatchKey (`arkoselabs.matchkey`)

- **Category:** `captcha_challenge`
- **Vendor:** `Arkose Labs`
- **Product:** `Arkose MatchKey`
- **Rule ID:** `arkoselabs.matchkey`

#### Evidence rationale

| Evidence ID | Group | Type | Pattern | Weight | Role | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `arkose-client-script` | `static_integration` | `script_url` | `^https://(?:[a-z0-9-]+\.)?(?:arkoselabs\.com\|funcaptcha\.com)/(?:v2/(?:[a-f0-9-]+/)?api\.js\|fc/api/\|client/)` | 75 | Decisive | Documented official Arkose Labs / FunCAPTCHA client API script URL ([Arkose Labs docs](https://developer.arkoselabs.com/)). |
| `arkose-challenge-iframe` | `static_integration` | `iframe_url` | `^https://(?:[a-z0-9-]+\.)?(?:arkoselabs\.com\|funcaptcha\.com)/fc/gc/` | 75 | Decisive | Official Arkose Labs challenge frame URL. |
| `arkose-html-marker` | `static_integration` | `page_content` | `arkose-enforcement`, `fc-token`, `arkose-matchkey` | 30 | Supporting | Standard widget container identifiers. |
| `arkose-inline-call` | `static_integration` | `page_content` | `(?:setupArkose\|arkose\.run\|myArkose)\(` | 35 | Supporting | Client-side initialization callback invocation. |

#### Scoring and threshold rationale

- `minimum_score`: 75 (`high`).
- `minimum_evidence`: 1 group.
- The official client script or challenge iframe provides 75 points (`high`).
- Supporting HTML markers and callback functions provide 30 or 35 points (`low`), resulting in `not_detected` without the script.

#### Vendor vs. product separation

- Detection of Arkose MatchKey indicates client-side challenge integration only and does not imply underlying hosting or WAF protections.

#### Fixture coverage

- **Positive:** `arkose-positive.html` &mdash; contains official client API script, container, and callback (`score: 75`, `level: high`, `detected: true`).
- **Hard negative:** `negative.html` &mdash; clean page (`score: 0`, `detected: false`).
- **Ambiguous / supporting:** `ambiguous-markers.html` &mdash; contains `arkose-enforcement` marker and `setupArkose()` call without script (`score: 35`, `level: low`, `detected: false`).

#### Known false positives and false negatives

- **Known false positives:** Negligible.
- **Known false negatives:** Custom proxy domains or enterprise deployments using fully self-hosted wrapper scripts.

---

## Contributor checklist for new detector families

When proposing a new detector family or adding rules to an existing family:

- [ ] **Rule schema compliance:** Valid JSON matching `schema_version: 2` with
  valid categories, regexes, and bounds.
- [ ] **Vendor vs. product separation:** Product rules declare `product` and
  require product-specific evidence; vendor rules do not claim products.
- [ ] **Evidence rationale documented:** Public documentation citations for every
  pattern, clear decisive vs. supporting roles, and justified correlation groups.
- [ ] **Scoring rationale documented:** Justified `minimum_score`, weights, and
  groupings.
- [ ] **Positive fixtures:** At least one hermetic positive fixture in
  `internal/scanner/testdata/` achieving `score >= minimum_score`.
- [ ] **Hard negative fixtures:** Clean page fixture producing `score: 0`.
- [ ] **Ambiguity / supporting-only fixtures:** Supporting markers alone must
  yield `score < minimum_score` and `detected: false`.
- [ ] **False positive / negative analysis:** Known limitations and trade-offs
  documented.
- [ ] **Automated test suite passes:** `go test ./...` and `internal/detectors`
  support standard tests pass without warnings.
