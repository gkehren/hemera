# Regression Corpus and Detector Accuracy Standards

This document defines the methodology, synthetic fixture corpus, accuracy metrics,
and catalog of known false positives and false negatives for Hemera's detector rules.

## 1. Synthetic Regression Corpus Methodology & Baseline

Hemera prioritizes detection accuracy and explainability above broad but unreliable
heuristics. To prevent regressions as rules evolve, every supported detector rule is
measured against a versioned synthetic regression corpus comprising:

- **Decisive positive fixtures** representing official, documented client SDKs, response headers, and challenge interstitials;
- **Adversarial lookalike fixtures** designed to trigger naive substring or domain matches;
- **Documentation & discussion fixtures** containing security terminology, error codes, and class names in inert text and pre/code blocks;
- **Direct origin fixtures** returning common non-CDN/WAF headers;
- **Commented-out and dormant fixtures** verifying that inert templates and script comments are ignored;
- **Multi-protection coexistence scenarios** verifying that multiple concurrent services (e.g. CloudFront + AWS WAF + reCAPTCHA) are detected independently without cross-talk.

### Synthetic Regression Corpus Baseline Metrics

The automated benchmark in `internal/detectors/accuracy_test.go` evaluates the 29-scenario synthetic regression corpus across all 12 built-in rules.

> [!WARNING]
> These metrics measure the versioned synthetic regression corpus only and are not estimates of real-world precision, recall, FPR, or FNR.

$$\text{False Positive Rate (FPR)} = \frac{\text{FP}}{\text{FP} + \text{TN}} = 0.0\%$$

$$\text{False Negative Rate (FNR)} = \frac{\text{FN}}{\text{FN} + \text{TP}} = 0.0\%$$

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = 100.0\%$$

$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}} = 100.0\%$$

| Rule ID | Category | Vendor | Product | Precision | Recall | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cloudflare.proxy` | `cdn_reverse_proxy` | Cloudflare | *(Infrastructure)* | 100.0% | 100.0% | 0.0% | 0.0% |
| `cloudflare.challenge_page` | `captcha_challenge` | Cloudflare | Challenge Page | 100.0% | 100.0% | 0.0% | 0.0% |
| `cloudflare.bot_protection` | `bot_management` | Cloudflare | Bot Protection | 100.0% | 100.0% | 0.0% | 0.0% |
| `cloudflare.turnstile` | `captcha_challenge` | Cloudflare | Turnstile | 100.0% | 100.0% | 0.0% | 0.0% |
| `google.recaptcha` | `captcha_challenge` | Google | reCAPTCHA | 100.0% | 100.0% | 0.0% | 0.0% |
| `aws.cloudfront` | `cdn_reverse_proxy` | AWS | *(Infrastructure)* | 100.0% | 100.0% | 0.0% | 0.0% |
| `aws.waf` | `waf` | AWS | AWS WAF | 100.0% | 100.0% | 0.0% | 0.0% |
| `datadome.bot_protection` | `bot_management` | DataDome | DataDome | 100.0% | 100.0% | 0.0% | 0.0% |
| `akamai.edge` | `cdn_reverse_proxy` | Akamai | *(Infrastructure)* | 100.0% | 100.0% | 0.0% | 0.0% |
| `akamai.bot_manager` | `bot_management` | Akamai | Bot Manager | 100.0% | 100.0% | 0.0% | 0.0% |
| `hcaptcha.challenge` | `captcha_challenge` | hCaptcha | hCaptcha | 100.0% | 100.0% | 0.0% | 0.0% |
| `arkoselabs.matchkey` | `captcha_challenge` | Arkose Labs | Arkose MatchKey | 100.0% | 100.0% | 0.0% | 0.0% |

---

## 2. Catalog of Known False Positive Vectors & Defenses

| False Positive Vector | Affected Products | Mechanism | Hemera Structural Defense |
| --- | --- | --- | --- |
| **Documentation / Discussion Quotes** | All rules | Security blogs, forum threads, or documentation pages mentioning header names (`cf-ray`, `x-amz-cf-id`), script URLs, or DOM classes (`g-recaptcha`, `h-captcha`). | Page content markers receive supporting-only weights (30–35), which remain below the `minimum_score: 75` threshold. Decisive script URLs and response headers are required for detection. |
| **Phishing / Lookalike Domains** | Turnstile, reCAPTCHA, DataDome, hCaptcha, Arkose | Malicious or deceptive pages loading lookalike URLs (e.g. `https://not-challenges.cloudflare.com/api.js`, `https://google.com.attacker.example/recaptcha/api.js`, `https://captcha-delivery.com.attacker.example/`). | Strict regex anchoring (`^https://`) with exact subdomain and domain boundaries prevents lookalike prefix/suffix hijacking. |
| **Direct Origin S3 Headers** | `aws.cloudfront` | S3 direct origin buckets emit `x-amz-request-id` and `x-amz-id-2` headers without CloudFront routing. | `aws.cloudfront` matches CloudFront-specific headers (`x-amz-cf-id`, `x-amz-cf-pop`, `Server: CloudFront`) rather than generic S3 bucket headers. |
| **Commented-Out or Inactive Markup** | All rules | Dead code, commented-out script tags (`<!-- <script src="..."></script> -->`), or JSON-LD schema descriptions. | `httpanalyzer` extracts script and iframe sources from valid DOM node attributes (`<script src>`, `<iframe src>`), ignoring HTML comments and schema text. |
| **Vendor Infrastructure Generalization** | `cloudflare.challenge_page`, `aws.waf`, `akamai.bot_manager`, etc. | Assuming that because a site uses Cloudflare, CloudFront, or Akamai CDN, it also has WAF or Bot Management active. | Strict **product-level separation**: vendor infrastructure rules (`cloudflare.proxy`, `aws.cloudfront`, `akamai.edge`) match routing headers, while product rules require explicit product evidence (SDKs, action headers, sensor scripts, block pages). |
| **Correlation Weight Inflation** | All rules | Sites containing multiple redundant supporting markers (e.g. 5 `g-recaptcha` divs and 3 inline calls). | Correlation groups (e.g. `static_integration`, `response_headers`) evaluate to $\max(\text{weights})$ rather than $\sum(\text{weights})$, preventing repetitive markup from reaching the detection threshold. |

---

## 3. Catalog of Known False Negative Vectors & Limitations

| False Negative Vector | Affected Products | Mechanism | Current Handling & Trade-offs |
| --- | --- | --- | --- |
| **Self-Hosted Reverse Proxy Wrappers** | Turnstile, reCAPTCHA, DataDome, hCaptcha, Arkose | Enterprises mirroring client SDK scripts to a first-party path (e.g. `/static/js/captcha.js`) to evade content blockers or ad-block lists. | **Known false negative.** URL predicates cannot identify an undocumented first-party wrapper. Browser capture can observe dynamic endpoints within its bounded navigation budgets, but the current Turnstile and reCAPTCHA rules intentionally accept only static HTTP evidence. |
| **Dynamic Post-Hydration Injection** | All client-side rules | Single Page Applications (SPAs) injecting CAPTCHA or bot sensor scripts dynamically after user interaction (e.g. on clicking "Submit") rather than on initial page load. | **Known false negative outside current capture and rule scope.** Browser capture observes work completed inside the bounded post-load window without simulating user interaction. Activity after that window or requiring interaction remains invisible, and the current Turnstile and reCAPTCHA rules do not consume Browser signals. |
| **API-Only Backend Protection** | `aws.waf`, `datadome.bot_protection`, `cloudflare.bot_protection` | API endpoints protected by server-side middleware without client-side HTML, headers, or cookies on benign requests. | **Known false negative.** Benign API requests returning standard JSON without custom security headers cannot be distinguished from unprotected origins without probing (which Hemera strictly avoids). |
| **Count / Monitor-Only Mode WAF Rules** | `aws.waf` | WAF rules configured in passive `Count` / `Monitor` mode that do not block requests, issue challenge pages, or attach diagnostic action headers. | **Known false negative.** Non-interfering passive monitoring emits no externally observable HTTP or DOM signals on public requests. |
| **Stripped Diagnostic Headers** | `cloudflare.proxy`, `aws.cloudfront`, `akamai.edge` | Custom enterprise edge distributions configured with `Server` masking and stripped diagnostic headers (`x-amz-cf-id`, `x-akamai-transformed`). | **Mitigated by DNS/TLS evidence.** Akamai Edge detects canonical edge CNAME records (`*.edgekey.net`, `*.akamaiedge.net`, 75 points); Cloudflare and CloudFront DNS CNAME and TLS certificates provide supporting corroboration (50 points). |

---

## 4. Regression Corpus Fixture Inventory

The regression suite in `internal/scanner/testdata/cases.json` contains 29 synthetic test cases:

1. `turnstile documented client` &mdash; `turnstile-positive.html`
2. `recaptcha documented client` &mdash; `recaptcha-positive.html`
3. `recaptcha enterprise alternate host regression` &mdash; `recaptcha-enterprise-regression.html`
4. `hcaptcha documented client` &mdash; `hcaptcha-positive.html`
5. `arkose matchkey documented client` &mdash; `arkose-positive.html`
6. `ambiguous static markers` &mdash; `ambiguous-markers.html`
7. `unrelated protection page` &mdash; `negative.html`
8. `documentation text regression` &mdash; `documentation-regression.html`
9. `cloudflare reverse proxy edge` &mdash; `cloudflare-proxy-positive.html`
10. `cloudflare challenge page` &mdash; `cloudflare-challenge-page.html`
11. `cloudflare generic block page` &mdash; `cloudflare-block-page.html`
12. `cloudflare bot protection telemetry` &mdash; `cloudflare-bot-protection-positive.html`
13. `cloudflare bot protection manual api` &mdash; `cloudflare-bot-protection-api.html`
14. `cloudflare challenge ambiguity` &mdash; `ambiguous-markers.html` with Cloudflare proxy headers
15. `aws cloudfront edge` &mdash; `aws-cloudfront-positive.html`
16. `aws waf sdk integration` &mdash; `aws-waf-positive.html`
17. `datadome bot protection` &mdash; `datadome-positive.html`
18. `datadome cookie ambiguity` &mdash; `negative.html` with DataDome cookie
19. `datadome versioned tag` &mdash; `datadome-versioned-positive.html`
20. `datadome alternate captcha delivery host` &mdash; `datadome-interstitial-positive.html`
21. `akamai edge proxy` &mdash; `akamai-edge-positive.html`
22. `akamai bot manager sensor` &mdash; `akamai-bot-manager-positive.html`
23. `akamai edge reference error` &mdash; `akamai-waf-positive.html`
24. `akamai edge with session info` &mdash; `negative.html` with `Server: AkamaiGHost` and `x-akamai-session-info`
25. `tech blog discussion` &mdash; `tech-blog-discussion.html` (adversarial discussion quotes)
26. `direct origin custom headers` &mdash; `direct-origin-custom-headers.html` (direct S3 & Apache)
27. `adversarial lookalike domains` &mdash; `adversarial-lookalike-domains.html` (phishing lookalikes)
28. `commented and dormant scripts` &mdash; `commented-and-dormant-scripts.html` (HTML comments & JSON-LD)
29. `multi-protection coexistence` &mdash; `multi-protection-coexistence.html` (CloudFront + AWS WAF + reCAPTCHA)

---

## 5. Future Real-World Validation Path

The current 29-scenario synthetic regression corpus is designed for fast, hermetic,
deterministic continuous integration to prevent regressions in rule semantics and
scoring logic. It does not replace empirical real-world validation.

A planned future validation benchmark (targeted for Milestone 3) will evaluate
Hemera against independently captured real-world targets:

```text
independently captured live samples
-> manually labelled ground-truth annotations
-> sanitized & redistributable dataset
-> isolated from rule-authoring synthetic fixtures
-> versioned empirical validation corpus
```

Key objectives for the future empirical validation dataset include:

- **100–300 labelled samples** covering top enterprise websites, public APIs, and government/e-commerce portals across all supported detector families;
- **Dedicated negative baselines** from unmanaged origins, non-protected cloud instances, and unrelated CDN/security infrastructure;
- **Custom and legacy enterprise deployments**, including first-party reverse-proxy script aliases and non-standard header topologies;
- **Independent capture isolation**, ensuring test targets were not authored specifically to satisfy internal rule regexes.

This empirical benchmark will remain separate from the hermetic CI regression corpus to ensure continuous integration tests remain fast, reproducible, and offline.
