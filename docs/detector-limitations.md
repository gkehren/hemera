# Detector Limitations and Operational Boundaries

This document describes the operational limitations, blind spots, and detection
boundaries of every built-in detector rule across the 7 supported vendor
families. The authoritative rule inventory is maintained in
[`internal/detectors/rules.json`](../internal/detectors/rules.json) and summarized
in the [detector rule schema](detector-rules.md#built-in-detectors).

## 1. General Scanner Principles & Architectural Boundaries

Hemera is an open-source, passive-first security scanner. Its observations are
strictly governed by security and ethical requirements:

- **No Active Exploit or Attack Probing:** Hemera never sends malicious SQLi/XSS
  payloads or abnormal traversal sequences to trigger WAF blocks.
- **No Challenge Bypassing or Solving:** Hemera never solves CAPTCHAs, executes
  turnstile tokens, or spoofs browser fingerprints for evasion.
- **No Aggressive Crawling or DoS:** Request counts, concurrency, transferred
  bytes, and total time are bounded.

Consequently, Hemera's detectors rely on observable, public signals:
1. Standard response headers emitted on benign or challenge responses;
2. Client-side SDK script and iframe URLs;
3. Standard DOM markup (challenge widgets, error wrappers);
4. Diagnostic and session cookie names (never values);
5. Canonical DNS CNAME records and TLS certificate metadata.

---

## 2. Per-Detector Limitation Profiles

### 2.1 Cloudflare (`cloudflare.proxy`, `cloudflare.challenge_page`, `cloudflare.bot_protection`, `cloudflare.turnstile`)

#### `cloudflare.proxy` (Category: `cdn_reverse_proxy`)
- **Plan Tier Invisibility:** Cannot determine whether the domain is on Free, Pro, Business, or Enterprise tiers from public headers alone.
- **Header Stripping:** Enterprise customers using Cloudflare Workers or custom Transform Rules may strip or rename `Server: cloudflare` and `cf-ray`. In such cases, DNS CNAME (`*.cloudflare.net`, 30 points) and TLS certificate metadata (20 points) provide supporting corroboration (50 points total), remaining below the `minimum_score: 75` threshold unless paired with decisive headers.
- **No Product Implication:** Detecting `cloudflare.proxy` does *not* imply that WAF, Bot Protection, or Turnstile are active.

#### `cloudflare.challenge_page` (Category: `captcha_challenge`)
- **Product-Neutral Challenge Attribution:** `cf-mitigated: challenge` and challenge platform scripts indicate that a Cloudflare Challenge Page was served. They do *not* uniquely prove whether the challenge was triggered by WAF custom rules, Bot Fight Mode, Rate Limiting, DDoS mitigations, or Under Attack Mode.
- **Block / Error Pages are not Challenges:** Generic Cloudflare security error / block pages (e.g. error 1020 "Sorry, you have been blocked") provide supporting diagnostic evidence only and do not trigger `cloudflare.challenge_page`.
- **Passive-Only Visibility:** Sites that allow benign traffic without issuing an active challenge or security error code do not emit challenge mitigation headers.

#### `cloudflare.bot_protection` (Category: `bot_management`)
- **Tier Invisibility (Bot Fight Mode vs. Enterprise Bot Management):** JavaScript Detections (`/cdn-cgi/challenge-platform/scripts/jsd/(main|api).js`) and `__cf_bm` cookies are shared across Bot Fight Mode (free/pro), Super Bot Fight Mode (business), and Bot Management (enterprise). Hemera intentionally asserts `Bot Protection` rather than overclaiming the enterprise-tier product.
- **Server-Side-Only Bot Heuristics:** If bot protections are deployed solely via backend API rules without client-side JavaScript telemetry or cookies, they are invisible to passive analysis.

#### `cloudflare.turnstile` (Category: `captcha_challenge`)
- **Self-Hosted Proxy Wrappers:** If a website proxies the Turnstile client library through a first-party path (e.g. `/assets/turnstile.js`) to prevent ad-blocker filtering, passive HTTP analysis will not detect the script URL unless DOM markers (`cf-turnstile`) are present.
- **Post-Hydration Dynamic Loading:** In Single Page Applications (SPAs), if the Turnstile script and widget container are only created after user interaction (e.g. clicking a modal button), initial page analysis will not observe it.

---

### 2.2 Google reCAPTCHA (`google.recaptcha`)

#### `google.recaptcha` (Category: `captcha_challenge`)
- **Version Granularity:** Currently detects the presence of Google reCAPTCHA (v2, v3, invisible, and Enterprise) under a unified rule ID (`google.recaptcha`). It does not split into distinct product IDs for v2 vs. v3.
- **Server-Side Token Assessment:** reCAPTCHA v3 score-based validation occurs entirely on the customer backend (`siteverify` or Cloud API). If client scripts are masked or loaded through Google Tag Manager (GTM) dynamic triggers without DOM markers, passive HTML analysis may miss it until dynamic browser evaluation runs.
- **Alternate Hosts:** The rule supports the documented `www.google.com` and
  `www.recaptcha.net` API paths. Custom private reverse proxies and other hosts
  are not detected statically.

---

### 2.3 Amazon Web Services (`aws.cloudfront`, `aws.waf`)

#### `aws.cloudfront` (Category: `cdn_reverse_proxy`)
- **Upstream S3 Passthrough:** Direct Amazon S3 origin buckets emit `x-amz-request-id` and `x-amz-id-2`. Hemera specifically requires CloudFront headers (`x-amz-cf-id`, `x-amz-cf-pop`, `Server: CloudFront`) to avoid false positives.
- **Custom Header Masking:** CloudFront distributions configured with custom response header policies that remove `Server` and `x-amz-cf-id` rely on DNS CNAME (`*.cloudfront.net`, 30 points) and TLS certificate metadata (20 points), which provide supporting corroboration (50 points total) below the 75 threshold.

#### `aws.waf` (Category: `waf`)
- **ALB / API Gateway Backend WAFs:** AWS WAF deployed on Application Load Balancers or API Gateways that inspect traffic silently in `Count` or `Allow` mode emit no public headers on benign requests.
- **Passive Non-Interference:** Unless the site integrates the AWS WAF JavaScript SDK (`awswaf.com/.../sdk.js`), emits `x-amzn-waf-action`, or serves a standard 405/403 block interstitial, AWS WAF is invisible to passive analysis.

---

### 2.4 DataDome (`datadome.bot_protection`)

#### `datadome.bot_protection` (Category: `bot_management`)
- **Server-Side API Enforcer Mode:** DataDome modules running on NGINX/HAProxy or cloud middleware that only inspect backend requests and do not inject the client-side JavaScript tag (`js.datadome.co/tags.js` or `js.datadome.co/vX.Y.Z/tags.js`), `x-datadome` headers, or CAPTCHA delivery iframes cannot be detected on benign requests.
- **First-Party JS Tag & Reverse Proxy Aliases:** Deployments serving the JavaScript tag under custom first-party domains (e.g. `https://<first_party_domain>/tags.js` or `https://<first_party_domain>/vX.Y.Z/tags.js`) or via reverse-proxy aliases are known false negatives for script-URL matching. Detection may still succeed when another decisive DataDome signal is present (such as `x-datadome` response headers or challenge interstitials); the `datadome` cookie remains supporting evidence only (score 40) and cannot trigger detection by itself.
- **Cookie Ambiguity Protection:** A standalone `datadome` cookie alone only awards a score of 40 (Low confidence), deliberately below the 75 threshold, to prevent false positives from stale cookies.

---

### 2.5 Akamai Technologies (`akamai.edge`, `akamai.bot_manager`)

#### `akamai.edge` (Category: `cdn_reverse_proxy`)
- **Header Sanitization:** Enterprise edge configurations that strip `Server: AkamaiGHost` and `x-akamai-transformed` rely on DNS CNAME (`*.edgekey.net`, `*.akamaiedge.net`, `*.edgesuite.net`) or TLS certificate issuer verification.
- **Prerequisite Role:** `akamai.edge` serves as an infrastructure prerequisite (`requires: ["akamai.edge"]`) for Akamai Bot Manager.
- **Debugging & Variable Headers:** `x-akamai-session-info` is an Akamai Property Manager variable exposure mechanism and serves as supporting Edge infrastructure evidence without implying product-level activation.
- **Generic Reference Error Pages:** Akamai Edge Reference Error pages (`Access Denied` + `Reference #18...`) and Global Request Numbers are generic Edge Diagnostics mechanisms shared across edge configurations and products, and are not treated as specific WAF product signatures.

#### `akamai.bot_manager` (Category: `bot_management`)
- **API-Only Endpoint Protections:** Backend API protections running without Akamai client sensor scripts (`/_sec/verify.js`, `/akam/13/`) or `_abck` cookies cannot be detected passively.
- **Dynamic Sensor Obfuscation:** Custom sensor paths generated per-customer require correlation with `_abck` telemetry cookies.

---

### 2.6 hCaptcha (`hcaptcha.challenge`)

#### `hcaptcha.challenge` (Category: `captcha_challenge`)
- **First-Party Script Proxies:** Sites proxying `js.hcaptcha.com` through an internal domain without `h-captcha` DOM containers are not detected statically.
- **Dynamic Post-Interaction Rendering:** SPAs that inject the hCaptcha script only upon form submission or checkout validation will not be observed on static page fetch.

---

### 2.7 Arkose Labs (`arkoselabs.matchkey`)

#### `arkoselabs.matchkey` (Category: `captcha_challenge`)
- **Custom Client API Hostnames:** Arkose MatchKey allows enterprise customers to configure custom CNAME subdomains for `client-api.arkoselabs.com`. If configured under a custom domain without `arkose-enforcement` DOM markers or `setupArkose` callbacks, static HTTP detection will not observe it.
- **Server-Side Verify Mode:** Verification performed exclusively via backend API without client challenge frames on initial page view is invisible passively.

---

## 3. Summary Matrix of Limitations

| Detector Rule | Primary Limitation | Evasion / Masking Vector | Mitigation in Hemera |
| --- | --- | --- | --- |
| `cloudflare.proxy` | Plan tier invisibility | Strip `Server` / `cf-ray` | Fallback to DNS CNAME / TLS |
| `cloudflare.challenge_page` | Generic challenge (not WAF-specific) | Custom origin error pages | Matches official challenge headers & DOM |
| `cloudflare.bot_protection` | Shared tier telemetry (not enterprise-only) | No JS telemetry / no cookie | Matches JSD telemetry script & `__cf_bm` |
| `cloudflare.turnstile` | Invisible if dynamically loaded | First-party script proxy | DOM marker correlation (`cf-turnstile`) |
| `google.recaptcha` | Unified rule across v2/v3/Enterprise | Masked via GTM tag | Supports alternate hosts & DOM markers |
| `aws.cloudfront` | Upstream S3 header passthrough | Strip `Server` header | Exact CloudFront header matching & DNS |
| `aws.waf` | Invisible in silent ALB/API mode | No client SDK embedded | Matches SDK, action headers, block pages |
| `datadome.bot_protection` | Invisible in server-only or first-party alias mode | Masked JS tag | Requires JS tag (unversioned/versioned), header, or cookie |
| `akamai.edge` | Stripped `Server: AkamaiGHost` | Custom edge rules | Fallback to DNS CNAME / TLS |
| `akamai.bot_manager` | Invisible on API-only endpoints | Obfuscated sensor path | Correlation with `_abck` cookie |
| `hcaptcha.challenge` | Invisible if dynamically rendered | First-party reverse proxy | DOM container matching (`h-captcha`) |
| `arkoselabs.matchkey` | Invisible on custom subdomains | Custom CNAME wrapper | DOM wrapper and callback matching |
