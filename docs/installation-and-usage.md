# Installation and usage guide

Hemera is an open-source web protection scanner. Given a target URL, it
observes publicly visible HTTP, DNS, TLS, DOM, and browser-network signals to
produce an explainable report of active protections (such as CDN/reverse
proxies, WAFs, bot management, CAPTCHAs, and client-side fingerprinting).

This guide provides instructions for installing the Hemera CLI, configuring the
browser analysis environment, executing scans, and integrating Hemera into
automation scripts and CI/CD pipelines.

---

## Prerequisites

- **Go:** Go 1.26 or later (with a standard toolchain).
- **Supported Operating Systems:** Linux (x86_64, arm64), macOS (Apple Silicon,
  Intel), Windows (x64).
- **Browser Analyzer (Recommended):** A locally installed Google Chrome or
  Chromium browser.
  - Hemera connects to Chromium via the Chrome DevTools Protocol (CDP) to
    observe dynamic DOM mutations, scripts, iframes, cookies, and network events.
  - Hemera runs Chromium in a strictly sandboxed, loopback-proxied environment
    and does not download or manage browser binaries automatically.
  - If Chromium is not installed or unavailable, Hemera continues the scan using
    HTTP and DNS/TLS analyzers, marking browser observation as failed in the
    report.

---

## Installation methods

### Method 1: Install with `go install`

Install the compiled binary directly into your `$GOPATH/bin` (or `~/go/bin`):

```sh
go install github.com/gkehren/hemera/cmd/hemera@latest
```

Ensure `$GOPATH/bin` is in your system `PATH`:

```sh
export PATH="$HOME/go/bin:$PATH"
hemera --version
```

### Method 2: Build from source

Clone the official repository and compile the binary:

```sh
git clone https://github.com/gkehren/hemera.git
cd hemera
go build -o hemera ./cmd/hemera
./hemera --help
```

You can optionally move the resulting executable to a system-wide directory:

```sh
sudo mv hemera /usr/local/bin/
```

### Method 3: Direct execution without installing

Run Hemera directly using the Go toolchain from the repository root:

```sh
go run ./cmd/hemera --help
go run ./cmd/hemera scan https://example.com/
```

---

## Configuring the browser analyzer

Hemera automatically searches standard system paths for a Chromium or Google
Chrome binary.

### Custom Chromium executable path

If Chromium is installed in a non-standard location or you wish to use a specific
binary (e.g. ungoogled-chromium or a testing build), set the
`HEMERA_CHROMIUM_PATH` environment variable:

```sh
export HEMERA_CHROMIUM_PATH="/usr/bin/chromium-browser"
hemera scan https://example.com/
```

### Sandboxing requirements

Hemera mandates that Chromium's system sandbox remains active:
- On Linux, unprivileged user namespaces or standard SUID sandboxes are required.
- Running Hemera as `root` without user namespaces or attempting to disable
  sandboxing will cause the browser analyzer initialization to fail.
- When browser analyzer initialization fails, the scan does not abort: HTTP and
  DNS/TLS analyzers proceed normally, and the report reflects
  `"status": "failed"` for `browser_analyzer` in the JSON output.

---

## CLI command reference

### Interactive mode

Run Hemera without arguments in a terminal to start the interactive scan
wizard. It asks for the scan mode (default or deep) and the target URL —
validated inline with the same policy the scanner enforces — shows live
per-analyzer progress, then prints a styled full report in the same visual
language as the progress view.

```text
Usage:
  hemera
```

The wizard starts only when both stdin and stdout are terminals. Piped or
scripted invocations print the classic help text instead, so automation is
never affected. Set `HEMERA_ACCESSIBLE=1` for an accessible, linear prompt
mode. Press `Ctrl+C` during the progress view to cancel the running scan.

### Root commands and flags

```text
Usage:
  hemera scan [--format text|json] [--deep] [--mode default|deep] <url>
  hemera [--help] [--version]

Options:
  -h, --help  Show this help message
  --version   Print the Hemera version
```

### Scan command

```text
Usage:
  hemera scan [--format text|json] [--deep] [--mode default|deep] <url>

Options:
  --deep      Enable deep scan with maximal observation budgets and timeouts
  --format    Report format: text (default) or json
  --mode      Scan mode: default or deep
  -h, --help  Show this help message
```

### Exit codes

Hemera CLI uses deterministic exit codes to facilitate script integration:

| Exit code | Meaning | Description |
| :---: | :--- | :--- |
| `0` | **Success** | The scan completed and the report was written to stdout. Detections and coverage states are detailed in the output. |
| `1` | **Scan / Runtime error** | A fatal network failure occurred (e.g. DNS resolution error, connection timeout, unreachable host) or writing the report failed. Details are written to stderr. |
| `2` | **Usage / Target error** | Invalid command-line arguments (unknown flag, missing URL, unsupported format) or an invalid/forbidden initial URL target (e.g. private/loopback IP, cloud metadata address, unsupported URL scheme). |

---

## Usage examples

### 1. Basic scan (Human-readable text report)

Run a scan against a target URL with standard text output on stdout:

```sh
hemera scan https://example.com/
```

Example text report output:

```text
Hemera scan report
Target: https://protected.example/
Final URL: https://protected.example/
HTTP status: 200

Detections:
  Cloudflare Turnstile  75.0  HIGH
    + turnstile-client-script: script_url https://challenges.cloudflare.com/turnstile/v0/api.js (raw 75.0; group static_integration)
    + turnstile-html-marker: page_content (raw 30.0; group static_integration)
    = group static_integration: 75.0 (105.0 raw; selected turnstile-client-script)
```

### 2. Machine-readable scan (JSON V5 report)

Generate a deterministic JSON document on stdout (suitable for redirection,
file storage, or pipe processing):

```sh
hemera scan --format json https://example.com/ > report.json
```

The JSON report follows the [JSON report schema V5](report-schema.md) specification:

```json
{
  "schema_version": 5,
  "tool_version": "dev",
  "requested_url": "https://example.com/",
  "final_url": "https://example.com/",
  "http": {
    "status_code": 200,
    "body_truncated": false,
    "redirects": [],
    "warnings": []
  },
  "analyzers": [
    {
      "source": "http_analyzer",
      "status": "complete",
      "warnings": []
    },
    {
      "source": "dns_tls_analyzer",
      "status": "complete",
      "warnings": []
    },
    {
      "source": "browser_analyzer",
      "status": "complete",
      "warnings": []
    }
  ],
  "detections": [
    {
      "rule_id": "cloudflare.turnstile",
      "name": "Cloudflare Turnstile",
      "vendor": "Cloudflare",
      "category": "captcha",
      "detected": false,
      "status": "not_detected",
      "incomplete_sources": [],
      "score": 0,
      "level": "NONE"
    }
  ]
}
```

---

## Automation and scripting with `jq`

Because `hemera scan --format json` writes clean JSON to stdout and diagnostics
to stderr, it integrates cleanly with `jq`.

### Filter detected protections

List all detected protections with their confidence score and confidence level:

```sh
hemera scan --format json https://example.com/ \
  | jq '.detections[] | select(.detected == true) | {rule_id, name, score, level}'
```

### Filter high-confidence detections

Select detections with score >= 70 or level `HIGH`:

```sh
hemera scan --format json https://example.com/ \
  | jq '.detections[] | select(.level == "HIGH" or .level == "CERTAIN") | {name, score, level}'
```

### Inspect analyzer execution status and warnings

Verify that all three analyzers (HTTP, DNS/TLS, Browser) ran completely without
errors:

```sh
hemera scan --format json https://example.com/ \
  | jq '.analyzers[] | {source, status, warnings}'
```

### Check for insufficient observation coverage

List rules whose detection status was uncertain due to partial or missing
analyzer observations:

```sh
hemera scan --format json https://example.com/ \
  | jq '.detections[] | select(.status == "insufficient_coverage") | {rule_id, name, incomplete_sources}'
```

---

## CI/CD and automation integration

### Shell script assertion

The following script scans an endpoint, validates exit codes, and fails if an
unexpected protection or high-risk configuration is found:

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="https://staging.example.com/"
REPORT_FILE="$(mktemp --suffix=.json)"
trap 'rm -f "$REPORT_FILE"' EXIT

echo "Scanning target: ${TARGET_URL}..."
if ! hemera scan --format json "${TARGET_URL}" > "${REPORT_FILE}"; then
  echo "Scan failed with runtime or usage error" >&2
  exit 1
fi

# Assert schema compatibility
SCHEMA_VERSION=$(jq -r '.schema_version' "${REPORT_FILE}")
if [ "${SCHEMA_VERSION}" -ne 5 ]; then
  echo "Unexpected JSON schema version: ${SCHEMA_VERSION}" >&2
  exit 1
fi

# Check for detected bot management or WAF
DETECTED_COUNT=$(jq '[.detections[] | select(.detected == true)] | length' "${REPORT_FILE}")
echo "Scan complete. Active protections detected: ${DETECTED_COUNT}"

jq -r '.detections[] | select(.detected == true) | " - \(.name) (\(.rule_id)): score \(.score) [\(.level)]"' "${REPORT_FILE}"
```

### GitHub Actions workflow step

Integrate Hemera into a GitHub Actions job with sandboxed Chromium pre-installed:

```yaml
name: Security Perimeter Scan

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 6 * * 1' # Weekly Monday scan

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - name: Install Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Install Hemera
        run: go install github.com/gkehren/hemera/cmd/hemera@latest

      - name: Run Hemera Scan
        run: |
          hemera scan --format json https://example.com/ > scan-report.json

      - name: Inspect Detections
        run: |
          jq '.detections[] | select(.detected == true)' scan-report.json

      - name: Archive Scan Report
        uses: actions/upload-artifact@v4
        with:
          name: hemera-scan-report
          path: scan-report.json
```

---

## Operational and safety boundaries

When using Hemera, keep the following operational rules in mind:

1. **Authorization:** Only scan targets that you own or have explicit
   authorization to assess.
2. **Passive and low-impact:** Hemera does not bypass CAPTCHAs, solve challenges,
   spoof fingerprints for evasion, send WAF attack payloads, or perform denial
   of service.
3. **Private-network protection:** Hemera automatically rejects scans targeting
   localhost, private RFC 1918/4193 subnets, link-local, multicast, and cloud
   metadata addresses (e.g. `169.254.169.254`). Initial targets violating this
   policy immediately exit with code `2`.
4. **Data minimization:** Scan reports never output cookie values, session
   tokens, authorization headers, or sensitive query parameters.
