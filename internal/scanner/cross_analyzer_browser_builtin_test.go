//go:build browser_integration

package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/analysis"
	"github.com/gkehren/hemera/internal/browser"
	"github.com/gkehren/hemera/internal/detectors"
	"github.com/gkehren/hemera/internal/httpanalyzer"
	"github.com/gkehren/hemera/internal/scoring"
)

func TestBrowserAnalyzerDynamicInjectionBuiltInRules(t *testing.T) {
	ruleSet, err := detectors.Load()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		htmlContent     string
		headers         map[string]string
		cookies         []*http.Cookie
		wantRuleID      string
		wantScore       float64
		wantDetected    bool
		wantLevel       scoring.Level
		wantEvidenceIDs []string
	}{
		{
			name: "Dynamic hCaptcha script and container injection in Browser",
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>hCaptcha Dynamic Test</title></head>
<body>
<div id="target"></div>
<script>
  setTimeout(() => {
    const s = document.createElement('script');
    s.src = 'https://js.hcaptcha.com/1/api.js';
    document.head.appendChild(s);
    const container = document.createElement('div');
    container.className = 'h-captcha';
    container.setAttribute('data-sitekey', '10000000-ffff-ffff-ffff-000000000001');
    document.getElementById('target').appendChild(container);
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "hcaptcha.challenge",
			wantScore:       75,
			wantDetected:    true,
			wantLevel:       scoring.LevelHigh,
			wantEvidenceIDs: []string{"hcaptcha-client-script"},
		},
		{
			name: "Dynamic Arkose Labs script and challenge iframe in Browser",
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>Arkose Dynamic Test</title></head>
<body>
<script>
  setTimeout(() => {
    const s = document.createElement('script');
    s.src = 'https://client-api.arkoselabs.com/v2/api.js';
    document.head.appendChild(s);
    const f = document.createElement('iframe');
    f.src = 'https://client-api.arkoselabs.com/fc/api/?token=synthetic_arkose_token';
    document.body.appendChild(f);
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "arkoselabs.matchkey",
			wantScore:       75,
			wantDetected:    true,
			wantLevel:       scoring.LevelHigh,
			wantEvidenceIDs: []string{"arkose-client-script"},
		},
		{
			name: "DataDome interstitial iframe, DOM and cookie in Browser",
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>DataDome Dynamic Test</title></head>
<body>
<script>
  window.datadomeOptions = { version: "4.6.0" };
  setTimeout(() => {
    const f = document.createElement('iframe');
    f.src = 'https://geo.captcha-delivery.com/captcha/?initialCid=AHrlqAAAAAMAx_example_interstitial';
    document.body.appendChild(f);
    document.cookie = 'datadome=AHrlqAAAAAMAx_example_token; path=/';
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "datadome.bot_protection",
			wantScore:       100,
			wantDetected:    true,
			wantLevel:       scoring.LevelVeryHigh,
			wantEvidenceIDs: []string{"datadome-interstitial-url", "datadome-cookie"},
		},
		{
			name: "Akamai Bot Manager sensor script and cookie with HTTP edge prerequisite",
			headers: map[string]string{
				"Server": "AkamaiGHost",
			},
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>Akamai Bot Manager Test</title></head>
<body>
<script>
  setTimeout(() => {
    const s = document.createElement('script');
    s.src = '/akam/13/sensor.js';
    document.head.appendChild(s);
    document.cookie = '_abck=synthetic_abck_token~0~YAAQ; path=/';
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "akamai.bot_manager",
			wantScore:       100,
			wantDetected:    true,
			wantLevel:       scoring.LevelVeryHigh,
			wantEvidenceIDs: []string{"akamai-bm-sensor-script", "akamai-bm-abck-cookie"},
		},
		{
			name: "Cloudflare Challenge Page script and DOM in Browser with edge prerequisite",
			headers: map[string]string{
				"Server": "cloudflare",
			},
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>Cloudflare Challenge Dynamic Test</title></head>
<body>
<div id="cf-wrapper">
  <div id="cf-error-details"></div>
</div>
<script>
  setTimeout(() => {
    const s = document.createElement('script');
    s.src = '/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1/flow.js';
    document.head.appendChild(s);
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "cloudflare.challenge_page",
			wantScore:       75,
			wantDetected:    true,
			wantLevel:       scoring.LevelHigh,
			wantEvidenceIDs: []string{"cloudflare-challenge-script"},
		},
		{
			name: "Cloudflare Bot Protection telemetry script and cookie in Browser with edge prerequisite",
			headers: map[string]string{
				"Server": "cloudflare",
			},
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>Cloudflare Bot Protection Dynamic Test</title></head>
<body>
<script>
  setTimeout(() => {
    const s = document.createElement('script');
    s.src = '/cdn-cgi/challenge-platform/scripts/jsd/main.js';
    document.head.appendChild(s);
    document.cookie = '__cf_bm=synthetic_cf_bm_token; path=/';
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "cloudflare.bot_protection",
			wantScore:       100,
			wantDetected:    true,
			wantLevel:       scoring.LevelVeryHigh,
			wantEvidenceIDs: []string{"cloudflare-bot-telemetry-script", "cloudflare-bot-cookie"},
		},
		{
			name: "AWS WAF SDK script, marker and cookie in Browser",
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>AWS WAF Dynamic Test</title></head>
<body>
<div id="aws-waf-container"></div>
<script>
  setTimeout(() => {
    const s = document.createElement('script');
    s.src = 'https://123456abcdef.awswaf.com/sdk.js';
    document.head.appendChild(s);
    document.cookie = 'aws-waf-token=synthetic_token; path=/';
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "aws.waf",
			wantScore:       100,
			wantDetected:    true,
			wantLevel:       scoring.LevelVeryHigh,
			wantEvidenceIDs: []string{"aws-waf-sdk-script", "aws-waf-token-cookie"},
		},
		{
			name: "Cloudflare Proxy clearance cookie in Browser",
			htmlContent: `<!DOCTYPE html>
<html>
<head><title>Cloudflare Proxy Clearance Cookie Test</title></head>
<body>
<script>
  setTimeout(() => {
    document.cookie = 'cf_clearance=synthetic_clearance_token; path=/';
  }, 50);
</script>
</body>
</html>`,
			wantRuleID:      "cloudflare.proxy",
			wantScore:       25,
			wantDetected:    false,
			wantLevel:       scoring.LevelLow,
			wantEvidenceIDs: []string{"cloudflare-clearance-cookie"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				for _, c := range tc.cookies {
					http.SetCookie(w, c)
				}
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = w.Write([]byte(tc.htmlContent))
					return
				}
				// Mock responses for sensor/script endpoints so browser does not fail network requests
				w.Header().Set("Content-Type", "application/javascript")
				_, _ = w.Write([]byte("/* mock script */"))
			}))
			defer server.Close()

			localURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}

			resolver := fixtureResolver(func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			})
			dialer := func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, localURL.Host)
			}

			httpConfig := httpanalyzer.DefaultConfig()
			httpConfig.Resolver = resolver
			httpConfig.Dialer = dialer
			httpAnalyzer, err := httpanalyzer.New(httpConfig)
			if err != nil {
				t.Fatal(err)
			}

			browserConfig := browser.DefaultConfig()
			browserConfig.StartupTimeout = 20 * time.Second
			browserConfig.PostLoadTimeout = 1500 * time.Millisecond
			browserPath, explicitBrowser := integrationBrowserPath(t)
			browserConfig.ExecutablePath = browserPath
			browserConfig.Resolver = resolver
			browserConfig.Dialer = dialer
			browserAnalyzer, err := browser.NewAnalyzer(browserConfig)
			if err != nil {
				t.Fatal(err)
			}

			engine, err := New(Config{
				Analyzers: []AnalyzerConfig{
					{Analyzer: httpAnalyzer, FailurePolicy: FailurePolicyAbort},
					{Analyzer: browserAnalyzer, FailurePolicy: FailurePolicyContinue},
				},
				RuleSet: ruleSet,
			})
			if err != nil {
				t.Fatal(err)
			}

			_, port, err := net.SplitHostPort(localURL.Host)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			result, err := engine.Scan(ctx, "http://fixture.example:"+port+"/")
			if err != nil {
				t.Fatal(err)
			}

			if len(result.Analyzers) != 2 {
				t.Fatalf("analyzers = %#v", result.Analyzers)
			}
			if result.Analyzers[1].Status == AnalyzerStatusFailed && !explicitBrowser {
				t.Skipf("sandboxed Chromium is unavailable: %v", result.Analyzers[1].Err)
			}

			var matched *scoring.Detection
			for _, d := range result.Detections {
				if d.RuleID == tc.wantRuleID {
					matched = &d
					break
				}
			}

			if matched == nil {
				t.Fatalf("rule %q not detected in scan results: %#v", tc.wantRuleID, result.Detections)
			}
			if matched.Score != tc.wantScore {
				t.Errorf("rule %q score = %v, want %v", tc.wantRuleID, matched.Score, tc.wantScore)
			}
			if matched.Detected != tc.wantDetected {
				t.Errorf("rule %q detected = %v, want %v", tc.wantRuleID, matched.Detected, tc.wantDetected)
			}
			if matched.Level != tc.wantLevel {
				t.Errorf("rule %q level = %v, want %v", tc.wantRuleID, matched.Level, tc.wantLevel)
			}

			var matchedEvidenceIDs []string
			for _, ev := range matched.PositiveEvidence {
				matchedEvidenceIDs = append(matchedEvidenceIDs, ev.Match.EvidenceID)
				if ev.Match.Signal.Source != analysis.SourceBrowser && tc.wantRuleID != "akamai.bot_manager" && tc.wantRuleID != "cloudflare.challenge_page" && tc.wantRuleID != "cloudflare.bot_protection" {
					t.Errorf("rule %q evidence %q has source %q, want %q", tc.wantRuleID, ev.Match.EvidenceID, ev.Match.Signal.Source, analysis.SourceBrowser)
				}
			}
			for _, wantEID := range tc.wantEvidenceIDs {
				if !slices.Contains(matchedEvidenceIDs, wantEID) {
					t.Errorf("rule %q matched evidence %v does not contain %q", tc.wantRuleID, matchedEvidenceIDs, wantEID)
				}
			}
		})
	}
}
