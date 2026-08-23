package buildversion

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolvePrecedenceAndFallbacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		injected string
		info     *debug.BuildInfo
		ok       bool
		want     string
	}{
		{
			name:     "injected release overrides module and VCS",
			injected: "v1.2.3",
			info: buildInfo("v0.2.0",
				setting("vcs", "git"),
				setting("vcs.revision", "0123456789abcdef0123456789abcdef01234567"),
				setting("vcs.modified", "true"),
			),
			ok:   true,
			want: "v1.2.3",
		},
		{
			name: "module release overrides VCS",
			info: buildInfo("v0.2.0",
				setting("vcs", "git"),
				setting("vcs.revision", "0123456789abcdef0123456789abcdef01234567"),
			),
			ok:   true,
			want: "v0.2.0",
		},
		{
			name: "clean development revision",
			info: buildInfo("(devel)",
				setting("vcs", "git"),
				setting("vcs.revision", "ABCDEF0123456789ABCDEF0123456789ABCDEF01"),
				setting("vcs.modified", "false"),
			),
			ok:   true,
			want: "dev+gabcdef012345",
		},
		{
			name: "modified development revision",
			info: buildInfo("(devel)",
				setting("vcs", "git"),
				setting("vcs.revision", "0123456789abcdef0123456789abcdef01234567"),
				setting("vcs.modified", "true"),
			),
			ok:   true,
			want: "dev+g0123456789ab.dirty",
		},
		{
			name: "short valid development revision",
			info: buildInfo("", setting("vcs", "git"), setting("vcs.revision", "0c02a1ce")),
			ok:   true,
			want: "dev+g0c02a1ce",
		},
		{name: "build info unavailable", ok: false, want: "dev"},
		{name: "nil build info", ok: true, want: "dev"},
		{name: "empty build info", info: buildInfo(""), ok: true, want: "dev"},
		{name: "development build without revision", info: buildInfo("(devel)"), ok: true, want: "dev"},
		{
			name: "non-Git revision",
			info: buildInfo("(devel)", setting("vcs", "hg"), setting("vcs.revision", "0123456789abcdef")),
			ok:   true,
			want: "dev",
		},
		{
			name: "invalid revision cannot leak a path",
			info: buildInfo("(devel)", setting("vcs", "git"), setting("vcs.revision", "/home/alice/hemera")),
			ok:   true,
			want: "dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolve(tt.injected, tt.info, tt.ok); got != tt.want {
				t.Errorf("resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveIgnoresUnrelatedBuildSettings(t *testing.T) {
	t.Parallel()

	secretValues := []string{
		"/home/alice/hemera",
		"alice@example.test",
		"SUPER_SECRET_TOKEN",
	}
	info := buildInfo("(devel)",
		setting("vcs", "git"),
		setting("vcs.revision", "0123456789abcdef0123456789abcdef01234567"),
		setting("vcs.modified", "false"),
		setting("-trimpath", secretValues[0]),
		setting("build.user", secretValues[1]),
		setting("CGO_CFLAGS", secretValues[2]),
	)

	got := resolve("", info, true)
	if got != "dev+g0123456789ab" {
		t.Fatalf("resolve() = %q, want bounded revision", got)
	}
	for _, secret := range secretValues {
		if strings.Contains(got, secret) {
			t.Errorf("resolve() leaked unrelated build setting %q", secret)
		}
	}
}

func buildInfo(version string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{
		Main:     debug.Module{Version: version},
		Settings: settings,
	}
}

func setting(key, value string) debug.BuildSetting {
	return debug.BuildSetting{Key: key, Value: value}
}
