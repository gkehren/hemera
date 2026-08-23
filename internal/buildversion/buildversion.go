// Package buildversion derives a bounded Hemera build identity from Go build
// metadata without exposing unrelated build settings.
package buildversion

import (
	"runtime/debug"
	"strings"
)

const (
	developmentVersion    = "dev"
	shortRevisionLength   = 12
	minimumRevisionLength = 7
	maximumRevisionLength = 64
)

// Resolve returns an explicitly injected version when present, then a versioned
// main module, then a bounded Git development identity, and finally "dev".
func Resolve(injected string) string {
	info, ok := debug.ReadBuildInfo()
	return resolve(injected, info, ok)
}

func resolve(injected string, info *debug.BuildInfo, ok bool) string {
	if injected != "" {
		return injected
	}
	if !ok || info == nil {
		return developmentVersion
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	var vcs, revision, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs":
			vcs = setting.Value
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if vcs != "git" || !validRevision(revision) {
		return developmentVersion
	}

	if len(revision) > shortRevisionLength {
		revision = revision[:shortRevisionLength]
	}
	identity := developmentVersion + "+g" + strings.ToLower(revision)
	if modified == "true" {
		identity += ".dirty"
	}
	return identity
}

func validRevision(revision string) bool {
	if len(revision) < minimumRevisionLength || len(revision) > maximumRevisionLength {
		return false
	}
	for _, character := range revision {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}
