// Package tui renders Hemera's interactive terminal experience: a scan
// configuration wizard, live analyzer progress, and a styled result summary.
// It is presentation only and performs no detection.
package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"charm.land/huh/v2"

	"github.com/gkehren/hemera/internal/networkguard"
)

// Options holds the scan configuration collected by the interactive wizard.
type Options struct {
	URL  string
	Deep bool
}

// ErrAborted reports that the user canceled the wizard before submitting it.
var ErrAborted = errors.New("interactive scan canceled")

// RunWizard collects the scan mode and target URL with an interactive form.
// It returns ErrAborted when the user exits before submitting.
func RunWizard() (Options, error) {
	var opts Options
	mode := "default"
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Scan mode").
				Description("Deep scans use larger observation budgets and timeouts.").
				Options(
					huh.NewOption("Default", "default"),
					huh.NewOption("Deep", "deep"),
				).
				Value(&mode),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Target URL").
				Description("Only public http(s) targets are scanned; private addresses are rejected.").
				Placeholder("https://example.com").
				CharLimit(2048).
				Validate(validateTargetURL).
				Value(&opts.URL),
		),
	).WithAccessible(accessibleMode())
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return Options{}, ErrAborted
		}
		return Options{}, fmt.Errorf("run wizard: %w", err)
	}
	opts.URL = strings.TrimSpace(opts.URL)
	opts.Deep = mode == "deep"
	return opts, nil
}

func validateTargetURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("a target URL is required")
	}
	if _, err := networkguard.ParseURL(raw); err != nil {
		return err
	}
	return nil
}

func accessibleMode() bool {
	value := os.Getenv("HEMERA_ACCESSIBLE")
	return value == "1" || strings.EqualFold(value, "true")
}
