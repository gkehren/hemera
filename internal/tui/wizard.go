// Package tui renders Hemera's interactive terminal experience: a scan
// configuration wizard, live analyzer progress, and a styled result summary.
// It is presentation only and performs no detection.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/gkehren/hemera/internal/networkguard"
	"github.com/gkehren/hemera/internal/safeoutput"
)

// Options holds the scan configuration collected by the interactive wizard.
type Options struct {
	URL  string
	Deep bool
}

// ErrAborted reports that the user canceled the wizard before submitting it.
var ErrAborted = errors.New("interactive scan canceled")

const accessibleWizardShutdownTimeout = time.Second

// RunWizard collects the scan mode and target URL with an interactive form.
// It returns ErrAborted when the user exits before submitting.
func RunWizard(ctx context.Context) (Options, error) {
	if ctx == nil {
		return Options{}, errors.New("run wizard: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Options{}, err
	}

	var opts Options
	mode := "default"
	accessible := accessibleMode()
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
	).WithAccessible(accessible)

	var err error
	if accessible {
		form.WithInput(os.Stdin).WithOutput(os.Stdout)
		err = runAccessibleForm(ctx, form, os.Stdin)
	} else {
		// The application boundary is the sole SIGINT/SIGTERM owner. Raw-mode
		// Ctrl+C still reaches the form as a key event and remains a user abort.
		form.WithProgramOptions(
			tea.WithInput(os.Stdin),
			tea.WithOutput(os.Stderr),
			tea.WithoutSignalHandler(),
		)
		err = form.RunWithContext(ctx)
	}
	// Parent cancellation dominates a concurrent form result so an external
	// signal can never be reclassified as a successful UI abort.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Options{}, ctxErr
	}
	if err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return Options{}, ErrAborted
		}
		return Options{}, fmt.Errorf("run wizard: %w", err)
	}
	opts.URL = strings.TrimSpace(opts.URL)
	opts.Deep = mode == "deep"
	return opts, nil
}

// runAccessibleForm supplies cancellation that huh's accessible runner does
// not currently implement. Closing the application-owned stdin unblocks its
// line reader during process shutdown; a hard deadline prevents an unusual
// input implementation from holding termination indefinitely.
func runAccessibleForm(ctx context.Context, form *huh.Form, input io.Closer) error {
	done := make(chan error, 1)
	go func() {
		done <- form.RunWithContext(ctx)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = input.Close()
	}

	timer := time.NewTimer(accessibleWizardShutdownTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return errors.Join(ctx.Err(), err)
	case <-timer.C:
		return fmt.Errorf("stop accessible wizard within %s: %w", accessibleWizardShutdownTimeout, ctx.Err())
	}
}

func validateTargetURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("a target URL is required")
	}
	if _, err := networkguard.ParseURL(raw); err != nil {
		// net/url parse failures can embed fragments of the raw input in
		// their message text. Render only bounded, control-free text; the
		// static policy wording passes through unchanged.
		return errors.New(safeoutput.SanitizeDiagnostic(err))
	}
	return nil
}

func accessibleMode() bool {
	value := os.Getenv("HEMERA_ACCESSIBLE")
	return value == "1" || strings.EqualFold(value, "true")
}
