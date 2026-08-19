//go:build browser_integration

package browser

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSandboxedChromiumLifecycle(t *testing.T) {
	config, explicit := integrationConfig(t)
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := client.Start(ctx)
	if err != nil {
		if !explicit {
			t.Skipf("sandboxed Chromium is unavailable: %v", err)
		}
		t.Fatalf("start explicitly configured Chromium: %v", err)
	}
	defer first.Close()
	second, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if version := first.Version(); version.Product == "" || version.ProtocolVersion == "" {
		t.Errorf("incomplete Browser.getVersion result: %#v", version)
	}
	firstRuntime := integrationRuntime(t, first)
	secondRuntime := integrationRuntime(t, second)
	if firstRuntime.initialURL != "about:blank" {
		t.Errorf("initial URL = %q, want about:blank", firstRuntime.initialURL)
	}
	if firstRuntime.profileDir == secondRuntime.profileDir {
		t.Errorf("sessions share profile %q", firstRuntime.profileDir)
	}
	for _, runtime := range []*chromedpSession{firstRuntime, secondRuntime} {
		if info, err := os.Stat(runtime.profileDir); err != nil || !info.IsDir() {
			t.Errorf("temporary profile %q is not an active directory: %v", runtime.profileDir, err)
		}
		assertChromiumArguments(t, runtime)
		if runtime.process == nil {
			t.Error("Chromium process is unavailable")
		}
	}

	assertStoppedAndCleaned(t, first, firstRuntime)
	assertStoppedAndCleaned(t, second, secondRuntime)
}

func integrationConfig(t *testing.T) (Config, bool) {
	t.Helper()
	config := DefaultConfig()
	if path := os.Getenv("HEMERA_CHROMIUM_PATH"); path != "" {
		config.ExecutablePath = path
		return config, true
	}
	for _, name := range []string{
		"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome",
	} {
		if path, err := exec.LookPath(name); err == nil {
			config.ExecutablePath = path
			return config, false
		}
	}
	t.Skip("no local Chromium or Chrome executable found")
	return Config{}, false
}

func integrationRuntime(t *testing.T, session *Session) *chromedpSession {
	t.Helper()
	runtime, ok := session.backend.(*chromedpSession)
	if !ok {
		t.Fatalf("backend session type = %T, want *chromedpSession", session.backend)
	}
	return runtime
}

func assertChromiumArguments(t *testing.T, runtime *chromedpSession) {
	t.Helper()
	if len(runtime.commandLine) == 0 {
		t.Fatal("Browser.getBrowserCommandLine returned no arguments")
	}
	wants := map[string]bool{
		"--headless":                            false,
		"--remote-debugging-address=127.0.0.1":  false,
		"--remote-debugging-port=0":             false,
		"--user-data-dir=" + runtime.profileDir: false,
	}
	for _, argument := range runtime.commandLine {
		if strings.HasPrefix(argument, "--no-sandbox") {
			t.Errorf("Chromium sandbox was disabled by %q", argument)
		}
		if _, ok := wants[argument]; ok {
			wants[argument] = true
		}
	}
	for argument, found := range wants {
		if !found {
			t.Errorf("Chromium command line is missing %q", argument)
		}
	}
}

func assertStoppedAndCleaned(t *testing.T, session *Session, runtime *chromedpSession) {
	t.Helper()
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.Done():
	case <-time.After(browserCloseTimeout + time.Second):
		t.Fatal("session Done did not close after shutdown deadline")
	}
	if _, err := os.Stat(runtime.profileDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary profile %q remains after Close: %v", runtime.profileDir, err)
	}
	if runtime.process == nil {
		return
	}
	if err := runtime.process.Signal(os.Interrupt); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("signal stopped Chromium process: %v, want os.ErrProcessDone", err)
	}
}
