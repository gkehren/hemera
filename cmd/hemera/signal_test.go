package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gkehren/hemera/internal/scanner"
)

const (
	signalHelperEnv         = "HEMERA_TEST_SIGNAL_HELPER"
	signalHelperCleanupEnv  = "HEMERA_TEST_SIGNAL_CLEANUP"
	signalHelperReadyMarker = "signal-helper-ready"
)

func TestRunMainWithRunnerPropagatesParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	finished := make(chan struct{})
	codeDone := make(chan int, 1)
	runner := func(ctx context.Context, _ []string, _, _ io.Writer) int {
		close(started)
		defer close(finished)
		<-ctx.Done()
		return 1
	}
	go func() {
		codeDone <- runMainWithRunner(parent, nil, io.Discard, io.Discard, runner)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("application runner did not start")
	}
	cancel()

	select {
	case code := <-codeDone:
		if code != 1 {
			t.Fatalf("runMainWithRunner() code = %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("application runner did not return after parent cancellation")
	}
	select {
	case <-finished:
	default:
		t.Fatal("runner cleanup did not finish before runMainWithRunner returned")
	}
}

func TestProcessSignalsCancelClassicScanAndJoinCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support sending os.Interrupt or SIGTERM with os.Process.Signal")
	}

	tests := []struct {
		name   string
		signal os.Signal
	}{
		{name: "SIGINT", signal: os.Interrupt},
		{name: "SIGTERM", signal: syscall.SIGTERM},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			cleanupPath := filepath.Join(t.TempDir(), "cleanup-complete")
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Env = append(os.Environ(),
				signalHelperEnv+"=1",
				signalHelperCleanupEnv+"="+cleanupPath,
			)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			processDone := false
			defer func() {
				if !processDone {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()

			ready := make(chan error, 1)
			go func() {
				line, readErr := bufio.NewReader(stdout).ReadString('\n')
				if readErr == nil && strings.TrimSpace(line) != signalHelperReadyMarker {
					readErr = fmt.Errorf("readiness marker = %q", strings.TrimSpace(line))
				}
				ready <- readErr
			}()
			select {
			case err := <-ready:
				if err != nil {
					t.Fatalf("wait for helper readiness: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("signal helper did not become ready")
			}

			if err := cmd.Process.Signal(testCase.signal); err != nil {
				t.Fatalf("send %s: %v", testCase.name, err)
			}
			waitDone := make(chan error, 1)
			go func() { waitDone <- cmd.Wait() }()
			var waitErr error
			select {
			case waitErr = <-waitDone:
				processDone = true
			case <-time.After(5 * time.Second):
				t.Fatal("signal helper did not exit after cancellation")
			}
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("helper wait error = %v, want exit code 1", waitErr)
			}
			if _, err := os.Stat(cleanupPath); err != nil {
				t.Fatalf("cleanup marker missing after process exit: %v", err)
			}
			if got := stderr.String(); got != "hemera: scan canceled\n" {
				t.Errorf("stderr = %q, want deterministic sanitized cancellation diagnostic", got)
			}
		})
	}
}

func runSignalHelper() int {
	cleanupPath := os.Getenv(signalHelperCleanupEnv)
	runner := func(ctx context.Context, _ []string, stdout, stderr io.Writer) int {
		fake := scanRunnerFunc(func(ctx context.Context, _ string) (_ scanner.Result, resultErr error) {
			fmt.Fprintln(os.Stdout, signalHelperReadyMarker)
			defer func() {
				if err := os.WriteFile(cleanupPath, []byte("complete\n"), 0o600); err != nil {
					resultErr = errors.Join(resultErr, err)
				}
			}()
			<-ctx.Done()
			return scanner.Result{}, fmt.Errorf(
				"cancel https://user:password@example.test/?token=SUPER_SECRET: %w",
				ctx.Err(),
			)
		})
		return runScan(ctx, []string{"https://example.test/"}, stdout, stderr, fake)
	}
	return runMainWithRunner(context.Background(), nil, os.Stdout, os.Stderr, runner)
}
