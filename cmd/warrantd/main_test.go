package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestHelpFlags checks that `warrantd --help`/`-h`/`help` and
// `warrantd gateway --help` print usage and exit 0, without requiring
// WARRANT_ADMIN_TOKEN or any gateway env vars to be set. This guards
// against a regression where the top-level and gateway subcommand help
// flags fell through to the normal startup path and failed with a fatal
// "... is required" error instead.
func TestHelpFlags(t *testing.T) {
	bin := buildWarrantd(t)

	for _, args := range [][]string{
		{"--help"}, {"-h"}, {"help"},
		{"gateway", "--help"}, {"gateway", "-h"}, {"gateway", "help"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			cmd := exec.Command(bin, args...)
			cmd.Env = []string{} // deliberately no WARRANT_* env vars
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("warrantd %v: %v\noutput:\n%s", args, err, out)
			}
			if !strings.Contains(string(out), "usage") {
				t.Fatalf("warrantd %v: expected usage text, got:\n%s", args, out)
			}
		})
	}
}

func buildWarrantd(t *testing.T) string {
	t.Helper()
	bin := t.TempDir() + "/warrantd"
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}
