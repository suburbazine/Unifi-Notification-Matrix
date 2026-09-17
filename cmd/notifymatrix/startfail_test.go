package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
)

// Found on a real installation: the service stopped at startup, and the reason
// was written only to a stderr that under the Windows service manager goes
// nowhere. services.msc said "Stopped"; the audit record, the interface and
// the next start's report said nothing about why.
//
// A run that cannot start must leave its reason in both places that outlive
// it: the audit record the interface shows, and the run marker the next start
// reports from.
func TestARunThatCannotStartRecordsWhy(t *testing.T) {
	dir := t.TempDir()

	// A configuration that parses and is then refused -- the shape of the one
	// found in the field, with an address no machine has (TEST-NET-1).
	//
	// Written by hand rather than through config.Save: saving mints and
	// encrypts the acknowledgement key, and a Linux CI runner has no keyring
	// to encrypt it with. The refusal under test happens at load, before any
	// secret is needed.
	broken := fmt.Sprintf("version: %d\nweb:\n  listen: 192.0.2.1:8322\n", config.SchemaVersion)
	if err := os.WriteFile(config.Path(dir), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	// Guard: a configuration that still loads would let the daemon go on to
	// bind real ports on the machine running the test. Stop before that.
	if _, err := config.Load(dir); err == nil {
		t.Fatal("the broken configuration still loads; refusing to start a daemon from it")
	}

	runErr := runDaemon(context.Background(), dir)
	if runErr == nil {
		t.Fatal("a configuration naming an address this machine does not have was started")
	}

	// 1. The audit record, which the interface's Activity log shows.
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
		var e struct {
			Summary string            `json:"summary"`
			Fields  map[string]string `json:"fields"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.Summary == "could not start" {
			found = true
			if !strings.Contains(e.Fields["error"], "192.0.2.1") {
				t.Errorf("the audit record does not carry the reason: %q", e.Fields["error"])
			}
		}
	}
	if !found {
		t.Errorf("no \"could not start\" entry in the audit record:\n%s", audit)
	}

	// 2. The run marker, which the NEXT start reports from.
	_, prev, err := service.Begin(dir, version, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || !strings.Contains(prev.Error, "192.0.2.1") {
		t.Fatalf("the next start cannot say why the last one stopped: %+v", prev)
	}
	if got := service.CrashSummary(prev); got != "the previous run could not start" {
		t.Errorf("the next start would report %q", got)
	}
}
