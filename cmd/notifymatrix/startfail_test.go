package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

	// A configuration that loads and is then refused -- the shape of the one
	// found in the field, with an address no machine has (TEST-NET-1).
	cfg := config.Default()
	if err := config.Save(dir, &cfg); err != nil {
		t.Fatal(err)
	}
	path := config.Path(dir)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The KEY, not the value: the value also appears in the file's comments,
	// and breaking a comment leaves a valid configuration that goes on to bind
	// a real port on the machine running the test.
	key := regexp.MustCompile(`(?m)^(\s+listen:\s*).*$`)
	if n := len(key.FindAllString(string(b), -1)); n != 1 {
		t.Fatalf("expected exactly one listen: key, found %d:\n%s", n, b)
	}
	broken := key.ReplaceAllString(string(b), "${1}192.0.2.1:8322")
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
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
