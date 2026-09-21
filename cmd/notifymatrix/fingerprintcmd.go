package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
)

// notifymatrix fingerprint -- what the startup warning has always told people
// to do and never gave them a way to do.
//
// "pin a certificate (notifymatrix will show you its fingerprint)" has been
// printed beside every unpinned console since pinning existed. The function
// that reads a certificate was written and tested and called by nothing, so
// the honest instruction was "go and find openssl".
func fingerprintCmd(args []string) int {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	host := fs.String("host", "", "the console to read (default: each configured console)")
	dir := fs.String("data-dir", "", "where the configuration lives")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dataDir := *dir
	if dataDir == "" {
		dataDir = service.DefaultDataDir()
	}

	hosts := []string{}
	names := map[string]string{}
	if h := strings.TrimSpace(*host); h != "" {
		hosts = append(hosts, h)
	} else if cfg, err := config.Load(dataDir); err == nil {
		for _, c := range cfg.Consoles {
			if h := strings.TrimSpace(c.Host); h != "" {
				hosts = append(hosts, h)
				names[h] = c.Name
				if strings.TrimSpace(c.Fingerprint) != "" {
					names[h] += " (pinned already)"
				}
			}
		}
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "no console to read: pass --host, or configure one first")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	failed, read := false, 0
	for _, h := range hosts {
		fp, err := fetchFingerprint(ctx, h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", h, err)
			failed = true
			continue
		}
		label := h
		if n := names[h]; n != "" {
			label = n + " (" + h + ")"
		}
		fmt.Printf("%s\n  %s\n", label, fp)
		read++
	}

	// Advice about pasting a value is noise when there is no value: a run
	// where nothing answered should end on the reason, not on instructions
	// for the thing that did not happen.
	if read == 0 {
		return 1
	}

	fmt.Println()
	fmt.Println("Paste that into the console's fingerprint field to pin it. THIS IS")
	fmt.Println("TRUST-ON-FIRST-USE: what you are reading is whatever is answering at")
	fmt.Println("that address right now, so it is worth confirming out of band -- the")
	fmt.Println("console's own interface shows the same value.")
	fmt.Println()
	fmt.Println("Once pinned, the certificate check setting no longer decides anything:")
	fmt.Println("the pin is checked after every handshake and anything else is refused.")

	if failed {
		return 1
	}
	return 0
}
