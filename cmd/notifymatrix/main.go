// Command notifymatrix turns one-shot UniFi events into tracked incidents that
// keep escalating until a human closes them.
//
// Scaffold: the incident lifecycle, the escalation policy and the secret store
// are real and tested. Ingest, channels, the store and the web UI are not built
// yet, so the only useful verbs today are `version` and `selfcheck`.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	flag.Usage = usage
	flag.Parse()

	switch flag.Arg(0) {
	case "", "version":
		fmt.Printf("notifymatrix %s (%s/%s, %s)\n",
			version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	case "selfcheck":
		os.Exit(selfcheck())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", flag.Arg(0))
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `notifymatrix %s

Usage:
  notifymatrix version     print the version
  notifymatrix selfcheck   report what this machine can do

Not yet implemented: run, install, uninstall, test-channel.
`, version)
}

// selfcheck reports what the machine can actually do, rather than what the
// documentation says it should. It exists because the commonest support
// question for a product like this is "it is installed and nothing happens",
// and the answer is usually visible here.
func selfcheck() int {
	rc := 0

	fmt.Println("Secret storage")
	fmt.Println("--------------")
	var usable bool
	for _, s := range secret.Report() {
		mark := "  "
		switch {
		case s.Available && s.MachineBound:
			mark, usable = "OK", true
		case s.Available:
			mark, usable = "ok", true
		default:
			mark = "--"
		}
		bound := "not machine-bound"
		if s.MachineBound {
			bound = "machine-bound"
		}
		fmt.Printf("  %s %-46s %s\n", mark, s.Mechanism+" ("+bound+")", s.Reason)
	}
	if p, err := secret.SelectWriter(); err == nil {
		fmt.Printf("\n  Secrets would be stored with: %s\n", p.Mechanism())
		if !p.MachineBound() {
			fmt.Println("  NOTE: this mechanism is not machine-bound. A copy of the config")
			fmt.Println("        and the key file together is readable on another machine.")
		}
	} else {
		fmt.Printf("\n  UNUSABLE: %v\n", err)
		rc = 1
	}
	if !usable {
		rc = 1
	}

	fmt.Println("\nEscalation policies")
	fmt.Println("-------------------")
	for _, sev := range []incident.Severity{
		incident.SeverityCritical, incident.SeverityHigh, incident.SeverityMedium,
		incident.SeverityLow, incident.SeverityInfo,
	} {
		p := escalate.DefaultPolicies()[sev]
		if err := p.Validate(sev); err != nil {
			fmt.Printf("  -- %-9s INVALID: %v\n", sev, err)
			rc = 1
			continue
		}
		giveUp := "never gives up"
		if p.GiveUpAfter > 0 {
			giveUp = "gives up after " + p.GiveUpAfter.String()
		}
		stages := "stages"
		if len(p.Stages) == 1 {
			stages = "stage"
		}
		fmt.Printf("  OK %-9s %d %-7s %s\n", sev, len(p.Stages), stages, giveUp)
	}

	return rc
}
