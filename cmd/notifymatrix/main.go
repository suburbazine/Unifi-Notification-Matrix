// Command notifymatrix turns one-shot UniFi events into tracked incidents that
// keep escalating until a human closes them.
//
// The incident lifecycle, the durable store, the escalation scheduler, the
// secret store, configuration, the Protect source, the ntfy and email channels
// and the service integration are real and tested. The rule engine, the ack
// surface and the web UI are not written -- so `run` supervises itself
// correctly and delivers correctly, and nothing yet produces incidents for it
// to deliver.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

// splitCommand separates the verb from the flags, wherever the verb appears.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `flag.Parse()` on `run --data-dir X` silently DISCARDS the flag: the daemon
// starts against the default directory and says nothing about it. That is a
// bad failure for this product specifically -- the data directory is where the
// incident store and the single-instance lock live, so the wrong one means a
// second instance that does not notice the first.
//
// Accepting the verb in either position is what people actually type.
func splitCommand(argv []string) (cmd string, flags []string) {
	for i, a := range argv {
		if a == "--" {
			return cmd, append(flags, argv[i+1:]...)
		}
		if cmd == "" && a != "" && a[0] != '-' {
			// A value belonging to the preceding flag, not the verb.
			if i > 0 && isFlagExpectingValue(argv[i-1]) {
				flags = append(flags, a)
				continue
			}
			cmd = a
			continue
		}
		flags = append(flags, a)
	}
	return cmd, flags
}

// isFlagExpectingValue reports whether arg is a bare flag that consumes the
// next argument (`--data-dir X` rather than `--data-dir=X`).
func isFlagExpectingValue(arg string) bool {
	if len(arg) == 0 || arg[0] != '-' {
		return false
	}
	name := strings.TrimLeft(arg, "-")
	if strings.Contains(name, "=") {
		return false
	}
	switch name {
	case "data-dir", "user":
		return true
	}
	return false
}

func main() {
	cmd, flagArgs := splitCommand(os.Args[1:])

	fs := flag.NewFlagSet("notifymatrix", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "where config, the incident store and the lock live")
	user := fs.String("user", "", "account the Linux service runs as (default notifymatrix)")
	fs.Usage = usage
	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}

	dir := *dataDir
	if dir == "" {
		dir = service.DefaultDataDir()
	}

	// Started by the Windows service control manager? Then `run` is implied
	// and the SCM owns the lifecycle. This is what lets one binary be both the
	// service and the CLI.
	handled, err := service.RunAsService(func(ctx context.Context) error {
		return runDaemon(ctx, dir)
	})
	if handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	os.Exit(dispatch(cmd, dir, *user))
}

func dispatch(cmd, dataDir, user string) int {
	switch cmd {
	case "version":
		fmt.Printf("notifymatrix %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0

	case "run":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := runDaemon(ctx, dataDir); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0

	case "selfcheck":
		return selfcheck(dataDir)

	case "install", "uninstall", "start", "stop", "status":
		return serviceCmd(cmd, dataDir, user)

	case "":
		// Double-clicked, or run with no arguments. Somebody who has never
		// opened a terminal must be able to get from "downloaded a file" to
		// "it is running and will keep running", so this reports state and
		// says what to do rather than printing usage and exiting.
		return control(dataDir)

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `notifymatrix %s

  notifymatrix run          run in the foreground
  notifymatrix install      install and start the service
  notifymatrix uninstall    stop and remove the service
  notifymatrix start|stop   control the installed service
  notifymatrix status       report service state
  notifymatrix selfcheck    report what this machine can do
  notifymatrix version

Flags:
  --data-dir PATH   config, incident store and lock (default %s)
  --user NAME       Linux service account (default %s)

Not yet implemented: rules, the ack surface, the web UI.
`, version, service.DefaultDataDir(), "notifymatrix")
}

// runDaemon is the supervised process.
func runDaemon(ctx context.Context, dataDir string) error {
	// ONE instance per data directory. The classic failure is a service and a
	// logon task both running, both ingesting, both alerting -- on a product
	// whose credibility depends on not crying wolf.
	lock, err := service.Acquire(dataDir)
	if err != nil {
		return err
	}
	defer lock.Release()

	started := time.Now()
	marker, prev, err := service.Begin(dataDir, version, started)
	if err != nil {
		return err
	}

	if prev != nil {
		// TODO(incident-pipeline): raise this through escalate rather than
		// only printing it. ARCHITECTURE.md §9a requires a crash to become an
		// incident; until the rule engine exists there is nothing to raise it
		// through, and printing it is the honest interim -- the marker is
		// already doing the part that cannot be retrofitted, which is
		// noticing.
		fmt.Fprintln(os.Stderr, "WARNING: "+service.CrashDetail(prev))
	}

	cfg, err := config.LoadOrCreate(dataDir)
	if err != nil {
		return err
	}
	// A credential pasted into the file by hand is accepted on purpose, but a
	// key that sat readable on disk should be treated as exposed -- so say so,
	// loudly, rather than quietly encrypting it and moving on.
	if w := config.PlaintextWarning(cfg.PlaintextFields, config.Path(dataDir)); w != "" {
		fmt.Fprintln(os.Stderr, w)
		if err := config.Save(dataDir, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "         could not re-encrypt them:", err)
		} else {
			fmt.Fprintln(os.Stderr, "         (now encrypted)")
		}
	}

	db, err := store.Open(filepath.Join(dataDir, "incidents.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	// A delivery failure is reported as it lands: a channel that has started
	// failing is itself something the operator needs to know, not only a field
	// on an incident nobody is looking at.
	delivery, err := config.BuildDelivery(cfg, func(r channel.Result) {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "delivery failed on %s for incident %s: %v\n",
				r.Channel, r.IncidentID, r.Err)
		}
	})
	if err != nil {
		return err
	}
	defer delivery.Close()

	built, err := cfg.BuildPolicies(delivery.Names())
	if err != nil {
		return err
	}
	policies := map[incident.Severity]escalate.Policy{}
	for name, p := range built {
		policies[incident.Severity(name)] = p
	}

	deliver := delivery.Deliver
	if len(delivery.Names()) == 0 {
		// Nothing enabled yet. Refuse rather than pretend: a scheduler whose
		// delivery silently succeeds marks incidents as alerted that nobody
		// was ever told about.
		deliver = func(_ context.Context, inc *incident.Incident, _ int, chans []string) error {
			return fmt.Errorf("no channels configured (incident %s wanted %v)", inc.ID, chans)
		}
		fmt.Fprintln(os.Stderr, "note: no channels are enabled, so nothing can be delivered yet")
		fmt.Fprintf(os.Stderr, "      edit %s\n", config.Path(dataDir))
	}

	sched, err := escalate.NewScheduler(db, policies, deliver,
		escalate.WithQuietHours(cfg.QuietHours))
	if err != nil {
		return err
	}

	fmt.Printf("notifymatrix %s running; data dir %s\n", version, dataDir)

	// Heartbeat so a later crash report can say how long this run lasted --
	// a crash three seconds in is a configuration problem, one after six days
	// is something else, and the operator should not have to guess which.
	hb := time.NewTicker(time.Minute)
	defer hb.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-hb.C:
				_ = marker.Heartbeat(version, started, now)
			}
		}
	}()

	runErr := sched.Run(ctx)

	// Finish ONLY on an orderly exit. Doing it from a deferred cleanup that
	// also runs on a panic would turn every crash into a clean shutdown and
	// delete the signal the marker exists to provide.
	if runErr == nil {
		if err := marker.Finish(); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not clear the run marker:", err)
		}
		fmt.Println("stopped cleanly")
	}
	return runErr
}

func serviceCmd(cmd, dataDir, user string) int {
	m := service.New()

	var err error
	switch cmd {
	case "install":
		err = m.Install(service.InstallOptions{DataDir: dataDir, User: user})
	case "uninstall":
		err = m.Uninstall()
	case "start":
		err = m.Start()
	case "stop":
		err = m.Stop()
	case "status":
		st, serr := m.Status()
		if serr != nil {
			fmt.Fprintln(os.Stderr, "error:", serr)
			return 1
		}
		fmt.Println(st)
		return 0
	}

	switch {
	case err == nil:
		fmt.Printf("%s: ok\n", cmd)
		return 0

	case errors.Is(err, service.ErrNeedsPrivilege):
		// Elevating is the difference between an operator who succeeds and one
		// who reads "access denied" and gives up.
		if runtime.GOOS == "windows" {
			args := cmd
			if dataDir != "" {
				args += fmt.Sprintf(` --data-dir "%s"`, dataDir)
			}
			if e := service.Elevate(args); e != nil {
				fmt.Fprintln(os.Stderr, "error:", e)
				return 1
			}
			fmt.Println("continuing in an elevated window -- approve the Windows prompt")
			return 0
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1

	case errors.Is(err, service.ErrNotInstalled):
		fmt.Fprintln(os.Stderr, "error: the service is not installed; run: notifymatrix install")
		return 1

	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
}

// control is what a double-clicked executable does.
func control(dataDir string) int {
	fmt.Printf("notifymatrix %s\n\n", version)

	st, err := service.New().Status()
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not query the service:", err)
	} else {
		fmt.Println("Service:", st)
	}

	switch {
	case err != nil:
	case st.State == service.StateNotInstalled:
		fmt.Println(`
Not installed yet. To install it so it starts at boot, survives a logout and
restarts itself after a crash:

    notifymatrix install

That needs administrator rights and will prompt for them.`)
	case st.State == service.StateRunning && !st.RecoversFromCrash:
		// Loud, because this configuration looks completely healthy and will
		// not come back from a panic at 2am.
		fmt.Println(`
WARNING: this service will NOT restart after a crash. Reinstall to fix it:

    notifymatrix uninstall && notifymatrix install`)
	case st.State == service.StateStopped:
		fmt.Println("\nInstalled but not running. Start it with:\n\n    notifymatrix start")
	}

	fmt.Printf("\nData directory: %s\n", dataDir)
	fmt.Println("Run `notifymatrix selfcheck` to see what this machine can do.")
	return 0
}

func selfcheck(dataDir string) int {
	rc := 0

	fmt.Println("Service")
	fmt.Println("-------")
	if st, err := service.New().Status(); err != nil {
		fmt.Printf("  -- could not query: %v\n", err)
		rc = 1
	} else {
		mark := "OK"
		if st.State == service.StateNotInstalled {
			mark = "--"
		} else if !st.RecoversFromCrash {
			mark = "!!"
			rc = 1
		}
		fmt.Printf("  %s %s\n", mark, st)
	}
	fmt.Printf("     data directory: %s\n", dataDir)
	// Test the lock rather than trusting the file's contents: the pid written
	// there outlives the process that wrote it, and naming a dead process as
	// the current holder sends the operator hunting for something long gone.
	if service.IsHeld(dataDir) {
		if pid := service.HolderPID(dataDir); pid != 0 {
			fmt.Printf("     locked by pid %d -- a daemon is running here\n", pid)
		} else {
			fmt.Println("     locked -- a daemon is running here")
		}
	} else {
		fmt.Println("     not locked -- no daemon is running here")
	}

	fmt.Println("\nSecret storage")
	fmt.Println("--------------")
	var usable bool
	for _, s := range secret.Report() {
		mark := "--"
		if s.Available {
			mark, usable = "OK", true
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
	if secret.ServiceCredentialsAvailable() {
		fmt.Println("  Service-provisioned credentials are present and take precedence.")
	}
	if !usable {
		rc = 1
	}

	fmt.Println("\nEscalation policies")
	fmt.Println("-------------------")
	policies := escalate.DefaultPolicies()
	for _, sev := range []incident.Severity{
		incident.SeverityCritical, incident.SeverityHigh, incident.SeverityMedium,
		incident.SeverityLow, incident.SeverityInfo,
	} {
		p := policies[sev]
		if err := p.Validate(sev); err != nil {
			fmt.Printf("  !! %-9s INVALID: %v\n", sev, err)
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
	fmt.Printf("  channels named by policy: %v\n", escalate.ChannelsUsed(policies))

	return rc
}
