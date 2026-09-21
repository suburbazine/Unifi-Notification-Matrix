// Command notifymatrix turns one-shot UniFi events into tracked incidents that
// keep escalating until a human closes them.
//
// The incident lifecycle, the durable store, the escalation scheduler, the
// rule engine, the acknowledgement surface, the secret store, configuration,
// the Protect and Access sources, the ingest supervisor and its deadman, the
// ntfy and email channels, the audit record, the web UI, the capability probe
// and the service integration are real and tested.
//
// The NETWORK source is not written, so a console's Network application is not
// watched -- `notifymatrix probe` is how its surfaces get described before it
// is. Anything that lists `network` under a console's sources is reported at
// startup rather than accepted quietly, because a config that is waved through
// reads as a WAN that is being watched.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ack"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/inbound"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ingest"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/integrity"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/probe"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/reconcile"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/surge"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/unifi"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/update"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

// dataDirWasGiven records whether --data-dir was passed, rather than defaulted.
var dataDirWasGiven bool

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
	// Asked once: the answer cannot change mid-run, and the offer made
	// during the run and the pause after it must agree about who is watching.
	alone := ownsTheConsoleAlone()
	code := run(alone)
	// Before os.Exit, which skips defers. A double-clicked binary has a
	// console only for as long as the process lives.
	holdTheWindowOpen(os.Stdout, os.Stdin, alone, os.Args[0])
	os.Exit(code)
}

// executableName is filepath.Base for a path that is always a WINDOWS path,
// whatever the machine deciding what a separator is.
//
// filepath.Base on Linux does not treat a backslash as a separator, so
// `C:\Users\x\Downloads\nm.exe` comes back whole and the suggested command
// becomes `.\C:\Users\x\Downloads\nm.exe setup` -- which is not a command.
// This only ever runs on Windows, but its test runs everywhere, and that is
// what noticed.
func executableName(argv0 string) string {
	if i := strings.LastIndexAny(argv0, `/\`); i >= 0 {
		return argv0[i+1:]
	}
	return argv0
}

// typeableExeName is what a person has to type to run this program.
//
// "notifymatrix" only when that is genuinely the name. A downloaded release
// asset is called notifymatrix-windows-amd64.exe, becomes
// "notifymatrix-windows-amd64 (1).exe" on a second download, and is not on
// PATH -- so every instruction this product printed failed with "not
// recognized" for anybody who had not already renamed it.
//
// Empty when it IS the plain name, which is what setup.Input documents as
// meaning "the packaged install"; the .exe suffix is not a rename.
func typeableExeName() string {
	name := executableName(os.Args[0])
	switch strings.ToLower(name) {
	case "notifymatrix", "notifymatrix.exe":
		return ""
	}
	return name
}

// channelPendingRestart reports whether name is enabled in the configuration
// on disk but absent from the channel set this process is actually running.
//
// The two can disagree for exactly one reason and it is not a rare one: the
// set is constructed once, at start, from the config as it was then. Every
// save after that updates the file and leaves the running process alone.
func channelPendingRestart(c *config.Config, live []string, name string) bool {
	if c == nil {
		return false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	for _, n := range live {
		if strings.EqualFold(n, name) {
			return false // it is running; whatever failed, it was not this
		}
	}
	for _, n := range c.EnabledChannelNames() {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// wrapText breaks a warning so it stays readable in a terminal.
func wrapText(s string, width int) string {
	var out strings.Builder
	line := 0
	for i, w := range strings.Fields(s) {
		if i > 0 {
			if line+1+len(w) > width {
				out.WriteString("\n         ")
				line = 0
			} else {
				out.WriteString(" ")
				line++
			}
		}
		out.WriteString(w)
		line += len(w)
	}
	return out.String()
}

// wrapIndent wraps to width and indents every line, including the first.
//
// wrapText hard-codes the nine-space continuation that its WARNING callers
// want; selfcheck's columns are a different shape, so this takes the indent
// rather than the two of them drifting apart over one constant.
func wrapIndent(s string, indent, width int) string {
	pad := strings.Repeat(" ", indent)
	var out strings.Builder
	line := 0
	for i, w := range strings.Fields(s) {
		switch {
		case i == 0:
			out.WriteString(pad)
		case line+1+len(w) > width-indent:
			out.WriteString("\n" + pad)
			line = 0
		default:
			out.WriteString(" ")
			line++
		}
		out.WriteString(w)
		line += len(w)
	}
	return out.String()
}

// typedCommand renders a runnable command for whatever this executable is
// actually called. Shares its rule with setup.Input.Command, so the checklist
// and the control screen never disagree about what to type.
func typedCommand(verb string) string {
	return setup.Input{Exe: typeableExeName()}.Command(verb)
}

// holdTheWindowOpen keeps a double-clicked console window on screen.
//
// Double-clicking this in Explorer ran it, printed the status, and closed the
// window in the same instant -- so it read as "it opens and closes and does
// nothing", which is the impression a downloaded security tool can least
// afford to make. The program was working; nobody could see it.
//
// It takes its inputs rather than reading the world, because the interesting
// case is unreachable from a test: a test process shares its console with the
// test runner, so `alone` is never true when it matters.
func holdTheWindowOpen(out io.Writer, in io.Reader, alone bool, argv0 string) {
	if !alone {
		return
	}
	exe := executableName(argv0)
	fmt.Fprintf(out, `
---

Windows closes this window as soon as the program finishes, so it is being
held open for you. Nothing else is running.

There is more it can do than the above. From a terminal in this folder --
shift+right-click the folder, "Open PowerShell window here":

    .\%s setup        what is left to configure, one step at a time
    .\%s selfcheck    what this machine can do
    .\%s --help       everything else

Press Enter to close this window. `, exe, exe, exe)
	// One byte is enough: Enter, any other key followed by Enter, or a closed
	// stdin all mean "stop waiting".
	var b [1]byte
	in.Read(b[:])
	fmt.Fprintln(out)
}

func run(alone bool) int {
	cmd, flagArgs := splitCommand(os.Args[1:])

	// The probe owns its own flag set: it has flags nothing else wants, and
	// the shared set below is ExitOnError, so routing them through it would
	// refuse the command rather than run it.
	if cmd == "probe" {
		return probeCommand(service.DefaultDataDir(), flagArgs)
	}
	// Same reason: --host belongs to this verb and to nothing else, and the
	// shared set below is ExitOnError, so it would refuse the command rather
	// than run it.
	if cmd == "fingerprint" {
		return fingerprintCmd(flagArgs)
	}

	fs := flag.NewFlagSet("notifymatrix", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "where config, the incident store and the lock live")
	links := fs.Bool("links", false, "print acknowledgement links (they are credentials)")
	all := fs.Bool("all", false, "with `setup`, show every step including the finished ones")
	user := fs.String("user", "", "account the Linux service runs as (default notifymatrix)")
	portable := fs.Bool("portable", false, "with `install`, run the service from where this file is rather than copying it somewhere only administrators can write")
	fs.Usage = usage
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}

	dir := *dataDir
	// Whether it was ASKED for matters to `demo`, which must not land on the
	// real data directory by default.
	dataDirWasGiven = dir != ""
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
			return 1
		}
		return 0
	}

	return dispatch(cmd, dir, *user, *links, *all, alone, *portable)
}

func dispatch(cmd, dataDir, user string, showLinks, showAll, interactive, portable bool) int {
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

	case "setup":
		return setupCmd(dataDir, showAll)

	case "selfcheck":
		return selfcheck(dataDir)

	case "incidents":
		return listIncidents(dataDir, showLinks)

	case restartServiceVerb:
		// Hidden: the detached child of a daemon restarting itself. Not listed
		// in usage because it is not something to type.
		return restartServiceHelper(dataDir)

	case "demo":
		return demoCmd(dataDir, dataDirWasGiven)

	case "setup-token":
		return setupTokenCmd(dataDir, interactive)

	case "set-password":
		return setPassword(dataDir, interactive)

	case "install", "uninstall", "start", "stop", "status":
		return serviceCmd(cmd, dataDir, user, portable)

	case "":
		// Double-clicked, or run with no arguments. Somebody who has never
		// opened a terminal must be able to get from "downloaded a file" to
		// "it is running and will keep running", so this reports state and
		// says what to do rather than printing usage and exiting.
		return control(dataDir, interactive)

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		return 2
	}
}

func usage() {
	// The verbs below are written as `notifymatrix X`, which is what they are
	// called. It is not necessarily what THIS file is called, and a reference
	// page full of commands that return "not recognized" is worse than no
	// reference page.
	if exe := typeableExeName(); exe != "" {
		fmt.Fprintf(os.Stderr, `Note: this file is called %s, not notifymatrix.
Either rename it to notifymatrix.exe, or read every command below as:

    %s

`, exe, setup.Input{Exe: exe}.Command("<command>"))
	}
	fmt.Fprintf(os.Stderr, `notifymatrix %s

  notifymatrix run          run in the foreground
  notifymatrix install      install and start the service
  notifymatrix uninstall    stop and remove the service
  notifymatrix start|stop   control the installed service
  notifymatrix status       report service state
  notifymatrix incidents    list open incidents (--links for ack URLs)
  notifymatrix setup-token  show the one-time setup token (elevates if it must)
  notifymatrix set-password set the settings password (works with the service installed)
  notifymatrix demo         look around a fabricated site, no console needed
  notifymatrix setup        what is left to do, step by step (--all for everything)
  notifymatrix selfcheck    report what this machine can do
  notifymatrix probe        ask a console what it exposes (local networks only)
  notifymatrix fingerprint  show a console's certificate fingerprint, to pin it
  notifymatrix version

Flags:
  --data-dir PATH   config, incident store and lock (default %s)
  --user NAME       Linux service account (default %s)
  --portable        with install, leave the program where it is instead of
                    copying it somewhere only administrators can write

Run "notifymatrix probe -h" for its own flags.

Sources: protect, access, network.
Channels: ntfy, email, pushover, webhook.
`, version, service.DefaultDataDir(), "notifymatrix")
}

// runDaemon is the supervised process.
func runDaemon(ctx context.Context, dataDir string) (retErr error) {
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
	// From here on, WHY this run stopped survives it.
	//
	// Found on a real installation: a listen address this machine did not
	// have stopped the service at startup, the reason went to a stderr that
	// under the Windows service manager is nowhere, and the next start
	// reported only that the previous run "did not shut down cleanly". The
	// marker carries the reason to that next start; the audit record below
	// puts it where the interface shows it.
	defer func() {
		if retErr != nil {
			if err := marker.Fail(version, started, time.Now(), retErr); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not record why this run stopped:", err)
			}
		}
	}()

	// Opened early: the crash report below is one of the entries that matters
	// most, and it happens before anything else is up.
	auditLog, err := audit.Open(dataDir, audit.WithErrorHandler(func(err error) {
		fmt.Fprintln(os.Stderr, "audit:", err)
	}))
	if err != nil {
		return err
	}
	defer auditLog.Close()
	// Registered after Close, so it runs before it.
	running := false
	defer func() {
		if retErr == nil {
			return
		}
		summary := "could not start"
		if running {
			summary = "stopped with an error"
		}
		// context.Background: ctx may be the very thing that was cancelled.
		_ = auditLog.Append(context.Background(), audit.Entry{
			Kind: audit.KindService, Actor: "system", Summary: summary,
			Fields: map[string]string{"error": retErr.Error()},
		})
	}()
	_ = auditLog.Append(ctx, audit.Entry{
		Kind: audit.KindService, Actor: "system",
		Summary: fmt.Sprintf("started, version %s", version),
	})

	// Repair the configuration's permissions before reading it. Installations
	// created before this existed left the file readable by every local
	// account on Windows, and an operator who never saves a setting from the
	// interface would never otherwise get the fix.
	if err := config.SecureExisting(dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not restrict who can read the configuration:", err)
		_ = auditLog.Append(ctx, audit.Entry{
			Kind: audit.KindService, Actor: "system",
			Summary: "could not restrict who can read the configuration",
			Fields:  map[string]string{"error": err.Error()},
		})
	}

	cfg, err := config.LoadOrCreate(dataDir)
	if err != nil {
		return err
	}
	// Usable, but worth saying out loud. These do NOT refuse the start: an
	// unpinned daemon that is watching beats a pinned one that is not running,
	// and one unimplemented source must not cost a console its other coverage.
	for _, w := range cfg.Warnings() {
		fmt.Fprintln(os.Stderr, "WARNING:", w)
		_ = auditLog.Append(ctx, audit.Entry{
			Kind: audit.KindService, Actor: "system",
			Summary: "configuration warning",
			Fields:  map[string]string{"detail": w},
		})
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

	// SAID AT THE MOMENT IT HAPPENS, because the operator will want it at a
	// moment when this product may not be running. An upgrade that changes the
	// schema cannot be undone -- the older build refuses a database newer than
	// itself, on purpose -- so the copy taken on the way through is the only
	// route back, and a path nobody was told about is not a route.
	if snap, snapErr := db.MigrationSnapshot(); snapErr != nil {
		fmt.Fprintln(os.Stderr, "WARNING: the database schema was upgraded and the "+
			"snapshot taken first could not be written:", snapErr)
		fmt.Fprintln(os.Stderr, "         The upgrade succeeded and this version is "+
			"running normally. What you do not have is a way back to the previous "+
			"version, which cannot open this database.")
	} else if snap != "" {
		fmt.Println("database schema upgraded; the version before it was saved to", snap)
		fmt.Println("keep that file until you are satisfied with this version: the one " +
			"before it cannot open the upgraded database")
	}

	upd := newUpdater(version)
	// The binary a previous update replaced, cleaned up here rather than at
	// the end of that update: at the end of an update the old file is still
	// the running process, and Windows will not delete a running executable.
	if exe, err := exePath(); err == nil {
		update.CleanBackups(exe)
	}
	// And the one a re-install moved aside, for the same reason: at install
	// time the file being replaced may still be the running process.
	service.CleanPlacedBackup()

	// A delivery failure is reported as it lands: a channel that has started
	// failing is itself something the operator needs to know, not only a field
	// on an incident nobody is looking at.
	// The supervisor is built much further down -- it needs the sources, which
	// need the config that is still being validated here -- so the activity
	// measurement reaches it through a pointer set at that point. Read per
	// call rather than captured, because "is a source silent" is a question
	// about now.
	var supervisorRef atomic.Pointer[ingest.Supervisor]
	blind := func() bool {
		sup := supervisorRef.Load()
		if sup == nil {
			// Nothing is watching yet, which is the most blind a daemon gets.
			return true
		}
		for _, st := range sup.Statuses() {
			if st.Silent || st.Fatal != "" {
				return true
			}
		}
		return false
	}

	// How busy this site is, measured at the ingest boundary and quoted on
	// alerts. Decoration only: it cannot move a severity or a ladder.
	activity := newSiteActivity(
		// Blind means a configured source is not reporting. A count taken
		// while half the site is unreachable measures what still reaches us,
		// not the site.
		surge.NewRecorder(db, time.Now, blind),
		surge.NewReporter(db, cfg.QuietHours.SiteLocation(), time.Now,
			func() (time.Time, bool) { return time.Time{}, blind() }),
		db.FlagBucket,
	)

	delivery, err := config.BuildDelivery(cfg, func(r channel.Result) {
		kind, summary := audit.KindAlertSent, "delivered via "+r.Channel
		fields := map[string]string{"channel": r.Channel}
		if r.Err != nil {
			kind, summary = audit.KindAlertFailed, "delivery failed via "+r.Channel
			fields["error"] = r.Err.Error()
		}
		_ = auditLog.Append(context.Background(), audit.Entry{
			Kind: kind, Actor: "system", IncidentID: r.IncidentID,
			Summary: summary, Fields: fields,
		})
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "delivery failed on %s for incident %s: %v\n",
				r.Channel, r.IncidentID, r.Err)
		}
	})
	if err != nil {
		return err
	}
	defer delivery.Close()

	// The one place an Alert is built asks how busy the site is. Appended to
	// the body; it cannot reach the severity or the ladder.
	delivery.SurgeNote = activity.note

	// A CHANNEL THAT IS CONFIGURED AND COULD NOT BE BUILT MUST SAY SO.
	//
	// Delivery.Broken() records these so that one malformed field cannot stop
	// the daemon -- which is right, and which had exactly one flaw: nothing
	// ever read it. The configuration said enabled, the setup checklist said
	// enabled, and the channel was simply absent, so it would have delivered
	// nothing at 3am while reading as healthy everywhere an operator looks.
	// That is the state this product exists to refuse, and it was being
	// produced by the mechanism added to make failures survivable.
	//
	// Reported at start rather than raised as an incident: the escalation
	// ladder delivers THROUGH channels, so an incident about a broken channel
	// may have no way to reach anybody. The audit record and the log are what
	// can be relied on here.
	for name, berr := range delivery.Broken() {
		fmt.Fprintf(os.Stderr, "channel %s is enabled in the configuration but "+
			"could not be started, so it will deliver nothing: %v\n", name, berr)
		_ = auditLog.Append(ctx, audit.Entry{
			Kind: audit.KindAlertFailed, Actor: "system",
			Summary: "channel " + name + " is configured but could not be started, " +
				"so it will deliver nothing until this is fixed and the service restarted",
			Fields: map[string]string{"channel": name, "error": berr.Error()},
		})
	}

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

	engine, err := rule.New(db, cfg.Rules,
		// Rule windows are clock times at the SITE, not on this machine.
		rule.WithLocation(cfg.QuietHours.SiteLocation()),
		rule.WithAuditHook(func(res rule.Result, ev event.Event) {
			kind := map[rule.Outcome]audit.Kind{
				rule.OutcomeOpened:   audit.KindIncidentOpened,
				rule.OutcomeUpdated:  audit.KindIncidentUpdated,
				rule.OutcomeRecurred: audit.KindIncidentRecurred,
				rule.OutcomeIgnored:  audit.KindIncidentIgnored,
				rule.OutcomeResolved: audit.KindResolved,
			}[res.Outcome]
			if kind == "" {
				return // a no-op clear is not worth a line
			}
			e := audit.Entry{
				Kind: kind, Actor: ev.Source, DedupKey: ev.DedupKey(),
				Severity: string(res.Decision.Severity),
				Summary:  string(res.Outcome) + ": " + ev.Condition,
				Fields:   map[string]string{"entity": ev.Entity.Name, "event": ev.Kind},
			}
			if res.Incident != nil {
				e.IncidentID = res.Incident.ID
			}
			if len(res.Decision.MatchedBy) > 0 {
				e.Fields["rules"] = strings.Join(res.Decision.MatchedBy, ", ")
			}
			_ = auditLog.Append(context.Background(), e)
		}))
	if err != nil {
		return err
	}

	// ARCHITECTURE.md §9a: a crash is itself an incident. Raised through the
	// ordinary machinery so it escalates like anything else -- without this a
	// crash loop is invisible, because the service restarts, the UI looks
	// healthy, and the only evidence is a gap in the history nobody reads.
	//
	// RaiseInternal deliberately bypasses the rule set: an operator ignore
	// aimed at a noisy camera must not be able to silence the product
	// reporting its own failure.
	if prev != nil {
		fmt.Fprintln(os.Stderr, "WARNING: "+service.CrashDetail(prev))
		_ = auditLog.Append(ctx, audit.Entry{
			Kind: audit.KindService, Actor: "system",
			Summary: service.CrashSummary(prev),
			Fields:  map[string]string{"detail": service.CrashDetail(prev)},
		})
		// Titled by the consequence, which is the same whatever the cause:
		// it was down, and alarms raised meanwhile were not delivered.
		title := "NotifyMatrix did not shut down cleanly"
		if prev.Error != "" {
			title = "NotifyMatrix was down after an error"
		}
		if _, err := engine.RaiseInternal(ctx, event.ConditionUncleanShutdown,
			incident.SeverityHigh, title,
			service.CrashDetail(prev)); err != nil {
			fmt.Fprintln(os.Stderr, "         could not raise it as an incident:", err)
		}
	}

	// IS THIS THE BINARY WE INSTALLED? Asked at every start, because the
	// install-time warning about a replaceable binary was never followed by
	// anything that looked.
	//
	// HIGH rather than critical, and the reason is the false positive rather
	// than the severity of the true one. The likeliest cause by far is an
	// operator who replaced the binary by hand -- a self-built one, a manual
	// rollback -- and quiet hours never apply to critical, so getting that
	// wrong wakes somebody for their own action. An operator who wants this to
	// page at 3am can say so in a rule, which is what rules are for.
	if exe, err := os.Executable(); err == nil {
		finding, ierr := integrity.Check(exe, dataDir, version)
		if ierr != nil {
			// Never fatal. A tripwire that cannot arm is a thing to report,
			// not a reason to leave the site unwatched.
			fmt.Fprintln(os.Stderr, "note: could not check the running binary:", ierr)
		}
		if finding.Changed {
			fmt.Fprintln(os.Stderr, "\nWARNING: "+finding.Title)
			fmt.Fprintln(os.Stderr, wrapText(finding.Detail, 72))
			_ = auditLog.Append(ctx, audit.Entry{
				Kind: audit.KindService, Actor: "system",
				Summary: finding.Title,
				Fields:  map[string]string{"detail": finding.Detail, "path": exe},
			})
			if _, err := engine.RaiseInternal(ctx, event.ConditionBinaryChanged,
				incident.SeverityHigh, finding.Title, finding.Detail); err != nil {
				fmt.Fprintln(os.Stderr, "         could not raise it as an incident:", err)
			}
		}
	}

	sched, err := escalate.NewScheduler(db, policies, deliver,
		escalate.WithQuietHours(cfg.QuietHours))
	if err != nil {
		return err
	}

	// INGEST. Everything above this decides what to do with events; nothing
	// above it produces any. A daemon that skipped this would start, serve the
	// interface, run the escalation scheduler, and watch nothing at all.
	sources, problems := config.BuildSources(cfg)
	for _, p := range problems {
		// Reported, not fatal. One misconfigured console must not take away
		// coverage that works -- but it must never be silent either, because a
		// source that failed to build looks exactly like a source that is
		// quiet.
		fmt.Fprintln(os.Stderr, "WARNING:", p)
		_ = auditLog.Append(ctx, audit.Entry{
			Kind: audit.KindService, Actor: "system",
			Summary: "a source could not be built",
			Fields:  map[string]string{"detail": p.Error()},
		})
	}
	if len(sources) == 0 {
		fmt.Fprintln(os.Stderr, "WARNING: no sources are running, so no incident "+
			"will ever be raised from a console")
		fmt.Fprintf(os.Stderr, "         add a console with a `sources:` list in %s\n",
			config.Path(dataDir))
	}

	// RUNNING ON THE DEVICE IT WATCHES.
	//
	// Said at EVERY start rather than once at install, because install output
	// is read once by somebody who has already decided, and this is the
	// sentence that matters later. Same reasoning as the
	// only-source-of-door-events warning: a structural limitation nothing else
	// on any screen would ever reveal, because the symptom of it is silence.
	//
	// Recorded as well as printed. A service has no console, so on the
	// installation this most likely describes -- installed on the gateway and
	// then left alone -- the audit log is the only place anybody would find it
	// afterwards.
	if service.OnUniFiOS() {
		warning := service.CoLocationWarning(service.UniFiOSModel())
		fmt.Fprintln(os.Stderr, "WARNING:", warning)
		_ = auditLog.Append(ctx, audit.Entry{
			Kind: audit.KindService, Actor: "system",
			Summary: "running on the UniFi device it watches",
			Fields:  map[string]string{"detail": warning},
		})
	}

	// The inbound receiver. Alarm Manager rules exist only in the UniFi UI, so
	// the console pushes to us and there is nothing to poll -- which also means
	// there is nothing to verify until an alarm actually arrives. The receiver
	// records that, and every setup surface reads it.
	hooks := config.BuildHooks(cfg)
	receiver := inbound.New(hooks, inbound.Options{
		Emit: func(ev event.Event) {
			activity.observe(ev)
			if _, err := engine.Handle(context.Background(), ev); err != nil {
				fmt.Fprintln(os.Stderr, "inbound:", err)
			}
		},
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})

	// Peer state. Empty and inert unless something is paired.
	linkPeers, _ := config.BuildLinks(cfg)
	links := newLinkState(linkPeers)

	// Held so the interface can offer a pairing code. Nil until the listener
	// starts, which is also the honest answer: with no listener there is
	// nowhere for a peer to pair TO.
	//
	// ATOMIC because the interface begins serving BEFORE this is set. The web
	// listener comes up early on purpose -- an operator whose link listener
	// fails to bind needs the page that can fix it -- so the pairing handlers
	// can read this while the start-up path is still writing it. A plain
	// pointer here is a data race with a very small window and a very bad
	// failure, and the race detector would only find it under a request
	// arriving in exactly that instant.
	var linkPairer atomic.Pointer[link.Pairer]

	supervisor, err := ingest.New(sources, ingest.Deps{
		// The permanent record of what this site has. Written through on
		// every event and read back at start, so "what did we have before the
		// power went out" survives the power going out.
		NoteEntity: func(ctx context.Context, e ingest.EntitySeen) {
			if err := db.NoteEntity(ctx, store.ObservedEntity{
				Source: e.Source, ID: e.ID, Name: e.Name, Kind: e.Kind,
				MAC: e.MAC, FirstSeen: e.LastAt, LastSeen: e.LastAt,
			}); err != nil {
				fmt.Fprintln(os.Stderr, "ingest:", err)
			}
		},
		KnownFrom: func(ctx context.Context) []ingest.EntitySeen {
			prior, err := db.ObservedEntities(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ingest: reading the entity record:", err)
				return nil
			}
			out := make([]ingest.EntitySeen, 0, len(prior))
			for _, e := range prior {
				out = append(out, ingest.EntitySeen{
					Source: e.Source, ID: e.ID, Name: e.Name, Kind: e.Kind,
					MAC: e.MAC, FirstAt: e.FirstSeen, LastAt: e.LastSeen,
				})
			}
			return out
		},
		Handle: func(ctx context.Context, ev event.Event) error {
			// A PAIRED PEER THAT IS ACTUALLY SERVING THE CAPABILITY takes over
			// raising for it, so one real-world event does not become two
			// incidents. Suppression is here rather than at the source on
			// purpose: the source keeps polling, so the console-contact
			// deadman keeps working and the rules editor keeps learning
			// entities, and this reverses the instant the peer stops being
			// able to serve.
			// Counted BEFORE the peer check as well as before the rules: an
			// event a peer is already raising still happened at this site,
			// and the measurement is of the site rather than of what this
			// installation chose to do about it.
			activity.observe(ev)
			if links.suppressedByPeer(ev, time.Now(), peerSilentAfter) {
				return nil
			}
			_, err := engine.Handle(ctx, ev)
			return err
		},
		Raise: func(ctx context.Context, ent event.Entity, condition string,
			sev incident.Severity, title, detail string) error {
			_, err := engine.RaiseInternalFor(ctx, ent, condition, sev, title, detail)
			return err
		},
		Resolve: func(ctx context.Context, ent event.Entity, condition string) error {
			_, err := engine.ResolveInternalFor(ctx, ent, condition)
			return err
		},
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	supervisorRef.Store(supervisor)
	if err != nil {
		return err
	}

	// Serve the acknowledgement endpoint.
	//
	// The full web UI is not built yet, but the ack surface cannot wait for
	// it: until this is listening, every alert carries a link that goes
	// nowhere, and "escalates until a human acknowledges" is a promise the
	// product cannot keep.
	if !cfg.Web.AckKey.IsZero() {
		signer, err := ack.NewSigner(cfg.Web.AckKey)
		if err != nil {
			return err
		}
		ackHandler, err := ack.New(db, signer,
			ack.WithAuditHook(func(inc *incident.Incident, via string) {
				_ = auditLog.Append(context.Background(), audit.Entry{
					Kind: audit.KindAcknowledged, Actor: via,
					IncidentID: inc.ID, DedupKey: inc.DedupKey,
					Severity: string(inc.Severity),
					Summary:  "acknowledged: " + inc.Title,
				})
				where := via
				if where == "" {
					where = "an unnamed channel"
				}
				fmt.Printf("incident %s acknowledged via %s\n", inc.ID, where)
			}))
		if err != nil {
			return err
		}

		mux := http.NewServeMux()
		// The more specific pattern wins, so the ack routes keep their OWN
		// headers -- internal/ack sets a stricter default-src 'none' policy
		// than the UI needs, and wrapping the UI's middleware around it would
		// loosen it.
		mux.Handle("/ack/", ackHandler)

		// The webhook endpoint. Mounted beside the acknowledgement routes and
		// outside the UI's middleware, because a console posting an alarm is
		// not a browser and must not be asked for a session.
		mux.Handle(inbound.PathPrefix, receiver)

		// The operator interface. Status is public so a wall display can show
		// it; every change needs the password.
		var cfgMu sync.RWMutex
		current := cfg

		// The amendment path needs the same things the link receiver's deps
		// need, and it is built HERE rather than inside the listener block
		// because the interface is assembled first. Approving a condition is
		// a configuration change made from a signed-in page, so it has to
		// work whenever the page does -- including on a build whose link
		// listener never started, where the proposals list is simply empty.
		amend := linkDeps{
			cfg: func() *config.Config {
				cfgMu.RLock()
				defer cfgMu.RUnlock()
				return current
			},
			saveCfg: func(c *config.Config) error {
				if err := config.Save(dataDir, c); err != nil {
					return err
				}
				cfgMu.Lock()
				current = c
				cfgMu.Unlock()
				return nil
			},
			state:    links,
			auditLog: auditLog,
		}

		// The probe, wired to the interface. It holds the configuration so it
		// can refuse a run against a console with no key BEFORE the capture
		// window rather than after it.
		prb := newProbeDeps(dataDir, version, func() *config.Config {
			cfgMu.RLock()
			defer cfgMu.RUnlock()
			return current
		})

		ui, err := web.New(web.Deps{
			Store:            db,
			Audit:            auditLog,
			FetchFingerprint: fetchFingerprint,
			ProbeStatus:      prb.status,
			ProbeStart:       prb.start,
			ProbeStop:        prb.stop,
			ProbeRead:        prb.read,
			Config: func() *config.Config {
				cfgMu.RLock()
				defer cfgMu.RUnlock()
				return current
			},
			SaveConfig: func(next *config.Config) error {
				if err := config.Save(dataDir, next); err != nil {
					return err
				}
				cfgMu.Lock()
				current = next
				cfgMu.Unlock()
				// TODO(reload): channels, policies and rules are built at
				// start, so a saved change reaches the FILE and the UI but not
				// the running engine until a restart. Said plainly here rather
				// than left for an operator to discover by saving a channel
				// and watching nothing use it.
				fmt.Fprintln(os.Stderr, "settings saved; restart to apply them to the running daemon")
				return nil
			},
			Health: func() web.Health {
				_ = prev // see UncleanPreviousExit below
				cfgMu.RLock()
				c := current
				cfgMu.RUnlock()
				// StartedAt was never set, so uptime_seconds was permanently
				// 0 and the computation in the web layer was dead code.
				h := web.Health{StartedAt: started}
				for _, st := range delivery.Stats() {
					h.Channels = append(h.Channels, web.ChannelHealth{
						Name: st.Channel, Enabled: true, Depth: st.Depth,
						Pending: st.Pending, Dropped: st.Dropped,
						InFlight: st.InFlight,
						LastSent: st.LastSent, LastError: st.LastError,
						// A channel being held back after repeated failures is
						// not being attempted, and must not read as healthy.
						ConsecutiveFails: st.ConsecutiveFails,
						BackingOffUntil:  st.BackingOffUntil,
					})
				}
				_ = c
				for _, st := range supervisor.Statuses() {
					sh := sourceHealthFrom(st)
					h.Sources = append(h.Sources, sh)
				}
				if st, err := service.New().Status(); err == nil {
					h.Service = web.ServiceHealth{
						State:               string(st.State),
						StartType:           st.StartType,
						RestartsAfterCrash:  st.RecoversFromCrash,
						PID:                 st.PID,
						Detail:              st.Detail,
						UncleanPreviousExit: prev != nil,
					}
				}
				return h
			},
			PasswordHash: func() string {
				cfgMu.RLock()
				defer cfgMu.RUnlock()
				return current.Web.PasswordHash
			},
			SetPasswordHash: func(h string) error {
				cfgMu.Lock()
				next := *current
				next.Web.PasswordHash = h
				cfgMu.Unlock()
				if err := config.Save(dataDir, &next); err != nil {
					return err
				}
				cfgMu.Lock()
				current = &next
				cfgMu.Unlock()
				// The token is spent and the file is now a thing that looks
				// like a credential and is not. Removed on the same path that
				// makes it obsolete, so the two cannot drift apart.
				_ = config.RemoveSetupToken(dataDir)
				return nil
			},
			LinkState: func() web.LinkPairing {
				return links.view(func() *config.Config {
					cfgMu.RLock()
					defer cfgMu.RUnlock()
					return current
				}, linkPairer.Load(), time.Now(), started)
			},
			LinkOfferCode: func() (string, time.Duration, error) {
				p := linkPairer.Load()
				if p == nil {
					return "", 0, errors.New("no peer link listener is running")
				}
				code, err := p.Offer()
				if err != nil {
					return "", 0, err
				}
				return link.FormatCode(code), link.CodeTTL, nil
			},
			LinkCancelCode: func() {
				if p := linkPairer.Load(); p != nil {
					p.Cancel()
				}
			},
			// IF THIS STOPS, WOULD ANYTHING SAY SO?
			//
			// Computed per request rather than at start, because the answer
			// CHANGES: pairing a peer at another site is what makes it yes,
			// and an operator who has just done that should watch the banner
			// go away rather than be told to restart to find out.
			//
			// Coverage means a paired peer today. An off-site heartbeat would
			// count too and does not exist yet; when it does it belongs in
			// this condition and nowhere else.
			SelfWatch: func() web.SelfWatch {
				if !service.OnUniFiOS() {
					return web.SelfWatch{}
				}
				cfgMu.RLock()
				peers := len(current.Links)
				cfgMu.RUnlock()
				if peers > 0 {
					// Something elsewhere is paired to this installation and
					// will notice it go quiet. The deployment is still
					// co-located; it is no longer unwatched, and only the
					// second half was ever the problem.
					return web.SelfWatch{}
				}
				return web.SelfWatch{
					AtRisk: true,
					// No mention of the hardware or the fix: this is served to
					// anybody who can see the board. What they need is that a
					// quiet board here cannot be trusted to mean quiet.
					Detail: "This installation runs on the equipment it is " +
						"watching, so if it stops, nothing will raise an alarm " +
						"about it — including this screen. Treat a quiet board " +
						"here as unconfirmed.",
				}
			},
			LinkApproveCondition: amend.approveCondition,
			LinkDismissCondition: func(slug, condition string) {
				links.proposals.Forget(slug, condition)
			},
			LinkUnpair: func(slug string) (bool, error) {
				cfgMu.RLock()
				next, capability, found := forgetPeer(current, slug)
				cfgMu.RUnlock()
				if !found {
					return false, nil
				}
				if err := config.Save(dataDir, next); err != nil {
					return false, err
				}
				cfgMu.Lock()
				current = next
				cfgMu.Unlock()

				// The claim goes with the credential, and it goes NOW rather
				// than at the next restart. Leaving it would keep this
				// product's own source suppressed on behalf of a peer that has
				// just been revoked -- so revoking would stop the peer's
				// events and stop ours, and the doors would be watched by
				// nobody while the page said a peer was holding them.
				links.release(capability)

				// The pending questions go with the peer. Leaving them would
				// mean an unpaired product still asking the operator for
				// vocabulary -- and a DIFFERENT installation of that product,
				// pairing later under the same slug, inheriting the first
				// one's queue of things to approve.
				links.proposals.ForgetPeer(slug)
				return true, nil
			},
			TestChannel: func(ctx context.Context, name string) (string, error) {
				summary, err := delivery.Test(ctx, name)
				if err == nil {
					return summary, nil
				}
				// "channel ntfy is not enabled" is a lie when the operator has
				// just enabled it, saved, and pressed Test -- which is exactly
				// the sequence that produces it. The channel set is built once
				// at start and never rebuilt, so the config on disk says
				// enabled while this process still knows nothing about it, and
				// the message contradicts the screen they are looking at.
				//
				// Worse than the wording: the SAME stale set delivers real
				// alarms, so this state is a channel that reads as configured
				// and would not be told anything at 3am.
				cfgMu.RLock()
				c := current
				cfgMu.RUnlock()
				if channelPendingRestart(c, delivery.Names(), name) {
					return "", fmt.Errorf("%s is enabled in the configuration, but this "+
						"daemon started before that change and is still running without "+
						"it -- real alarms would not reach it either. Restart to apply: %s",
						name, typedCommand("stop")+" && "+typedCommand("start"))
				}
				return "", err
			},
			// Restarting is the action this page most needed and least had.
			// Channels, policies and rules are built once, at start, so every
			// saved change needs one -- and the only way to do it was a
			// terminal, told to somebody whose reason for being on this page
			// is that they would rather not open one.
			//
			// A restart takes THIS process down, so it cannot be "stop, then
			// start": nothing would be left running to do the start. The
			// service manager is asked to restart us, and on Windows that is
			// the SCM doing it, not us.
			ControlService: func(a web.ServiceAction) error {
				m := service.New()
				switch a {
				case web.ServiceStop:
					return m.Stop()
				case web.ServiceStart:
					return m.Start()
				case web.ServiceRestart:
					return restartSelf(m, dataDir)
				}
				return fmt.Errorf("unknown service action %q", a)
			},
			UpdateState: upd.state,
			CheckUpdate: upd.check,
			ApplyUpdate: func(ctx context.Context, v string) error {
				return upd.apply(ctx, v, dataDir)
			},
			KnownEntities: func() []web.EntitySeen {
				seen := supervisor.KnownEntities()
				out := make([]web.EntitySeen, 0, len(seen))
				for _, e := range seen {
					out = append(out, web.EntitySeen{
						Source: e.Source, ID: e.ID, Name: e.Name,
						Kind: e.Kind, LastAt: e.LastAt,
					})
				}
				return out
			},
			// The permanent record, NOT the in-memory one KnownEntities
			// serves. Read straight from the store on each request so the
			// review reflects what the site has had rather than what this
			// process happens to have seen since it started -- which after a
			// restart is the difference between finding a re-adoption and
			// being unable to see one.
			ObservedEntities: func(ctx context.Context) ([]reconcile.Entity, error) {
				rows, err := db.ObservedEntities(ctx)
				if err != nil {
					return nil, err
				}
				out := make([]reconcile.Entity, 0, len(rows))
				for _, e := range rows {
					out = append(out, reconcile.Entity{
						Source: e.Source, ID: e.ID, Name: e.Name, Kind: e.Kind,
						MAC: e.MAC, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
					})
				}
				return out, nil
			},
			HookTestMode: func(name string, minutes int) (time.Time, error) {
				if minutes <= 0 {
					return time.Time{}, receiver.DisarmTest(name)
				}
				return receiver.ArmTest(name, time.Duration(minutes)*time.Minute)
			},
			FireHookTest: func(name string) (string, error) {
				ev, err := receiver.FireTest(name)
				if err != nil {
					return "", err
				}
				return ev.Title, nil
			},
			Checklist: func() setup.Input {
				cfgMu.RLock()
				c := current
				cfgMu.RUnlock()

				in := fromConfig(setup.Input{
					DataDir: dataDir, ConfigPath: config.Path(dataDir),
					Listen: "127.0.0.1:8322",
					Exe:    typeableExeName(),
				}, c)
				if st, err := service.New().Status(); err == nil {
					in.ServiceInstalled = st.State != service.StateNotInstalled
					in.ServiceRunning = st.State == service.StateRunning
					in.RecoversFromCrash = st.RecoversFromCrash
				}
				// The half only this process knows: whether a webhook has ever
				// fired, and whether a source is actually running.
				for _, rec := range receiver.Receipts() {
					for i := range in.Hooks {
						if in.Hooks[i].Name == rec.Name {
							in.Hooks[i].Count = rec.Count
							in.Hooks[i].LastAt = rec.LastAt
							in.Hooks[i].Rejected = rec.Rejected
							in.Hooks[i].LastReject = rec.LastReject
							in.Hooks[i].TestCount = rec.TestCount
							in.Hooks[i].LastTestAt = rec.LastTestAt
							in.Hooks[i].TestArmedUntil = receiver.TestArmedUntil(rec.Name)
						}
					}
				}
				for _, st := range supervisor.Statuses() {
					in.SourcesLive = append(in.SourcesLive, setup.SourceState{
						Name: st.Name, Silent: st.Silent, Fatal: st.Fatal,
						Events: st.Events,
					})
				}
				return in
			},
			Version: version,
		})
		if err != nil {
			return err
		}
		mux.Handle("/", ui.Handler())
		if tok := ui.SetupToken(); tok != "" {
			// Written to a file as well as printed, because printing it is
			// exactly what does not work where it matters most: a Windows
			// service has no stdout, so on the installation this product tells
			// everybody to make, the token was minted into a void and the
			// settings page could not be claimed at all.
			//
			// Protected to administrators only, and if it cannot be protected
			// it is not written -- see config.WriteSetupToken.
			where := config.SetupTokenPath(dataDir)
			if err := config.WriteSetupToken(dataDir, tok); err != nil {
				fmt.Fprintln(os.Stderr, "note:", err)
				where = ""
			}
			fmt.Printf(`
No settings password is set yet. To set one, open the interface
and enter this one-time setup token:

    %s

It works once, and a new one is generated each time this starts.
`, tok)
			if where != "" {
				fmt.Printf(`
It is also in
    %s
deleted as soon as a password is set. A service has no console to print to,
so that file is where to look after installing.

Reading it needs an ELEVATED terminal -- being in the Administrators group
is not enough on its own, because Windows withholds those rights until a
process elevates. This will do it for you, prompting if it has to:

    %s

`, where, typedCommand("setup-token"))
			}
			fmt.Printf("Or set one directly, with nothing left on disk:  %s\n\n",
				typedCommand("set-password"))
		} else {
			// A password exists, so any token file is stale and its contents
			// are spent. Leaving it would be a file that looks like a live
			// credential and is not.
			_ = config.RemoveSetupToken(dataDir)
		}

		srv := &http.Server{
			Addr:    cfg.Web.Listen,
			Handler: mux,
			// /ack/ is mounted here as well as on its own listener, so an
			// operator who forwards THIS port -- which the documentation
			// argues against and some people will do anyway -- gets the same
			// header bound. Go's default is a megabyte per request.
			MaxHeaderBytes: maxAckHeaderBytes,
			// Bounded so a stalled client cannot hold a connection open
			// indefinitely; this listens on a LAN that may include devices
			// nobody is administering.
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		// Bind BEFORE declaring success, and fail startup if we cannot.
		//
		// ListenAndServe inside a goroutine reports a bind failure to stderr
		// and leaves the daemon running, which is the worst outcome available:
		// every alert then carries an acknowledgement link that goes nowhere
		// -- or worse, to a different instance that happens to hold the port,
		// where it reads as "that link is not valid". The operator taps it at
		// 3am and has no way to stop the alert.
		//
		// An alarm daemon whose acknowledgement endpoint is not listening has
		// not started. Say so.
		ln, err := net.Listen("tcp", cfg.Web.Listen)
		if err != nil {
			return fmt.Errorf("cannot listen on %s for acknowledgements "+
				"(another instance, or something else on that port?): %w",
				cfg.Web.Listen, err)
		}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(os.Stderr, "the acknowledgement endpoint stopped: %v\n", err)
			}
		}()
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
		}()
		// The ack-only listener, for reaching an alarm from off-site.
		//
		// A NAT port forward CANNOT SCOPE BY PATH. A forward aimed at the main
		// listener publishes the status page -- which names cameras, doors and
		// open alarms -- and the settings sign-in, to the whole internet. This
		// gives the forward something safe to point at: a port on which /ack/
		// is the only thing that exists and everything else is a 404.
		if want := strings.TrimSpace(cfg.Web.AckListen); want != "" {
			// Bound BEFORE being written down. Pinning a port this daemon
			// cannot actually bind is worse than not pinning at all: the
			// firewall rule and every acknowledgement link already sent would
			// point at it forever.
			resolved, ackLn, err := config.ResolveAckListen(want)
			if err != nil {
				return fmt.Errorf("cannot listen on %s for acknowledgements "+
					"(if this port was pinned earlier, something else has taken "+
					"it -- free it, or set web.ack_listen back to \"auto\" to "+
					"choose another): %w", want, err)
			}

			if resolved != want {
				// Chosen at random and now KEPT. A port that changed on every
				// start would break the forward and every link already sent.
				cfgMu.Lock()
				next := *current
				next.Web.AckListen = resolved
				cfgMu.Unlock()
				if err := config.Save(dataDir, &next); err != nil {
					_ = ackLn.Close()
					return fmt.Errorf("chose port %s for acknowledgements but could "+
						"not write it to the configuration, so it would change on "+
						"the next start: %w", resolved, err)
				}
				cfgMu.Lock()
				current = &next
				cfgMu.Unlock()
				fmt.Println("note:", config.AckPortPinnedMessage(resolved, config.Path(dataDir)))
			}

			// THIS IS THE PORT THE OPERATOR IS TOLD TO FORWARD, and it is
			// therefore the one that gets scanned and fuzzed indefinitely.
			// Everything in exposed.go is about what that COSTS: the safety
			// of what it serves was always handled, the cost of being hammered
			// was not. See exposed.go for why the in-flight cap matters most.
			ackSrv := &http.Server{
				Handler: inFlight(maxAckInFlight, ackOnly(ackHandler)),
				// A real acknowledgement URL is about 120 bytes. Go's default
				// allows a megabyte of headers per request.
				MaxHeaderBytes: maxAckHeaderBytes,
				// Tighter than the LAN interface, because the legitimate
				// traffic here is unusually well understood: two short
				// requests from a phone, then nothing. A minute of idle
				// keep-alive is a minute of held resources per scanner.
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       5 * time.Second,
			}
			go func() {
				err := ackSrv.Serve(limitListener(ackLn, maxAckConns))
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Fprintf(os.Stderr, "the acknowledgement listener stopped: %v\n", err)
				}
			}()
			defer func() {
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = ackSrv.Shutdown(shutdown)
			}()
			fmt.Printf("acknowledgements only on http://%s/ack/  (this is the port to forward)\n", resolved)
		}

		// THE PEER LINK, on a listener of its own for the same reason the
		// acknowledgement routes have one: a port forward cannot scope by
		// path, so a peer reaching this across a network gets a port where
		// /link/ is the only thing that exists.
		if want := strings.TrimSpace(cfg.Web.LinkListen); want != "" {
			resolved, linkLn, err := config.ResolveAckListen(want)
			if err != nil {
				return fmt.Errorf("cannot listen on %s for the peer link (free the "+
					"port, or set web.link_listen to \"auto\" to choose another): %w", want, err)
			}
			if resolved != want {
				// Pinned once and kept: a port that moved every start would
				// break the firewall rule and every peer's stored address.
				cfgMu.Lock()
				next := *current
				next.Web.LinkListen = resolved
				cfgMu.Unlock()
				if err := config.Save(dataDir, &next); err != nil {
					_ = linkLn.Close()
					return fmt.Errorf("chose port %s for the peer link but could not "+
						"write it to the configuration: %w", resolved, err)
				}
				cfgMu.Lock()
				current = &next
				cfgMu.Unlock()
				cfg = current
			}

			// What was actually bound, which is what the page shows and what
			// the product hello advertises. Recorded before anything can fail
			// below, so the two can never disagree.
			links.setAddress(resolved)

			certPEM, keyPEM, err := linkCertificate(cfg, func(c *config.Config) error {
				return config.Save(dataDir, c)
			})
			if err != nil {
				_ = linkLn.Close()
				return err
			}
			tlsCfg, err := link.TLSConfig(certPEM, keyPEM)
			if err != nil {
				_ = linkLn.Close()
				return err
			}
			fingerprint, err := link.Fingerprint(certPEM)
			if err != nil {
				_ = linkLn.Close()
				return err
			}

			pairer := link.NewPairer(fingerprint)
			linkPairer.Store(pairer)
			linkRC := link.NewReceiver(linkDeps{
				cfg: func() *config.Config { cfgMu.RLock(); defer cfgMu.RUnlock(); return current },
				saveCfg: func(c *config.Config) error {
					if err := config.Save(dataDir, c); err != nil {
						return err
					}
					cfgMu.Lock()
					current = c
					cfgMu.Unlock()
					return nil
				},
				state:    links,
				db:       db,
				delivery: delivery,
				handle: func(ctx context.Context, ev event.Event) error {
					activity.observe(ev)
					_, err := engine.Handle(ctx, ev)
					return err
				},
				auditLog:  auditLog,
				pairer:    pairer,
				version:   version,
				silentFor: peerSilentAfter,
			}.build())

			linkCtx, stopLink := context.WithCancel(ctx)
			defer stopLink()
			go func() {
				if err := link.Serve(linkCtx, linkLn, linkRC, tlsCfg); err != nil {
					fmt.Fprintf(os.Stderr, "the peer link listener stopped: %v\n", err)
				}
			}()
			fmt.Printf("peer link on https://%s/link/  (certificate %s...)\n",
				resolved, fingerprint[:16])
		}

		fmt.Printf("interface on http://%s/  (acknowledgements at /ack/)\n", cfg.Web.Listen)
		if cfg.Web.AckBaseURL == "" {
			fmt.Fprintln(os.Stderr, "note: web.ack_base_url is unset, so alerts will "+
				"carry no acknowledgement link")
		}
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

	// The supervisor and the scheduler run together and stop together: a
	// product that kept escalating while ingesting nothing, or ingested while
	// nothing escalated, would be halfway broken in a way neither half could
	// report.
	ingestCtx, stopIngest := context.WithCancel(ctx)

	// Closing buckets on a timer, because a site that goes SILENT stops
	// producing events and a silent stretch is a measurement rather than the
	// absence of one.
	go activity.run(ingestCtx)

	var ingestDone sync.WaitGroup
	ingestDone.Add(1)
	go func() {
		defer ingestDone.Done()
		if err := supervisor.Run(ingestCtx); err != nil {
			fmt.Fprintln(os.Stderr, "ingest stopped:", err)
		}
	}()

	running = true
	runErr := sched.Run(ctx)
	stopIngest()
	ingestDone.Wait()

	// Finish ONLY on an orderly exit. Doing it from a deferred cleanup that
	// also runs on a panic would turn every crash into a clean shutdown and
	// delete the signal the marker exists to provide.
	if runErr == nil {
		if err := marker.Finish(); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not clear the run marker:", err)
		}
		_ = auditLog.Append(context.Background(), audit.Entry{
			Kind: audit.KindService, Actor: "system", Summary: "stopped cleanly",
		})
		fmt.Println("stopped cleanly")
	}
	return runErr
}

func serviceCmd(cmd, dataDir, user string, portable bool) int {
	m := service.New()

	var err error
	switch cmd {
	case "install":
		// The binary is put where a service binary BELONGS before the service
		// is created, because install records a path and keeps it for ever.
		//
		// Without this, install registered whatever path it was run from --
		// which for a downloaded program is Downloads, a directory its own
		// unelevated user can write to. A service running as LocalSystem out
		// of there is a file anybody running as that user can replace,
		// choosing what runs as the service account next time it starts, with
		// no prompt and none of the updater's signature checking involved.
		exePath, locErr := os.Executable()
		if locErr != nil {
			fmt.Fprintln(os.Stderr, "error: locating this executable:", locErr)
			return 1
		}
		if portable {
			if w := service.LocationWarning(exePath); w != "" {
				fmt.Fprintln(os.Stderr, "\nWARNING: "+wrapText(w, 72))
				fmt.Fprintln(os.Stderr, "\nInstalling from there anyway: --portable was given.")
				fmt.Fprintln(os.Stderr)
			}
		} else {
			placed, perr := service.PlaceBinary(exePath)
			// A permission failure here is not something to report and stop
			// on: it is something to elevate past. Copying the binary happens
			// before the service is created, so it failed FIRST -- and only
			// m.Install returned the sentinel the handler below elevates on.
			// The UAC prompt that the double-click path and SETUP.md both
			// promise was therefore unreachable, and the only way forward
			// offered was --portable, which is the insecure one.
			if errors.Is(perr, service.ErrNeedsPrivilege) {
				err = perr
				break
			}
			if perr != nil {
				fmt.Fprintln(os.Stderr, "error:", perr)
				fmt.Fprintln(os.Stderr, "       to install from where it is instead, add --portable")
				return 1
			}
			if placed != exePath {
				fmt.Printf("copied the program to %s\n", placed)
				fmt.Printf("the download you ran this from is no longer needed\n")
			}
			exePath = placed
		}
		err = m.Install(service.InstallOptions{
			DataDir: dataDir, User: user, ExePath: exePath,
		})
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
		if cmd == "install" {
			// The install is not finished when the service is running. It is
			// finished when the operator holds the one thing that lets them
			// claim the settings page -- and this is the last moment anything
			// is talking to them, because the daemon's own announcement goes
			// to a console a service does not have.
			handOverSetupToken(os.Stdout, os.Stdin, dataDir,
				someoneIsWatching(), tokenWaitFor, os.Args[0])
		}
		return 0

	case errors.Is(err, service.ErrNeedsPrivilege):
		// Elevating is the difference between an operator who succeeds and one
		// who reads "access denied" and gives up.
		if runtime.GOOS == "windows" {
			args := cmd
			if dataDir != "" {
				args += " --data-dir " + service.EscapeArg(dataDir)
			}
			// Carried across the elevation, or the elevated run would do the
			// opposite of what was asked.
			if portable {
				args += " --portable"
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
		fmt.Fprintln(os.Stderr, "error: the service is not installed; run: "+typedCommand("install"))
		return 1

	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
}

// webAddress is where the interface is listening, according to the config the
// service is actually running with.
//
// Falls back to the documented default rather than reporting an error: this is
// a signpost printed beside a healthy service, and "could not read the config"
// in place of an address helps nobody who is looking for the address.
func webAddress(dataDir string) string {
	if cfg, err := config.Load(dataDir); err == nil && strings.TrimSpace(cfg.Web.Listen) != "" {
		return cfg.Web.Listen
	}
	return "127.0.0.1:8322"
}

// askYesNo puts a question to somebody who is actually sitting there.
//
// Defaults to yes on a bare Enter, because it is only ever asked after the
// program has said what it is about to do, and the alternative for the person
// it is aimed at is a terminal they have never opened. A closed stdin reads as
// no: unattended runs must not be committed to installing a service because
// nobody was there to decline.
func askYesNo(out io.Writer, in *bufio.Reader, question string) bool {
	fmt.Fprintf(out, "\n%s [Y/n] ", question)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(out)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true
	}
	return false
}

// control is what a double-clicked executable does.
//
// When somebody is sitting in front of it -- which is exactly the double-click
// case -- this OFFERS to do the next thing rather than printing a command for
// them to type. Telling a person who has never opened a terminal to open one
// is where this product loses them, and it is the one audience that most needs
// the thing installed correctly.
//
// Run from a script or a shell pipeline, `interactive` is false and it behaves
// as it always did: report state, print the command, change nothing.
func control(dataDir string, interactive bool) int {
	fmt.Printf("notifymatrix %s\n\n", version)

	st, err := service.New().Status()
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not query the service:", err)
	} else {
		fmt.Println("Service:", st)
	}

	in := bufio.NewReader(os.Stdin)

	switch {
	case err != nil:
	case st.State == service.StateNotInstalled:
		fmt.Println(`
Not installed yet. Installing it means it starts at boot, survives a logout,
and restarts itself after a crash -- none of which happens if you just leave
this window open.

It needs administrator rights, so Windows will ask you to confirm.`)
		if interactive && askYesNo(os.Stdout, in, "Install and start it now?") {
			return serviceCmd("install", dataDir, "", false)
		}

		// Offered HERE, to somebody who has just declined to install a
		// security tool they have never seen working. "No" at this point is
		// usually "not yet", and the honest next step is to let them look at
		// it -- without a console, without an API key, and without pointing
		// anything at their doors first.
		fmt.Println(`
Not ready to install it? You can look around a fabricated site instead --
a board mid-incident, the settings, the setup checklist. Nothing is watched
and nothing is delivered.`)
		if interactive && askYesNo(os.Stdout, in, "Open the demo instead?") {
			return demoCmd(dataDir, false)
		}
		fmt.Println("\nTo do either later, from a terminal:")
		fmt.Println("    " + typedCommand("install") + "   install it properly")
		fmt.Println("    " + typedCommand("demo") + "      look around first")

	case st.State == service.StateRunning && !st.RecoversFromCrash:
		// Loud, because this configuration looks completely healthy and will
		// not come back from a panic at 2am.
		fmt.Println(`
WARNING: this service will NOT restart after a crash. It looks healthy right
now and will stay down the next time it falls over, which is the whole thing
you installed it to avoid. Reinstalling fixes it.`)
		if interactive && askYesNo(os.Stdout, in, "Reinstall it now?") {
			if code := serviceCmd("uninstall", dataDir, "", false); code != 0 {
				return code
			}
			return serviceCmd("install", dataDir, "", false)
		}
		fmt.Println("\nTo do it later:  " + typedCommand("uninstall") + " && " + typedCommand("install"))

	case st.State == service.StateStopped:
		fmt.Println("\nInstalled, but not running -- so nothing is being watched.")
		if interactive && askYesNo(os.Stdout, in, "Start it now?") {
			return serviceCmd("start", dataDir, "", false)
		}
		fmt.Println("\nTo do it later:  " + typedCommand("start"))

	case st.State == service.StateRunning:
		// Where to go next. Somebody who has just watched it install has no
		// way to know there is a web interface at all, and the address is not
		// guessable -- it is whatever their config says.
		fmt.Printf("\nRunning. The interface is at http://%s/\n", webAddress(dataDir))
	}

	fmt.Printf("\nData directory: %s\n", dataDir)
	fmt.Println("Run `" + typedCommand("selfcheck") + "` to see what this machine can do.")
	return 0
}

// listIncidents answers "what is open right now?" without a web UI.
//
// Opens the store READ-ONLY-ish and does not take the single-instance lock, so
// it works while the daemon is running -- which is when somebody actually
// wants to ask.
func listIncidents(dataDir string, links bool) int {
	db, err := store.Open(filepath.Join(dataDir, "incidents.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer db.Close()

	active, err := db.Active(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var signer *ack.Signer
	cfg, cfgErr := config.Load(dataDir)
	if cfgErr == nil && !cfg.Web.AckKey.IsZero() {
		signer, _ = ack.NewSigner(cfg.Web.AckKey)
	}
	if links && signer == nil {
		fmt.Fprintln(os.Stderr, "note: no acknowledgement key is configured, so no links can be printed")
	}
	if len(active) == 0 {
		fmt.Println("no open incidents")
		return 0
	}
	for _, inc := range active {
		fmt.Printf("%-10s %-8s %-12s %s\n",
			inc.ID[:min(10, len(inc.ID))], inc.Severity, inc.State(), inc.Title)
		fmt.Printf("           opened %s", inc.OpenedAt.UTC().Format(time.RFC3339))
		if inc.AlertCount > 0 {
			fmt.Printf(", alerted %d time(s)", inc.AlertCount)
		}
		if inc.LastDeliveryError != "" {
			fmt.Printf("\n           LAST DELIVERY FAILED: %s", inc.LastDeliveryError)
		}
		fmt.Println()
		// Printed only on request. An acknowledgement link IS a credential --
		// anyone holding it can silence that alarm -- so it does not appear in
		// a listing somebody might paste into a support ticket.
		if links && signer != nil {
			base := cfg.Web.AckBaseURL
			if base == "" {
				base = "http://" + cfg.Web.Listen
			}
			fmt.Printf("           %s\n", signer.URL(base, inc.ID, inc.OpenedAt, "cli"))
		}
	}
	return 0
}

// sourceHealthFrom turns one supervisor status into what the board shows.
//
// EXTRACTED BECAUSE IT KEPT BEING WRONG. As a closure inside the daemon it was
// unreachable from any test, and it produced two lies in a row: a source that
// had never once reached its console badged as reporting, and then, once that
// was fixed, "last seen 17 seconds ago" beside a badge saying no contact --
// because the supervisor starts lastEventAt at launch so the deadman has a
// grace window, and this read that as a sighting.
func sourceHealthFrom(st ingest.Status) web.SourceHealth {
	// "Last seen" is the last CONTACT where the source can tell the
	// difference, because that is the question the column answers: are we
	// still watching? Showing the last emitted event made a healthy source
	// over a quiet night read as hours dead, next to a green badge.
	lastSeen := st.LastEventAt
	if !st.LastContactAt.IsZero() {
		lastSeen = st.LastContactAt
	}
	sh := web.SourceHealth{
		Name:           st.Name,
		LastSeen:       lastSeen,
		ExpectedWithin: st.Expected,
		Silent:         st.Silent,
	}
	switch {
	case st.Fatal != "":
		// Distinct from silent on purpose: a source that cannot run will
		// never recover on its own, and telling an operator it is merely
		// "quiet" sends them looking at the console instead of at the config.
		sh.Detail = "cannot run: " + st.Fatal
		sh.Silent = true
	case st.Restarts > 0:
		sh.Detail = fmt.Sprintf("%d event(s); restarted %d time(s)",
			st.Events, st.Restarts)
	default:
		sh.Detail = fmt.Sprintf("%d event(s)", st.Events)
	}
	// A source in contact with nothing to say is the normal state of a quiet
	// site, and saying so stops "0 event(s)" reading as a fault.
	if !st.Silent && st.Events == 0 && !st.LastContactAt.IsZero() {
		sh.Detail = "in contact; nothing to report yet"
	}
	// NEVER ONCE. The board said "in contact; nothing to report yet" for two
	// applications that were not installed on the console at all, and a third
	// whose key belonged to a different appliance.
	//
	// Checked last so it wins: this is the fact an operator most needs, and
	// every branch above would paper over it.
	if st.LastContactAt.IsZero() && st.Events == 0 && st.Fatal == "" {
		sh.NeverConnected = true
		sh.Silent = true
		// Zeroed so the column says "never". The supervisor's lastEventAt
		// starts at launch, so leaving it put a fresh timestamp beside a
		// badge saying there has been no contact -- the two halves of one row
		// contradicting each other.
		sh.LastSeen = time.Time{}
		sh.Detail = "no contact with the console yet"
		if why := firstLine(st.LastError, 160); why != "" {
			sh.Detail += " — " + why
		}
	}
	return sh
}

// fetchFingerprint reads the certificate a console is presenting.
//
// LOCAL ADDRESSES ONLY, enforced with the probe's own check. This is the
// daemon dialling whatever an operator typed into a form; pointed at somebody
// else's address it is a connection made from this machine to a host nobody
// here chose, and the probe refuses that for exactly the same reason.
//
// It SHOWS a fingerprint and never stores one. Trust-on-first-use is an
// operator action: what comes back is displayed for a human to accept, and
// accepting it is an ordinary save of the console.
func fetchFingerprint(ctx context.Context, host string) (string, error) {
	if err := probe.CheckHost(ctx, host); err != nil {
		if errors.Is(err, probe.ErrNotLocal) {
			// Said in this verb's own words. The probe's phrasing names the
			// probe, and somebody who pressed "read the certificate" did not
			// run a probe.
			return "", fmt.Errorf("%s is not on a local network, and this "+
				"reads certificates on local networks only", host)
		}
		return "", err
	}
	return unifi.FetchCertFingerprint(ctx, host)
}

// firstLine trims a source's error down to something a table cell can hold.
//
// A failing sweep reports every endpoint it could not read, so the raw string
// is three dial errors carrying full URLs -- accurate, and a wall of text in
// the one column an operator is scanning. The first line carries the
// diagnosis; the rest repeats it per path.
func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > max {
		s = strings.TrimSpace(s[:max]) + "…"
	}
	return s
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

	// WHAT THIS PLATFORM CAN ESTABLISH ABOUT ITS OWN BINARY, stated here
	// because "what this machine can do" is the question this command answers
	// and because the honest answer differs sharply between platforms. A
	// reader on Linux should find out here that change is detected and
	// authenticity is not, rather than inferring from a quiet startup that
	// the binary has been vouched for.
	fmt.Println("\nRunning binary")
	fmt.Println("--------------")
	if exe, err := os.Executable(); err != nil {
		fmt.Printf("  -- could not locate this executable: %v\n", err)
	} else {
		fmt.Printf("     %s\n", exe)
		if _, statErr := os.Stat(filepath.Join(dataDir, integrity.PinName)); statErr == nil {
			fmt.Println("  OK a reference is recorded; it is compared at every start")
		} else {
			fmt.Println("  -- no reference recorded yet; the next start will take one")
		}
	}
	fmt.Println(wrapIndent(integrity.Limitation(), 5, 72))

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
