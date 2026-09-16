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
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
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

	fs := flag.NewFlagSet("notifymatrix", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "where config, the incident store and the lock live")
	links := fs.Bool("links", false, "print acknowledgement links (they are credentials)")
	all := fs.Bool("all", false, "with `setup`, show every step including the finished ones")
	user := fs.String("user", "", "account the Linux service runs as (default notifymatrix)")
	fs.Usage = usage
	if err := fs.Parse(flagArgs); err != nil {
		return 2
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
			return 1
		}
		return 0
	}

	return dispatch(cmd, dir, *user, *links, *all, alone)
}

func dispatch(cmd, dataDir, user string, showLinks, showAll, interactive bool) int {
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

	case "install", "uninstall", "start", "stop", "status":
		return serviceCmd(cmd, dataDir, user)

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
	fmt.Fprintf(os.Stderr, `notifymatrix %s

  notifymatrix run          run in the foreground
  notifymatrix install      install and start the service
  notifymatrix uninstall    stop and remove the service
  notifymatrix start|stop   control the installed service
  notifymatrix status       report service state
  notifymatrix incidents    list open incidents (--links for ack URLs)
  notifymatrix setup        what is left to do, step by step (--all for everything)
  notifymatrix selfcheck    report what this machine can do
  notifymatrix probe        ask a console what it exposes (local networks only)
  notifymatrix version

Flags:
  --data-dir PATH   config, incident store and lock (default %s)
  --user NAME       Linux service account (default %s)

Run "notifymatrix probe -h" for its own flags.

Sources: protect, access, network.
Channels: ntfy, email, pushover, webhook.
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

	// Opened early: the crash report below is one of the entries that matters
	// most, and it happens before anything else is up.
	auditLog, err := audit.Open(dataDir, audit.WithErrorHandler(func(err error) {
		fmt.Fprintln(os.Stderr, "audit:", err)
	}))
	if err != nil {
		return err
	}
	defer auditLog.Close()
	_ = auditLog.Append(ctx, audit.Entry{
		Kind: audit.KindService, Actor: "system",
		Summary: fmt.Sprintf("started, version %s", version),
	})

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

	// A delivery failure is reported as it lands: a channel that has started
	// failing is itself something the operator needs to know, not only a field
	// on an incident nobody is looking at.
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
			Summary: "the previous run did not shut down cleanly",
			Fields:  map[string]string{"detail": service.CrashDetail(prev)},
		})
		if _, err := engine.RaiseInternal(ctx, event.ConditionUncleanShutdown,
			incident.SeverityHigh,
			"NotifyMatrix did not shut down cleanly",
			service.CrashDetail(prev)); err != nil {
			fmt.Fprintln(os.Stderr, "         could not raise it as an incident:", err)
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

	// The inbound receiver. Alarm Manager rules exist only in the UniFi UI, so
	// the console pushes to us and there is nothing to poll -- which also means
	// there is nothing to verify until an alarm actually arrives. The receiver
	// records that, and every setup surface reads it.
	hooks := config.BuildHooks(cfg)
	receiver := inbound.New(hooks, inbound.Options{
		Emit: func(ev event.Event) {
			if _, err := engine.Handle(context.Background(), ev); err != nil {
				fmt.Fprintln(os.Stderr, "inbound:", err)
			}
		},
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})

	supervisor, err := ingest.New(sources, ingest.Deps{
		Handle: func(ctx context.Context, ev event.Event) error {
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
		ui, err := web.New(web.Deps{
			Store: db,
			Audit: auditLog,
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
				h := web.Health{}
				for _, st := range delivery.Stats() {
					h.Channels = append(h.Channels, web.ChannelHealth{
						Name: st.Channel, Enabled: true, Depth: st.Depth,
						Pending: st.Pending, Dropped: st.Dropped,
						InFlight: st.InFlight,
					})
				}
				_ = c
				for _, st := range supervisor.Statuses() {
					sh := web.SourceHealth{
						Name:           st.Name,
						LastSeen:       st.LastEventAt,
						ExpectedWithin: st.Expected,
						Silent:         st.Silent,
					}
					switch {
					case st.Fatal != "":
						// Distinct from silent on purpose: a source that
						// cannot run will never recover on its own, and
						// telling an operator it is merely "quiet" sends them
						// looking at the console instead of at the config.
						sh.Detail = "cannot run: " + st.Fatal
						sh.Silent = true
					case st.Restarts > 0:
						sh.Detail = fmt.Sprintf("%d event(s); restarted %d time(s)",
							st.Events, st.Restarts)
					default:
						sh.Detail = fmt.Sprintf("%d event(s)", st.Events)
					}
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
				return nil
			},
			TestChannel: func(ctx context.Context, name string) error {
				return delivery.Test(ctx, name)
			},
			Checklist: func() setup.Input {
				cfgMu.RLock()
				c := current
				cfgMu.RUnlock()

				in := fromConfig(setup.Input{
					DataDir: dataDir, ConfigPath: config.Path(dataDir),
					Listen: "127.0.0.1:8322",
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
			fmt.Printf(`
No settings password is set yet. To set one, open the interface
and enter this one-time setup token:

    %s

It works once, and a new one is printed each time this starts.

`, tok)
		}

		srv := &http.Server{
			Addr:    cfg.Web.Listen,
			Handler: mux,
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

			ackMux := http.NewServeMux()
			ackMux.Handle("/ack/", ackHandler)
			ackSrv := &http.Server{
				Handler:           ackMux,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			go func() {
				if err := ackSrv.Serve(ackLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	var ingestDone sync.WaitGroup
	ingestDone.Add(1)
	go func() {
		defer ingestDone.Done()
		if err := supervisor.Run(ingestCtx); err != nil {
			fmt.Fprintln(os.Stderr, "ingest stopped:", err)
		}
	}()

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
			return serviceCmd("install", dataDir, "")
		}
		fmt.Println("\nTo do it later, from a terminal:  notifymatrix install")

	case st.State == service.StateRunning && !st.RecoversFromCrash:
		// Loud, because this configuration looks completely healthy and will
		// not come back from a panic at 2am.
		fmt.Println(`
WARNING: this service will NOT restart after a crash. It looks healthy right
now and will stay down the next time it falls over, which is the whole thing
you installed it to avoid. Reinstalling fixes it.`)
		if interactive && askYesNo(os.Stdout, in, "Reinstall it now?") {
			if code := serviceCmd("uninstall", dataDir, ""); code != 0 {
				return code
			}
			return serviceCmd("install", dataDir, "")
		}
		fmt.Println("\nTo do it later:  notifymatrix uninstall && notifymatrix install")

	case st.State == service.StateStopped:
		fmt.Println("\nInstalled, but not running -- so nothing is being watched.")
		if interactive && askYesNo(os.Stdout, in, "Start it now?") {
			return serviceCmd("start", dataDir, "")
		}
		fmt.Println("\nTo do it later:  notifymatrix start")

	case st.State == service.StateRunning:
		// Where to go next. Somebody who has just watched it install has no
		// way to know there is a web interface at all, and the address is not
		// guessable -- it is whatever their config says.
		fmt.Printf("\nRunning. The interface is at http://%s/\n", webAddress(dataDir))
	}

	fmt.Printf("\nData directory: %s\n", dataDir)
	fmt.Println("Run `notifymatrix selfcheck` to see what this machine can do.")
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
