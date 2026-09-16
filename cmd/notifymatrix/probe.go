package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/probe"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// probeUsage is printed on a bad invocation and by `probe -h`.
const probeUsage = `notifymatrix probe -- ask a console what it actually exposes

  notifymatrix probe [flags]            survey the console and write a report
  notifymatrix probe submit [flags]     print a report in full and say how to contribute it

Flags:
  --host HOST        console to probe (default: the first console in the config)
  --listen DURATION  how long to listen on each socket (default 30s)
  --products LIST    comma-separated: protect,access,network (default: all)
  --out FILE         where to write the report (default: a timestamped file in the data directory)
  --print            print the whole report after writing it
  --data-dir DIR     where config and reports live

The probe may only be pointed at a local network. There is no flag to change
that; see docs/ARCHITECTURE.md section 10a.

Credentials come from the console entry in the config, and may be overridden
per product with NOTIFYMATRIX_PROTECT_KEY, NOTIFYMATRIX_ACCESS_KEY and
NOTIFYMATRIX_NETWORK_KEY. They are never written to the report.
`

// probeCommand runs `notifymatrix probe`.
//
// It owns its own flag set rather than sharing the main one. The probe has
// flags nothing else wants (--host, --listen, --products) and the main flag
// set is ExitOnError, so passing them through it would simply refuse the
// command.
func probeCommand(defaultDataDir string, args []string) int {
	fs := flag.NewFlagSet("notifymatrix probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		host     = fs.String("host", "", "console to probe")
		listen   = fs.Duration("listen", probe.DefaultListen, "how long to listen on each socket")
		products = fs.String("products", "", "comma-separated subset of protect,access,network")
		out      = fs.String("out", "", "where to write the report")
		printAll = fs.Bool("print", false, "print the whole report after writing it")
		dataDir  = fs.String("data-dir", "", "where config and reports live")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, probeUsage) }

	// The sub-verb is pulled out before parsing for the same reason
	// splitCommand exists: Go's flag package stops at the first non-flag
	// argument, so `probe submit --print` would parse no flags at all and
	// discard them silently.
	sub, flagArgs := splitProbeArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}

	dir := *dataDir
	if dir == "" {
		dir = defaultDataDir
	}

	switch sub {
	case "", "run":
	case "submit":
		return probeSubmit(dir, fs.Arg(0))
	default:
		fmt.Fprintf(os.Stderr, "unknown probe command %q\n\n", sub)
		fmt.Fprint(os.Stderr, probeUsage)
		return 2
	}

	opts, err := probeOptions(dir, *host, *listen, *products)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("probing %s\n", opts.Host)
	fmt.Println("every value that could identify a device, a person or a room is " +
		"replaced before anything is written to disk.")
	fmt.Println()

	report, err := probe.Run(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, probe.ErrNotLocal) {
			fmt.Fprintln(os.Stderr,
				"\nThe probe is a scanner, and pointed at somebody else's network it is an\n"+
					"unauthorised scan run from your machine and your address. It only talks to\n"+
					"local networks, and there is no flag to change that.")
		}
		return 1
	}

	path := *out
	if path == "" {
		path = probe.DefaultPath(dir)
	}
	if err := report.Save(path); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	fmt.Println()
	report.Summarise(os.Stdout)

	if *printAll {
		fmt.Println()
		_ = report.Write(os.Stdout)
	}

	fmt.Printf("\nreport written to %s\n", path)
	fmt.Println("Nothing has been sent anywhere. To contribute it:")
	fmt.Printf("  notifymatrix probe submit %s\n", path)
	return 0
}

// splitProbeArgs separates the probe sub-verb from its flags, wherever the
// verb appears.
func splitProbeArgs(argv []string) (sub string, flags []string) {
	expectsValue := func(arg string) bool {
		if len(arg) == 0 || arg[0] != '-' {
			return false
		}
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			return false
		}
		switch name {
		case "host", "listen", "products", "out", "data-dir":
			return true
		}
		return false
	}
	for i, a := range argv {
		if a == "--" {
			return sub, append(flags, argv[i+1:]...)
		}
		if sub == "" && a != "" && a[0] != '-' {
			if i > 0 && expectsValue(argv[i-1]) {
				flags = append(flags, a)
				continue
			}
			sub = a
			continue
		}
		flags = append(flags, a)
	}
	return sub, flags
}

// probeOptions assembles a run from the config, the flags and the environment.
func probeOptions(dir, host string, listen time.Duration, products string) (probe.Options, error) {
	opts := probe.Options{
		Listen:  listen,
		Version: version,
		Progress: func(s string) {
			if s == "" {
				fmt.Println()
				return
			}
			fmt.Println("  " + s)
		},
	}
	if products != "" {
		for _, p := range strings.Split(products, ",") {
			if p = strings.TrimSpace(p); p != "" {
				opts.Products = append(opts.Products, p)
			}
		}
	}

	// A missing or unreadable config is not fatal: an operator probing a
	// console they have not configured yet is the normal first use of this
	// command, and refusing them would make it useless exactly when it helps.
	cfg, err := config.Load(dir)
	if err != nil {
		cfg = nil
	}

	var key secret.Secret
	if cfg != nil {
		for _, c := range cfg.Consoles {
			if host == "" || strings.EqualFold(c.Host, host) || strings.EqualFold(c.Name, host) {
				host = c.Host
				key, _ = c.ResolveAPIKey()
				break
			}
		}
	}
	if host == "" {
		return opts, errors.New("no console to probe: pass --host, or configure one first")
	}
	opts.Host = host

	// One key per console in the config, because Protect, Access and Network
	// are applications behind one host. In practice the console issues a
	// separate integration key per application, so each may be overridden --
	// and a 401 from a product whose key is wrong is itself a recorded finding
	// rather than a failure.
	opts.ProtectKey = envKey("NOTIFYMATRIX_PROTECT_KEY", key)
	opts.AccessKey = envKey("NOTIFYMATRIX_ACCESS_KEY", key)
	opts.NetworkKey = envKey("NOTIFYMATRIX_NETWORK_KEY", key)
	return opts, nil
}

func envKey(name string, fallback secret.Secret) secret.Secret {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return secret.Secret(v)
	}
	return fallback
}

// probeSubmit prints a report in full and explains how to contribute it.
//
// PRINTING IS THE POINT, and it is why this is a separate command rather than
// a prompt at the end of a run. The pipeline is capture, redact, show the
// operator, submit -- and "show the operator" means the exact bytes that would
// be published, not a summary of them. A summary is the thing somebody skims.
func probeSubmit(dir, path string) int {
	if path == "" {
		latest, err := latestReport(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		path = latest
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer f.Close()

	fmt.Printf("---- %s ----\n", path)
	if _, err := io.Copy(os.Stdout, f); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("---- end of %s ----\n\n", path)

	fmt.Println("That is the whole file, exactly as it would be published.")
	fmt.Println("Read it before you contribute it. It should contain no camera names, no")
	fmt.Println("door names, no MAC addresses and no IP addresses -- only field names,")
	fmt.Println("types, UniFi's own vocabulary, and your console's firmware version.")
	fmt.Println()
	fmt.Println("If anything in it identifies your site, that is a bug in this tool and")
	fmt.Println("reporting it matters more than the contribution does.")
	fmt.Println()
	fmt.Println("To contribute, open an issue and attach the file:")
	fmt.Println("  https://github.com/suburbazine/Unifi-Notification-Matrix/issues/new")
	fmt.Println()
	fmt.Println("Nothing is uploaded by this command. This product never phones home,")
	fmt.Println("and a probe that submitted on its own would make that false.")
	return 0
}

// latestReport finds the newest report in the data directory.
func latestReport(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "probe-*.jsonl"))
	if err != nil || len(matches) == 0 {
		return "", fmt.Errorf("no report found in %s: run `notifymatrix probe` first, "+
			"or name a file", dir)
	}
	// Timestamped names sort chronologically, which is the whole reason they
	// are timestamped.
	newest := matches[0]
	for _, m := range matches {
		if m > newest {
			newest = m
		}
	}
	return newest, nil
}
