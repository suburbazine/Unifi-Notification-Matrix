package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/probe"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// Wiring the probe to the interface.
//
// The precondition is the reason this exists. A console with no integration
// key answers every request with its login page, and a run against one burns
// the capture window -- the ninety seconds somebody spends deliberately
// walking past their own cameras -- to produce a file that describes this
// build's catalogue and nothing about their site.
//
// The daemon holds the configuration. It knows before the button is pressed.

// maxProbeReportBytes bounds what the page will read back. A real report is a
// few tens of kilobytes; this is far above that and exists so a file that has
// been replaced with something else cannot be loaded into the daemon whole.
const maxProbeReportBytes = 8 << 20

type probeDeps struct {
	dataDir string
	version string
	cfg     func() *config.Config
	runner  *probe.Runner
}

func newProbeDeps(dataDir, version string, cfg func() *config.Config) *probeDeps {
	return &probeDeps{
		dataDir: dataDir,
		version: version,
		cfg:     cfg,
		runner:  probe.NewRunner(dataDir),
	}
}

// status is what the Probe section reads on every poll.
func (p *probeDeps) status() web.ProbeStatus {
	st := web.ProbeStatus{Available: true, Consoles: []web.ProbeConsole{}}

	cfg := p.cfg()
	if cfg != nil {
		for _, c := range cfg.Consoles {
			// Any key that would be sent to any application counts: a
			// console carrying only a Protect key can still be probed, and
			// saying otherwise would block the run that would have worked.
			st.Consoles = append(st.Consoles, web.ProbeConsole{
				Name: c.Name, Host: c.Host,
				HasKey: consoleHasAnyKey(c), Sources: c.Sources,
			})
		}
	}

	// THE SENTENCE THAT WOULD HAVE SAVED THE WINDOW. Written for somebody who
	// has not been told what an integration key is, and naming the place they
	// would go to fix it.
	switch {
	case len(st.Consoles) == 0:
		st.Blocked = "No console is configured yet. Add one under Consoles first; " +
			"the probe asks a console what it can do, so it needs one to ask."
	case !anyKey(st.Consoles):
		st.Blocked = "No console here has an API key. A console without one answers " +
			"every request with its login page, so a probe would spend its capture " +
			"window learning nothing. Create an integration key in the UniFi " +
			"console and save it under Consoles."
	default:
		st.Ready = true
	}

	prog := p.runner.Snapshot()
	st.Running = prog.Running
	st.Lines = prog.Lines
	st.StartedAt = prog.StartedAt
	st.EndedAt = prog.EndedAt
	st.Error = prog.Error
	st.LastReport = prog.Report
	st.LastAuthenticated = prog.Authenticated

	list, err := probe.ListReports(p.dataDir, 20)
	if err != nil {
		st.Detail = "the report directory could not be read"
	}
	st.Reports = make([]web.ProbeReportInfo, 0, len(list))
	for _, r := range list {
		st.Reports = append(st.Reports, web.ProbeReportInfo{
			Name: r.Name, At: r.At, Size: r.Size,
			Authenticated: r.Authenticated, Findings: r.Findings,
			Unreadable: r.Unreadable,
		})
	}
	return st
}

// consoleHasAnyKey reports whether this console could authenticate anywhere:
// its own key, or a key for any one application.
func consoleHasAnyKey(c config.Console) bool {
	for _, product := range []string{"protect", "access", "network"} {
		if k, _ := c.KeyFor(product); !k.IsZero() {
			return true
		}
	}
	return false
}

func anyKey(cs []web.ProbeConsole) bool {
	for _, c := range cs {
		if c.HasKey {
			return true
		}
	}
	return false
}

// start resolves the named console and runs against it.
//
// BY NAME, NOT BY HOST. From a terminal the host is the operator's to type;
// from a page the console is one they already configured, and resolving it
// here is what keeps a key from being sent to a host it does not belong to.
func (p *probeDeps) start(name string, listen time.Duration, products []string) error {
	cfg := p.cfg()
	if cfg == nil || len(cfg.Consoles) == 0 {
		return errors.New("no console is configured to probe")
	}

	var chosen *config.Console
	for i := range cfg.Consoles {
		c := &cfg.Consoles[i]
		if name == "" {
			// No console named: the first one that could actually answer.
			if key, _ := c.ResolveAPIKey(); !key.IsZero() {
				chosen = c
				break
			}
			continue
		}
		if strings.EqualFold(c.Name, name) {
			chosen = c
			break
		}
	}
	if chosen == nil {
		if name == "" {
			return errors.New("no configured console has an API key yet")
		}
		return fmt.Errorf("no console called %q is configured", name)
	}

	protectKey, _ := chosen.KeyFor("protect")
	accessKey, _ := chosen.KeyFor("access")
	networkKey, _ := chosen.KeyFor("network")
	if protectKey.IsZero() && accessKey.IsZero() && networkKey.IsZero() {
		// Refused rather than run. This is the whole point of the section:
		// the run would reach the login page and report nothing.
		return fmt.Errorf("%s has no API key, so a probe would only reach its "+
			"login page; create an integration key in the console and save it "+
			"under Consoles first", chosen.Name)
	}

	err := p.runner.Start(probe.Options{
		Host:       chosen.Host,
		ProtectKey: protectKey,
		AccessKey:  accessKey,
		NetworkKey: networkKey,
		Listen:     listen,
		Products:   products,
		Version:    p.version,
	})
	if errors.Is(err, probe.ErrBusy) {
		return web.ErrProbeBusy
	}
	return err
}

func (p *probeDeps) stop() { p.runner.Stop() }

// read returns one report's bytes for the page to show or hand over.
//
// The name is validated again here, after the handler has already validated
// it. Cheap, and this is the function that turns a string from a URL into a
// path on disk.
func (p *probeDeps) read(name string) ([]byte, error) {
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") ||
		!strings.HasPrefix(name, "probe-") || !strings.HasSuffix(name, ".jsonl") {
		return nil, errors.New("not a report name")
	}
	f, err := os.Open(filepath.Join(p.dataDir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	body, err := io.ReadAll(io.LimitReader(f, maxProbeReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxProbeReportBytes {
		return nil, errors.New("that file is too large to be a report")
	}
	return body, nil
}
