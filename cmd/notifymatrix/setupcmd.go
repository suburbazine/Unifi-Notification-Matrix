package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/inbound"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
)

// setupCmd prints the whole checklist.
func setupCmd(dataDir string, full bool) int {
	in := setupInput(dataDir)
	fmt.Printf("notifymatrix %s — setup\n", version)
	fmt.Printf("configuration: %s\n\n", in.ConfigPath)

	var b strings.Builder
	setup.Render(&b, in, full)
	fmt.Print(b.String())

	if !full {
		fmt.Println("Steps already done are listed without their instructions.")
		fmt.Println("Run `notifymatrix setup --all` to see every step in full.")
	}
	return 0
}

// setupInput assembles the assessment from the config, the service manager and
// -- when the daemon is up — the daemon itself.
func setupInput(dataDir string) setup.Input {
	in := setup.Input{
		DataDir:    dataDir,
		ConfigPath: config.Path(dataDir),
		Listen:     "127.0.0.1:8322",
		// The name they must actually type, which for a downloaded binary is
		// not "notifymatrix" and is not on PATH.
		Exe: typeableExeName(),
	}

	// LoadOrCreate rather than Load: on a fresh machine there is no config
	// file yet, and telling somebody to edit a file that does not exist is
	// exactly the kind of instruction this command exists to replace. Creating
	// it writes the annotated template (see config/header.go), so the next
	// thing they open already explains itself.
	//
	// Falls back to a plain read when the directory is not writable -- running
	// this without administrator rights against the service's data directory
	// must still answer the question.
	cfg, err := config.LoadOrCreate(dataDir)
	if err != nil {
		cfg, err = config.Load(dataDir)
	}
	if err == nil && cfg != nil {
		in = fromConfig(in, cfg)
	}

	if st, err := service.New().Status(); err == nil {
		in.ServiceInstalled = st.State != service.StateNotInstalled
		in.ServiceRunning = st.State == service.StateRunning
		in.RecoversFromCrash = st.RecoversFromCrash
	}

	// The receipts live in the running daemon's memory, so a config-only
	// answer would say "nothing has ever arrived" for a hook that is working
	// perfectly. Asked for, and skipped silently if nothing is listening --
	// the checklist must still be useful when the service is stopped.
	enrichFromDaemon(&in)
	return in
}

// hookBase is the address a UniFi console must POST an alarm to.
//
// IT IS NOT ack_base_url, and it used to be. That address belongs to the
// acknowledgement LINKS, which is a different listener and often a different
// network entirely:
//
//   - The hook receiver is mounted on the MAIN listener, beside the interface,
//     on web.listen.
//   - web.ack_listen, when set, starts a SECOND listener that serves only
//     /ack/ and answers everything else with 404. That is the whole point of
//     it -- it exists so a port forward can publish acknowledgements without
//     publishing the status page and the settings sign-in.
//
// So on the configuration the setup checklist actively recommends -- an
// ack_base_url pointing at a forwarded port, scoped with ack_listen -- the
// hook URL came out as https://alerts.example.com/hook/<token>, which reaches
// the ack-only listener and 404s. And the receiver answers every unknown path
// with a bare 404 by design, so the operator sees a rule that looks perfect at
// the UniFi end, nothing arriving, and no rejection recorded either, because
// the request never reached the receiver at all. Steps 4 and 5 of the
// checklist are adjacent: doing what it says produced the failure.
//
// The second error was quieter and would have survived the first being fixed:
// it sent a console sitting on the same LAN out to a public hostname and back,
// over plain http, to reach a machine in the same building.
func hookBase(in setup.Input) string {
	port := setup.ListenPort(in.Listen)
	if port == "" {
		port = "8322"
	}

	// A listener bound to one specific address is already the answer, and is
	// more likely to be right than anything guessed from the interface list.
	if host, _, err := net.SplitHostPort(strings.TrimSpace(in.Listen)); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			return "http://" + net.JoinHostPort(host, port)
		}
	}

	// Bound to everything, or to loopback. Either way the console needs this
	// machine's address on the network it shares with it. Loopback is a
	// misconfiguration rather than an address to print -- the checklist says
	// so at the step that fixes it -- but the LAN address is still the one
	// they will need once they have.
	if lan := setup.LocalAddress(); lan != "" {
		return "http://" + net.JoinHostPort(lan, port)
	}
	return "http://<this machine's LAN address>:" + port
}

func fromConfig(in setup.Input, cfg *config.Config) setup.Input {
	in.Consoles = len(cfg.Consoles)
	seen := map[string]bool{}
	in.HasConsoleKey = len(cfg.Consoles) > 0
	for _, con := range cfg.Consoles {
		if key, _ := con.ResolveAPIKey(); key.IsZero() {
			in.HasConsoleKey = false
		}
		for _, s := range con.Sources {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" && !seen[s] {
				seen[s] = true
				in.SourceNames = append(in.SourceNames, s)
			}
		}
	}

	// One list, built in one place: a second hand-maintained copy would drift
	// and the checklist would disagree with the validator about whether
	// anything can be delivered.
	in.ChannelsEnabled = cfg.EnabledChannelNames()

	in.AckBaseURL = cfg.Web.AckBaseURL
	in.AckListen = strings.TrimSpace(cfg.Web.AckListen)
	in.AckScoped = in.AckListen != ""
	in.PublicAckURL = config.LooksInternetFacing(cfg.Web.AckBaseURL)
	if cfg.Web.Listen != "" {
		in.Listen = cfg.Web.Listen
	}
	in.PasswordSet = cfg.Web.PasswordHash != ""

	// The URL carries the token, so it is only rendered here -- on a machine
	// that already has the config file open. The daemon's public status
	// endpoint reports the hook's NAME and whether anything arrived, never the
	// URL.
	base := hookBase(in)
	for _, h := range config.BuildHooks(cfg) {
		in.Hooks = append(in.Hooks, setup.HookState{
			Name: h.Name, Product: h.Product,
			URL:    inbound.URLFor(base, h),
			Header: inbound.HeaderValueFor(h),
		})
	}
	return in
}

// daemonSetup is the shape the running daemon reports.
type daemonSetup struct {
	Hooks []struct {
		Name       string    `json:"name"`
		Count      int64     `json:"count"`
		LastAt     time.Time `json:"last_at"`
		Rejected   int64     `json:"rejected"`
		LastReject string    `json:"last_reject"`
	} `json:"hooks"`
	Sources []struct {
		Name   string `json:"name"`
		Silent bool   `json:"silent"`
		Detail string `json:"detail"`
		Events int64  `json:"events"`
	} `json:"sources"`
}

// enrichFromDaemon fills in what only the running process knows.
func enrichFromDaemon(in *setup.Input) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + in.Listen + "/api/checklist")
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var d daemonSetup
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return
	}
	for _, h := range d.Hooks {
		for i := range in.Hooks {
			if in.Hooks[i].Name == h.Name {
				in.Hooks[i].Count = h.Count
				in.Hooks[i].LastAt = h.LastAt
				in.Hooks[i].Rejected = h.Rejected
				in.Hooks[i].LastReject = h.LastReject
			}
		}
	}
	for _, s := range d.Sources {
		st := setup.SourceState{Name: s.Name, Silent: s.Silent, Events: s.Events}
		if strings.HasPrefix(s.Detail, "cannot run: ") {
			st.Fatal = strings.TrimPrefix(s.Detail, "cannot run: ")
		}
		in.SourcesLive = append(in.SourcesLive, st)
	}
}

// setupSummary is the short form printed by the first-run screen.
func setupSummary(w *os.File, in setup.Input) {
	remaining := setup.Remaining(in)
	if len(remaining) == 0 {
		fmt.Fprintln(w, "\nSetup is complete.")
		return
	}
	if setup.Ready(in) {
		fmt.Fprintf(w, "\nThis installation can raise and deliver an alarm. "+
			"%d step(s) would make it better:\n", len(remaining))
	} else {
		fmt.Fprintf(w, "\nNOT READY: this cannot deliver an alarm yet. "+
			"%d step(s) remain:\n", len(remaining))
	}
	for _, s := range remaining {
		mark := "  - "
		if s.Status == setup.Todo {
			mark = "  ! "
		}
		fmt.Fprintf(w, "%s%s", mark, s.Title)
		if s.State != "" {
			fmt.Fprintf(w, " (%s)", s.State)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "\nRun `notifymatrix setup` for step-by-step instructions.")
}
