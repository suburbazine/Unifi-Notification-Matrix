// Package setup works out what is still needed to make this product actually
// work, and says so in words a person who has never used it can follow.
//
// It exists because of a gap that is easy to miss when you wrote the thing:
// every individual surface in this product tells you what is WRONG, and none
// of them told you what to DO. A config file that validates, a service that is
// running and a status page that is green can all coexist with a product that
// will never raise an alarm, because nobody added a console, or enabled a
// channel, or made the Alarm Manager rule that is the only way Network events
// exist at all.
//
// One assessment, rendered in several places -- the terminal, the first-run
// screen, the interface -- so they cannot drift apart and disagree with each
// other about what is left to do.
package setup

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// HeaderName is the header a console must send alongside the hook URL. Mirrors
// inbound.HeaderName, which this package does not import -- Input is plain
// data so the CLI and the interface can both fill it without either reaching
// into the other.
const HeaderName = "Authorization"

// Status is how far along one step is.
type Status string

const (
	// Done means this step needs nothing further.
	Done Status = "done"

	// Todo means the product will not do its job until this is finished.
	Todo Status = "todo"

	// Optional means it works without this, but worse, and the operator should
	// know what they are choosing.
	Optional Status = "optional"

	// Unverified is the one that matters for webhooks: it is configured here,
	// it looks right, and NOTHING HAS EVER ARRIVED. Because Alarm Manager
	// rules can only be created in the UniFi UI, a configuration that looks
	// complete is not evidence that anybody made the rule.
	Unverified Status = "unverified"
)

// Step is one thing to do, with the reason and the exact actions.
type Step struct {
	// Title is the short name of the step.
	Title string

	Status Status

	// Why is what goes wrong if this is skipped. Present on every step,
	// because "do this" without "or else" is an instruction people postpone.
	Why string

	// State is what is true right now -- "2 consoles configured", "nothing has
	// arrived yet".
	State string

	// How are the exact actions, in order. Written for somebody who has not
	// used UniFi's interface before: named menus, named buttons, and the
	// literal text to paste.
	How []string
}

// Input is everything the assessment needs to know.
//
// Plain data rather than the config type, so this package can be rendered by
// the CLI and the web UI without either of them reaching into the other.
type Input struct {
	DataDir    string
	ConfigPath string

	Consoles      int
	SourceNames   []string
	HasConsoleKey bool

	ChannelsEnabled []string
	AckBaseURL      string
	Listen          string

	// AckListen is the ack-only listener, when one is configured. AckScoped
	// says a forward has something safe to point at; PublicAckURL says the
	// acknowledgement address looks reachable from the internet.
	//
	// Both matter only together: a public address with nothing scoping it is
	// the state where a port forward publishes the status page, and neither
	// fact alone says that.
	AckListen    string
	AckScoped    bool
	PublicAckURL bool

	PasswordSet bool

	// Exe is what the operator must actually TYPE to run this program.
	//
	// Every instruction here used to read "notifymatrix install". Nobody has a
	// program called that: they have `notifymatrix-windows-amd64 (1).exe` in
	// Downloads, and it is not on PATH, so every command in this checklist
	// failed with "not recognized" for anybody who had not already solved a
	// problem the checklist never mentioned.
	//
	// Empty means the plain name, which is right for a packaged install.
	Exe string

	// Hooks are the configured webhook endpoints and whether anything has ever
	// arrived at each.
	Hooks []HookState

	// ServiceInstalled and ServiceRunning describe the supervised process.
	ServiceInstalled  bool
	ServiceRunning    bool
	RecoversFromCrash bool

	// SourcesLive is what the running daemon's ingest supervisor reports.
	SourcesLive []SourceState
}

// HookState is one webhook and its evidence.
type HookState struct {
	Name    string
	Product string
	URL     string

	// Header is the Authorization header the console must also send. A URL is
	// not an authenticator, so a hook needs both -- and an operator who pastes
	// only the URL gets silence, which is the case this field exists to make
	// diagnosable.
	Header string

	Count  int64
	LastAt time.Time

	// Rejected counts arrivals that reached the URL and were refused. Almost
	// always the missing header, and almost always the whole answer to "I made
	// the rule and nothing happens".
	Rejected   int64
	LastReject string
}

// SourceState is one running source.
type SourceState struct {
	Name   string
	Silent bool
	Fatal  string
	Events int64
}

// Steps returns the checklist, in the order somebody should do them.
func Steps(in Input) []Step {
	return []Step{
		consoleStep(in),
		sourcesStep(in),
		channelStep(in),
		ackStep(in),
		hooksStep(in),
		passwordStep(in),
		serviceStep(in),
	}
}

// Remaining is the steps that are not Done, for a short prompt.
func Remaining(in Input) []Step {
	var out []Step
	for _, s := range Steps(in) {
		if s.Status != Done {
			out = append(out, s)
		}
	}
	return out
}

// Ready reports whether this installation can raise and deliver an alarm.
//
// Deliberately NOT "everything is done". A product with a console, a source
// and a channel works; the rest makes it better. Telling somebody they are not
// ready when they are is how a checklist gets ignored.
func Ready(in Input) bool {
	return in.Consoles > 0 && in.HasConsoleKey &&
		len(in.SourceNames) > 0 && len(in.ChannelsEnabled) > 0
}

func consoleStep(in Input) Step {
	s := Step{
		Title: "Add your UniFi console",
		Why: "Without a console there is nothing to watch, and this product " +
			"will run happily forever without ever raising anything.",
		How: []string{
			"In a browser, open your UniFi console (the box itself, not unifi.ui.com).",
			"Go to Settings > Control Plane > Integrations.",
			"Create an API key for each application you want watched. Protect, " +
				"Access and Network each issue their OWN key -- one key does not " +
				"cover the others.",
			"Copy the key immediately. The console shows it once and never again.",
			"Open " + in.ConfigPath + " and add a console entry with its address " +
				"and key, or add it in the interface at http://" + listenOr(in.Listen) + "/.",
		},
	}
	switch {
	case in.Consoles == 0:
		s.Status, s.State = Todo, "no console configured"
	case !in.HasConsoleKey:
		s.Status, s.State = Todo, fmt.Sprintf("%d console(s) configured, but one has no API key", in.Consoles)
	default:
		s.Status, s.State = Done, fmt.Sprintf("%d console(s) configured", in.Consoles)
	}
	return s
}

func sourcesStep(in Input) Step {
	s := Step{
		Title: "Choose what to watch",
		Why: "A console with no sources enabled is polled for nothing. This is " +
			"the setting people most often leave empty, because the console " +
			"itself looks correctly configured either way.",
		How: []string{
			"On the console entry, list the applications to watch: protect, access, network.",
			"protect -- cameras, sensors, doorbells, alarm hubs. Pushed live.",
			"access  -- doors: forced open, held open, refused credentials.",
			"network -- switches and access points going offline. WAN outages " +
				"and threats need a webhook as well; see the webhook step.",
		},
	}
	switch {
	case len(in.SourceNames) == 0:
		s.Status, s.State = Todo, "no sources enabled on any console"
	default:
		s.Status, s.State = Done, strings.Join(in.SourceNames, ", ")
	}

	// A source that is running and broken is more urgent than one that is
	// merely unconfigured, so it overrides the state text.
	for _, live := range in.SourcesLive {
		if live.Fatal != "" {
			s.Status = Todo
			s.State = live.Name + " cannot run: " + live.Fatal
			break
		}
	}
	return s
}

func channelStep(in Input) Step {
	s := Step{
		Title: "Set up a way to be told",
		Why: "With no channel enabled, incidents are still tracked but nobody is " +
			"ever told about them -- which is the one failure this product exists " +
			"to prevent.",
		How: []string{
			"ntfy is the quickest: install the ntfy app on your phone, subscribe " +
				"to a topic name nobody could guess, and put that topic in the config.",
			"A guessable topic on the public ntfy.sh server is readable by anyone " +
				"who guesses it. Treat the topic name as a password.",
			"pushover is the other good phone option. It needs TWO credentials and " +
				"they are easy to swap: the application token you create at " +
				"pushover.net/apps/build, and your own user key from the dashboard. " +
				"Swapped, Pushover says the application token is invalid, which " +
				"reads as a bad token rather than as the pair being reversed.",
			"email works too, and needs an SMTP server, a username and a password.",
			"webhook sends one JSON document per alert to anything you run -- Home " +
				"Assistant, Node-RED, a script of your own. Set a signing secret " +
				"unless you want anyone who learns the URL to be able to feed you " +
				"false alarms.",
			"Enable at least one. Two is better: a phone that is asleep and a " +
				"mailbox that is not fail differently.",
			"Then press \"Send a test\" on each one in the interface. It reports " +
				"what happened to that attempt, including the service's own error, " +
				"which usually says exactly what to change.",
		},
	}
	if len(in.ChannelsEnabled) == 0 {
		s.Status, s.State = Todo, "no channel enabled -- nothing can be delivered"
		return s
	}
	s.Status, s.State = Done, strings.Join(in.ChannelsEnabled, ", ")
	if len(in.ChannelsEnabled) == 1 {
		s.Status = Optional
		s.State += " (one channel: if it fails, nobody is told)"
	}
	return s
}

func ackStep(in Input) Step {
	s := Step{
		Title: "Make the acknowledgement links work",
		Why: "Alerts carry a link that stops the escalation. If this address is " +
			"wrong, the link in a 3am notification opens nothing on the phone " +
			"holding it, and the only way to stop the alert is to reach a computer " +
			"on the same network -- which, if nobody is at the site, means nobody " +
			"can stop it at all.",
		How: []string{
			"Set web.ack_base_url to an address the phone can actually reach.",
			"If the phone is on the same network: this machine's LAN address, " +
				"not 127.0.0.1 -- for example http://192.168.1.50:8322",
		},
	}

	// The off-site case, which is the one that turns a configuration question
	// into a security question.
	s.How = append(s.How,
		"IF SOMEBODY MAY BE AWAY FROM THE SITE, that address has to be reachable "+
			"from outside, and there are two ways to do it.",
		"BEST: a VPN. WireGuard or Tailscale, on the phone. Nothing is forwarded, "+
			"nothing is exposed, and the ack address is just the VPN address of "+
			"this machine. Tailscale in particular needs no firewall change at all.",
		"IF YOU MUST FORWARD A PORT, scope it. A NAT forward CANNOT restrict by "+
			"path -- forwarding the main port publishes the status page, which "+
			"names your cameras, doors and open alarms, and the settings sign-in, "+
			"to the entire internet.",
		"So set web.ack_listen to \"auto\". A second listener starts on a random "+
			"high port that serves ONLY /ack/ -- everything else on it is a 404. "+
			"The port is written back to the configuration on first start and then "+
			"never changes, so the firewall rule and the links already sent stay "+
			"valid.",
		"Forward ONLY that port, from the internet to this machine, TCP only. Do "+
			"not forward web.listen. Do not put this machine in a DMZ.",
		"Put TLS in front of it. The acknowledgement token travels in the URL, so "+
			"over plain http anyone on the path can read it and silence an alarm. "+
			"A reverse proxy that obtains a certificate automatically (Caddy, "+
			"nginx with certbot) is the usual answer. If that is more than you "+
			"want to run, use the VPN option instead -- it is genuinely easier.",
		"Then set web.ack_base_url to the public address, and check it from a "+
			"phone on mobile data with Wi-Fi off. That is the only test that "+
			"matches the situation it exists for.",
	)

	switch {
	case strings.TrimSpace(in.AckBaseURL) == "":
		s.Status, s.State = Todo, "not set -- alerts will carry no acknowledgement link"
	case strings.Contains(in.AckBaseURL, "127.0.0.1"), strings.Contains(in.AckBaseURL, "localhost"):
		s.Status = Todo
		s.State = in.AckBaseURL + " -- only works on this machine, so the link " +
			"in a phone notification will not open"
	case in.PublicAckURL && !in.AckScoped:
		// The dangerous middle state: a public address, and nothing scoping
		// what is published on it.
		s.Status = Todo
		s.State = in.AckBaseURL + " looks public, but web.ack_listen is not set -- " +
			"if a port is forwarded to the main listener then the status page and " +
			"the settings sign-in are on the internet too"
	case in.PublicAckURL && strings.HasPrefix(strings.ToLower(in.AckBaseURL), "http://"):
		s.Status = Optional
		s.State = in.AckBaseURL + " is public over plain http -- the acknowledgement " +
			"token is in the URL and readable in transit"
	default:
		s.Status, s.State = Done, in.AckBaseURL
		if in.AckScoped {
			s.State += " (acknowledgements scoped to " + in.AckListen + ")"
		}
	}
	return s
}

// hooksTitle is referenced by Render, so the URLs are printed under the right
// step without matching on prose.
const hooksTitle = "Create the UniFi Alarm Manager rules"

func hooksStep(in Input) Step {
	s := Step{
		Title: hooksTitle,
		Why: "WAN outages, threat detections, PoE faults and Protect's own " +
			"hardware alarms are not readable by any API. They exist ONLY as " +
			"Alarm Manager rules that push to a URL, and no API can create " +
			"those rules -- so if nobody makes them by hand, those alarms will " +
			"never reach this product at all.",
	}

	if len(in.Hooks) == 0 {
		s.Status = Optional
		s.State = "no webhooks configured"
		s.How = []string{
			"Add a hook to the config with a name matching the rule you are about " +
				"to create, and restart. A URL will be generated for it.",
			"Then follow the steps this screen will show you.",
			"Skip this only if you do not need WAN, threat, PoE or NVR-hardware alarms.",
		}
		return s
	}

	var arrived, waiting []string
	for _, h := range in.Hooks {
		if h.Count > 0 {
			arrived = append(arrived, h.Name)
			continue
		}
		waiting = append(waiting, h.Name)
	}

	s.How = []string{
		"In the UniFi console, open the application (Network, Protect or Access) " +
			"and go to Settings > Alarm Manager. In Network it may be called " +
			"Alarms, under Settings > System.",
		"Create one alarm. Pick the trigger you want -- for example WAN Offline.",
		"For the action, choose Webhook, and set the method to POST.",
		"Paste the URL for the matching hook below into the Delivery URL field.",
		"ADD THE HEADER TOO. Both are listed below. A URL on its own is not a " +
			"password -- it goes through this form, the console's configuration " +
			"backup, your browser history and every proxy log on the way. The " +
			"header does not, so this product requires both and there is no way " +
			"to turn that off.",
		"In Alarm Manager's webhook action, add a custom header with the name " +
			"and value shown below.",
		"Save the rule, then press Test. This screen will say the alarm arrived.",
		"A test alarm raises a REAL incident here, on purpose: that is what proves " +
			"the whole chain works, including the notification on your phone. " +
			"Acknowledge it and you are done.",
		"If nothing arrives, look at the line below each URL. \"Refused\" means " +
			"the console IS reaching us and the header is wrong or missing -- " +
			"which is a different problem from the rule not firing at all.",
	}
	s.How = append(s.How,
		"The URL for each hook is listed separately below. They are credentials: "+
			"anyone who has one can raise an alarm on this system.")

	// THE URLS ARE DELIBERATELY NOT IN THIS LIST. They live only on
	// Input.Hooks, so there is exactly one field a caller reads them from and
	// exactly one place to gate. An earlier version wrote them into these
	// instruction lines as well, which published every token through the
	// PUBLIC checklist endpoint -- the url field was gated and the prose
	// beside it was not. A test on the raw response body found it.

	// A refusal is a much better clue than silence, so it leads.
	var refused []string
	for _, h := range in.Hooks {
		if h.Count == 0 && h.Rejected > 0 {
			refused = append(refused, h.Name)
		}
	}

	switch {
	case len(refused) > 0:
		s.Status = Todo
		s.State = "the console IS reaching " + strings.Join(refused, ", ") +
			" and being refused -- the Authorization header is missing or wrong"
	case len(arrived) == 0:
		s.Status = Unverified
		s.State = "configured, but nothing has ever arrived at " +
			strings.Join(waiting, ", ") + " -- the rule may not exist yet"
	case len(waiting) > 0:
		s.Status = Unverified
		s.State = "received on " + strings.Join(arrived, ", ") +
			"; nothing yet on " + strings.Join(waiting, ", ")
	default:
		s.Status = Done
		s.State = "alarms have arrived on every hook"
	}
	return s
}

func passwordStep(in Input) Step {
	s := Step{
		Title: "Set a password for the settings page",
		Why: "Anyone on your network can read the status page. That is deliberate " +
			"-- it makes a wall display useful -- but changing settings, " +
			"acknowledging alarms and reading the audit record must not be open " +
			"to everyone.",
	}

	// Which route works depends entirely on whether this is already a service,
	// and only one of them is possible at a time.
	//
	// The token is printed to the daemon's stdout. A service HAS no stdout --
	// on Windows it is not redirected anywhere, it does not exist -- so once
	// installed, the token is minted into a void and no amount of restarting
	// will show it to anybody. Telling an operator in that position to "enter
	// the token the daemon printed" is telling them to find something that was
	// never displayed, and it was the only instruction here.
	if in.ServiceInstalled {
		s.How = []string{
			"Run: " + in.Command("set-password"),
			"Or, to use the one-time token the service could not print: " +
				in.Command("setup-token") + " -- it needs administrator rights and " +
				"will ask for them, because being in the Administrators group is " +
				"not enough until a process elevates.",
			"It asks twice, does not echo, and writes the password straight to " +
				"the configuration.",
			"It offers to restart the service afterwards, which is required: a " +
				"running daemon is still holding the old configuration.",
			"Then open http://" + listenOr(in.Listen) + "/ and sign in.",
		}
	} else {
		s.How = []string{
			"Open http://" + listenOr(in.Listen) + "/ in a browser.",
			"The daemon prints a one-time setup token each time it starts. Enter it.",
			"Choose a password. The token then stops working.",
			"Or, if you would rather not use the token: " + in.Command("set-password"),
		}
	}

	if in.PasswordSet {
		s.Status, s.State = Done, "set"
		return s
	}
	s.Status = Todo
	if in.ServiceInstalled {
		s.State = "not set -- and the setup token is not reachable while it runs as a service"
	} else {
		s.State = "not set -- the settings page is waiting for a setup token"
	}
	return s
}

func serviceStep(in Input) Step {
	s := Step{
		Title: "Install it as a service",
		Why: "Run from a terminal, it stops when you close the window, when you " +
			"log out, and when the machine reboots -- and it will not be watching " +
			"anything during the night that matters.",
		How: []string{
			"Run: " + in.Command("install"),
			"It will ask for administrator rights, install itself to start at boot, " +
				"and configure itself to restart after a crash.",
			"Check it afterwards with: " + in.Command("status"),
		},
	}
	switch {
	case !in.ServiceInstalled:
		s.Status, s.State = Todo, "not installed -- it will stop when you close this window"
	case !in.ServiceRunning:
		s.Status, s.State = Todo, "installed but not running ("+in.Command("start")+")"
	case !in.RecoversFromCrash:
		// Loud, because this configuration looks completely healthy and will
		// not come back from a crash at 2am.
		s.Status = Todo
		s.State = "running, but will NOT restart after a crash -- reinstall to fix"
	default:
		s.Status, s.State = Done, "running, and restarts after a crash"
	}
	return s
}

// command renders "<exe> verb" as something that can be pasted into a shell.
//
// A downloaded binary is named after its platform and often carries a " (1)"
// from a second download, so the name needs quoting far more often than not.
// Command is exported so the CLI renders the same command text this checklist
// does; two different answers to "what do I type" is worse than neither.
func (in Input) Command(verb string) string {
	exe := strings.TrimSpace(in.Exe)
	if exe == "" {
		return "notifymatrix " + verb
	}
	if strings.ContainsAny(exe, " ()&^%!,;=") {
		// PowerShell needs the call operator before a quoted path, or it
		// treats the string as a string and prints it back at you.
		return `& ".\` + exe + `" ` + verb
	}
	return exe + " " + verb
}

func listenOr(listen string) string {
	if strings.TrimSpace(listen) == "" {
		return "127.0.0.1:8322"
	}
	return listen
}

// Render writes the checklist as plain text.
//
// Verbose on purpose. The audience is somebody who has not done this before,
// on a product whose failure mode is silence -- so every step says what it is
// for, what is true now, and exactly what to type or click.
func Render(w io.StringWriter, in Input, full bool) {
	steps := Steps(in)

	if Ready(in) {
		_, _ = w.WriteString("This installation can raise and deliver an alarm.\n\n")
	} else {
		_, _ = w.WriteString("NOT READY: this installation cannot deliver an alarm yet.\n" +
			"The steps marked TODO below are what is missing.\n\n")
	}

	for i, s := range steps {
		mark := map[Status]string{
			Done: "  ok  ", Todo: " TODO ", Optional: " note ", Unverified: " check ",
		}[s.Status]
		_, _ = w.WriteString(fmt.Sprintf("%s%d. %s\n", mark, i+1, s.Title))
		if s.State != "" {
			_, _ = w.WriteString("        now: " + s.State + "\n")
		}
		if !full && s.Status == Done {
			continue
		}
		if s.Why != "" {
			_, _ = w.WriteString("        why: " + wrap(s.Why, 66, "             ") + "\n")
		}
		for _, h := range s.How {
			_, _ = w.WriteString("         - " + wrap(h, 66, "           ") + "\n")
		}
		if s.Title == hooksTitle {
			renderHookURLs(w, in)
		}
		_, _ = w.WriteString("\n")
	}
}

// renderHookURLs prints the URLs to paste into Alarm Manager.
//
// Only here. The CLI runs on a machine that already holds the config file, so
// showing them costs nothing it has not already got; the web checklist renders
// the same steps without calling this, and gates the URLs behind a session.
func renderHookURLs(w io.StringWriter, in Input) {
	if len(in.Hooks) == 0 {
		return
	}
	_, _ = w.WriteString("\n        To paste into each Alarm Manager rule. BOTH are needed,\n" +
		"        and both are passwords:\n")
	for _, h := range in.Hooks {
		line := "          " + h.Name
		if h.Product != "" {
			line += " (" + h.Product + ")"
		}
		_, _ = w.WriteString(line + "\n            URL:    " + h.URL + "\n")
		if h.Header != "" {
			_, _ = w.WriteString("            Header: " + HeaderName + ": " + h.Header + "\n")
		}
		switch {
		case h.Count > 0:
			_, _ = w.WriteString(fmt.Sprintf("            %d alarm(s) received, last at %s\n",
				h.Count, h.LastAt.Format(time.RFC3339)))
		case h.Rejected > 0:
			// The most useful line on this screen when it applies: the rule
			// exists, the network path works, and the header is the problem.
			// Without it an operator sees "nothing arrived" and goes looking
			// at the console, which is the wrong end entirely.
			_, _ = w.WriteString(fmt.Sprintf("            REFUSED %d time(s) -- %s\n",
				h.Rejected, h.LastReject))
		default:
			_, _ = w.WriteString("            nothing has ever arrived here\n")
		}
	}
}

// wrap breaks a long line so it stays readable in a terminal.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := 0
	for i, word := range words {
		if i > 0 && line+len(word)+1 > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(word)
		line += len(word)
	}
	return b.String()
}
