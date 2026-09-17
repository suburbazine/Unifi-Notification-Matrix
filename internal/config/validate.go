package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel/ntfy"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Problems is a validation failure carrying every problem found, not just the
// first.
//
// One-at-a-time validation makes fixing a config a sequence of restarts, and
// each restart of an alarm daemon is a window where nothing is watching.
type Problems []string

func (p Problems) Error() string {
	if len(p) == 1 {
		return p[0]
	}
	return fmt.Sprintf("%d problems:\n  - %s", len(p), strings.Join(p, "\n  - "))
}

// ErrInvalid marks any validation failure, for errors.Is.
var ErrInvalid = errors.New("invalid configuration")

func (p Problems) Is(target error) bool { return target == ErrInvalid }

// consoleLabel names a console in a message, falling back to its position.
func consoleLabel(con Console, i int) string {
	if con.Name != "" {
		return fmt.Sprintf("console %q", con.Name)
	}
	return fmt.Sprintf("console %d", i)
}

// Warnings returns configurations that are usable but worth saying out loud.
//
// SEPARATE FROM Problems, because everything in Problems refuses the start.
// That distinction was missing and two things had ended up on the wrong side
// of it:
//
//   - `insecure_skip_verify` with no pinned fingerprint. Its own comment said
//     "not fatal", but it was appended to Problems like everything else, so a
//     console with a self-signed certificate and no pin learned yet -- which
//     is the ordinary UniFi console, on day one -- could not start the daemon
//     at all. Refusing to run is a far worse outcome than running unpinned:
//     an operator locked out at setup does not get to the pinning step.
//   - a console listing the `network` source. It must be SAID, because silence
//     reads as a WAN that is being watched, but refusing to start takes away
//     the Protect and Access coverage on that same console to punish one
//     unimplemented entry.
//
// A warning is printed at startup and shown in the interface. It is not a
// reason to leave a site unmonitored.
func (c Config) Warnings() []string {
	var w []string
	for i, con := range c.Consoles {
		where := consoleLabel(con, i)
		if con.Fingerprint == "" && con.InsecureSkipVerify {
			w = append(w, where+": insecure_skip_verify is set with no fingerprint, "+
				"so nothing authenticates the console; pin a certificate "+
				"(notifymatrix will show you its fingerprint) or turn verification back on")
		}
	}
	w = append(w, c.unavailableChannelWarnings()...)
	w = append(w, c.voiceOnNoLadderWarning()...)
	w = append(w, c.siteZoneWarning()...)
	w = append(w, c.exposureWarnings()...)
	return w
}

// siteZoneWarning reports a time zone this machine cannot resolve.
//
// quiet_hours.zone is also the clock every alert is ANNOUNCED in, so a bad one
// matters even when quiet hours are switched off -- and that is exactly the
// case QuietHours.Validate returns early on without looking. Times then fall
// back to this machine's own clock, which is right when the machine sits at
// the site and wrong when it is a server running on UTC: the voice channel
// speaks a bare "at 3:14 PM" with no zone in it to give the game away.
//
// A warning rather than a problem. Falling back is survivable; refusing to
// start over a mistyped zone, and delivering nothing at all, is not.
func (c Config) siteZoneWarning() []string {
	z := strings.TrimSpace(c.QuietHours.Zone)
	if z == "" || c.QuietHours.Enabled {
		// Enabled quiet hours already refuse a bad zone at startup, which is
		// a better answer than this one.
		return nil
	}
	if _, err := time.LoadLocation(z); err != nil {
		return []string{fmt.Sprintf("quiet_hours.zone %q is not a time zone this "+
			"machine knows, so the times in your alerts will use this machine's "+
			"own clock rather than the site's", z)}
	}
	return nil
}

// unavailableChannelWarnings reports escalation rungs naming a channel that is
// not available, which are silently dropped rather than refused.
//
// Dropped is the right behaviour -- a ladder should deliver through whatever
// exists rather than not at all -- but it must not be SILENT. A rung the
// operator wrote and that will never fire is exactly the kind of thing this
// product refuses to let pass without saying so.
func (c Config) unavailableChannelWarnings() []string {
	have := map[string]bool{}
	for _, ch := range c.EnabledChannelNames() {
		have[strings.ToLower(ch)] = true
	}
	if len(have) == 0 {
		return nil // nothing is configured; a different problem says so
	}

	names := make([]string, 0, len(c.Policies))
	for name := range c.Policies {
		names = append(names, name)
	}
	sort.Strings(names) // stable across runs

	var w []string
	for _, name := range names {
		missing := map[string]bool{}
		var order []string
		for _, st := range c.Policies[name].Stages {
			for _, ch := range st.Channels {
				if !have[strings.ToLower(ch)] && !missing[ch] {
					missing[ch] = true
					order = append(order, ch)
				}
			}
		}
		if len(order) == 0 {
			continue
		}
		w = append(w, fmt.Sprintf("policy %q names %s, which %s not enabled -- "+
			"those rungs are skipped and the rest of the ladder still delivers",
			name, strings.Join(order, ", "), plural(len(order))))
	}
	return w
}

func plural(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// Validate refuses a configuration that would fail silently later.
//
// The bar is deliberately high, because every check here is a failure that
// would otherwise surface during an alarm. A daemon that refuses to start with
// a clear message is recoverable in a minute; one that starts and quietly does
// not deliver is discovered days later, by its absence.
func (c Config) Validate() error {
	var p Problems

	if c.Version > SchemaVersion {
		p = append(p, fmt.Sprintf("version %d is newer than this build understands (%d)",
			c.Version, SchemaVersion))
	}

	p = append(p, c.validateConsoles()...)
	p = append(p, c.validateHooks()...)
	p = append(p, c.validateChannels()...)
	p = append(p, c.validateWeb()...)

	if err := c.QuietHours.Validate(); err != nil {
		p = append(p, err.Error())
	}

	// A rule set that cannot be expressed is refused at startup like anything
	// else here -- a blanket ignore would leave the service running, looking
	// healthy, and monitoring nothing.
	if err := c.Rules.Validate(); err != nil {
		p = append(p, err.Error())
	}

	p = append(p, c.validatePolicies()...)

	if len(p) > 0 {
		return p
	}
	return nil
}

func (c Config) validateConsoles() Problems {
	var p Problems
	seen := map[string]bool{}
	for i, con := range c.Consoles {
		where := consoleLabel(con, i)
		if con.Name == "" {
			p = append(p, where+": needs a name")
		} else if seen[con.Name] {
			// Two consoles sharing a name make incidents ambiguous about which
			// site they came from, and the dedup key is built from the source
			// -- so a duplicate name silently merges two sites' alarms.
			p = append(p, fmt.Sprintf("console name %q is used more than once", con.Name))
		}
		seen[con.Name] = true

		if strings.TrimSpace(con.Host) == "" {
			p = append(p, where+": needs a host")
		}
		key, _ := con.ResolveAPIKey()
		if key.IsZero() {
			p = append(p, where+": has no API key (set one, or point api_key_credential at a service credential)")
		}
		if len(con.Sources) == 0 {
			p = append(p, where+": enables no sources; it would be polled for nothing")
		}
		for _, s := range con.Sources {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "protect", "access", "network":
			case "":
			default:
				p = append(p, fmt.Sprintf("%s: unknown source %q (want protect or access)", where, s))
			}
		}
		// insecure_skip_verify with no pin is a WARNING, not a refusal. See
		// Config.Warnings.
	}
	return p
}

func (c Config) validateChannels() Problems {
	var p Problems
	if n := c.Channels.Ntfy; n != nil && n.Enabled {
		if strings.TrimSpace(n.Topic) == "" {
			p = append(p, "channel ntfy: needs a topic")
		}
		// Empty means the public instance, which is what ntfy.New already does
		// with it. Refusing it here made the two disagree: the channel had a
		// perfectly good default and the validator would not let anybody reach
		// it, so enabling ntfy meant knowing to type a URL that was going to be
		// used anyway.
		if raw := strings.TrimSpace(n.ServerURL); raw != "" {
			if u, err := url.Parse(raw); err != nil || u.Host == "" ||
				(u.Scheme != "http" && u.Scheme != "https") {
				p = append(p, fmt.Sprintf("channel ntfy: server_url %q is not an "+
					"http(s) URL. Leave it blank for %s", n.ServerURL, ntfy.DefaultServer))
			}
		}
	}
	if e := c.Channels.Email; e != nil && e.Enabled {
		if strings.TrimSpace(e.Host) == "" {
			p = append(p, "channel email: needs an SMTP host")
		}
		// Checked HERE rather than discovered when the channel is built.
		//
		// "Notify Matrix" with no address parses as a display name and nothing
		// else, and an unparseable From used to surface only at construction
		// time -- which took the whole daemon down. Saying it at save time is
		// the difference between a rejected field and an alarm system that
		// will not start.
		if from := strings.TrimSpace(e.From); from != "" {
			if _, err := mail.ParseAddress(from); err != nil {
				p = append(p, fmt.Sprintf("channel email: from %q is not an email "+
					"address -- write it as name@example.com, or as "+
					"\"Display Name <name@example.com>\" if you want a name on it", from))
			}
		}
		for _, to := range e.Recipients {
			if to = strings.TrimSpace(to); to == "" {
				continue
			}
			if _, err := mail.ParseAddress(to); err != nil {
				p = append(p, fmt.Sprintf("channel email: recipient %q is not an "+
					"email address", to))
			}
		}
		if e.Port < 0 || e.Port > 65535 {
			p = append(p, fmt.Sprintf("channel email: port %d is out of range", e.Port))
		}
		switch e.TLS {
		case "auto", "starttls", "implicit", "none":
		default:
			p = append(p, fmt.Sprintf(
				"channel email: tls %q is not auto, starttls, implicit or none", e.TLS))
		}
		if strings.TrimSpace(e.From) == "" {
			p = append(p, "channel email: needs a from address")
		}
		if len(e.Recipients) == 0 {
			p = append(p, "channel email: has no recipients, so it would send to nobody")
		}
		if e.Username != "" && e.Password.IsZero() {
			p = append(p, "channel email: a username is set with no password")
		}
	}
	p = append(p, c.validatePushover()...)
	p = append(p, c.validateVoice()...)
	p = append(p, c.validateWebhook()...)
	return p
}

func (c Config) validatePushover() Problems {
	var p Problems
	o := c.Channels.Pushover
	if o == nil || !o.Enabled {
		return nil
	}
	// Named separately rather than as "credentials missing", because these are
	// two different things from two different places and an operator who has
	// one has usually not realised there is another.
	if o.Token.IsZero() {
		p = append(p, "channel pushover: needs an application token "+
			"(create one at pushover.net/apps/build -- it is not your user key)")
	}
	if o.User.IsZero() {
		p = append(p, "channel pushover: needs a user or group key "+
			"(it is on your Pushover dashboard -- it is not the application token)")
	}
	return p
}

// validateVoice refuses an enabled voice channel that could not place a call.
//
// Everything here is checked again by voice.New, which is where it has to be
// -- a channel cannot trust that anybody validated its Config. Checking it a
// second time at this layer is what turns "the voice channel is broken, see
// the health page" into a rejected field at the moment somebody typed it,
// which is the difference between finding out now and finding out from a
// silent rung during an alarm.
func (c Config) validateVoice() Problems {
	var p Problems
	v := c.Channels.Voice
	if v == nil || !v.Enabled {
		return nil
	}
	// Named separately rather than as "credentials missing": they are two
	// values from the same page of the Twilio console and an operator who
	// pasted one has usually pasted it into the wrong box.
	if v.AccountSID.IsZero() {
		p = append(p, "channel voice: needs a Twilio account SID "+
			"(it begins \"AC\" and is on the Twilio console home page)")
	} else if !strings.HasPrefix(v.AccountSID.Reveal(), "AC") {
		// The message must not quote what it found. If the auth token really
		// is in this field, echoing it writes the credential into a startup
		// log and into the UI's problem list.
		p = append(p, "channel voice: the account SID must begin \"AC\" "+
			"(the auth token goes in the token field, not this one)")
	}
	if v.AuthToken.IsZero() {
		p = append(p, "channel voice: needs the Twilio auth token "+
			"(it is next to the account SID in the console -- it is not the account SID)")
	}

	if from := strings.TrimSpace(v.From); from == "" {
		p = append(p, "channel voice: needs a from number -- a number bought "+
			"from Twilio, or one verified as an outgoing caller ID on the account")
	} else if !validE164(from) {
		p = append(p, fmt.Sprintf("channel voice: from %q is not in E.164 form -- "+
			"a + followed by the country code and the number, no spaces, dashes "+
			"or parentheses (for example +15552223214)", v.From))
	}

	var recipients int
	for _, to := range v.Recipients {
		to = strings.TrimSpace(to)
		if to == "" {
			continue
		}
		recipients++
		if !validE164(to) {
			p = append(p, fmt.Sprintf("channel voice: recipient %q is not in "+
				"E.164 form -- a + followed by the country code and the number, "+
				"no spaces, dashes or parentheses (for example +15558675310)", to))
		}
	}
	// An enabled channel with nobody to call is the shape this product exists
	// to refuse: it would report a healthy channel, accept every alert handed
	// to it, and ring nobody at all.
	if recipients == 0 {
		p = append(p, "channel voice: has no recipients, so it would call nobody")
	}
	return p
}

// validE164 is the shape Twilio insists on: a leading +, a country code that
// never begins with 0, then digits, at most fifteen of them.
//
// Deliberately a copy of the check inside internal/channel/voice rather than
// a shared helper. Ten lines duplicated is cheaper than this package importing
// a channel for a string check, and the two cannot drift in a way that matters
// -- the channel's copy is the one that decides what gets sent, and this one
// exists only to say no earlier and more kindly.
func validE164(s string) bool {
	if !strings.HasPrefix(s, "+") {
		return false
	}
	digits := s[1:]
	if len(digits) < 2 || len(digits) > 15 {
		return false
	}
	if digits[0] == '0' {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return true
}

func (c Config) validateWebhook() Problems {
	var p Problems

	// Names have to be unique and must not collide with the built-in channels,
	// because a policy rung names a channel and there is no way to say which
	// of two "alerts" it meant. A collision with "ntfy" is worse: the rung
	// would silently address whichever the map happened to keep.
	reserved := map[string]bool{"ntfy": true, "email": true, "pushover": true, "voice": true}
	seen := map[string]bool{}

	for _, w := range c.WebhookEndpoints() {
		name := webhookName(w)
		where := "channel " + name

		if lower := strings.ToLower(name); reserved[lower] {
			p = append(p, fmt.Sprintf("webhook %q uses the name of a built-in "+
				"channel; give it a different one", name))
		}
		if seen[strings.ToLower(name)] {
			p = append(p, fmt.Sprintf("two webhooks are both called %q, so an "+
				"escalation rung naming it cannot say which", name))
		}
		seen[strings.ToLower(name)] = true

		if !w.Enabled {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(w.URL))
		switch {
		case strings.TrimSpace(w.URL) == "":
			p = append(p, where+": needs a url")
		case err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https"):
			p = append(p, fmt.Sprintf("%s: url %q is not an http(s) URL", where, w.URL))
		}
		for k := range w.Headers {
			if reservedWebhookHeader(k) {
				// Set by hand, this silently breaks every receiver's signature
				// check -- and it breaks it in the direction where the
				// receiver rejects real alarms.
				p = append(p, fmt.Sprintf("%s: header %q is set by the "+
					"channel itself and cannot be overridden", where, k))
			}
		}
	}
	return p
}

// reservedWebhookHeader names the headers the channel owns.
//
// Kept here as well as in the channel so a bad configuration is refused at
// startup, with a message, rather than at the first alarm.
func reservedWebhookHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "content-type",
		"x-notifymatrix-signature",
		"x-notifymatrix-timestamp":
		return true
	}
	return false
}

func (c Config) validateWeb() Problems {
	var p Problems
	if _, _, err := net.SplitHostPort(c.Web.Listen); err != nil {
		p = append(p, fmt.Sprintf("web.listen %q is not host:port", c.Web.Listen))
	}
	if a := strings.TrimSpace(c.Web.AckListen); a != "" {
		// "auto" and "host:auto" are legal: the port is chosen at first start
		// and written back, so the value in the file is only briefly not an
		// address.
		if _, wantsRandom := WantsRandomAckPort(a); !wantsRandom {
			if _, _, err := net.SplitHostPort(a); err != nil {
				p = append(p, fmt.Sprintf("web.ack_listen %q is not host:port "+
					"(or %q, to pick a port once and keep it)", a, AckListenAuto))
			}
		}
	}

	if c.Web.AckBaseURL == "" {
		// A WARNING, not a refusal, and the reason is in the sentence itself:
		// alerts still go out and can still be acknowledged, from the web UI.
		// That is worse, not impossible.
		//
		// As a refusal it was also a trap, because it only fired once a
		// channel was enabled -- so the act of adding a first channel
		// introduced it, and an operator could not add one until they had set
		// an address they had not been asked for yet. First-run configuration
		// has an order, and a rule that forbids the natural one has to be very
		// sure it is preventing something worse than it causes.
		//
		// The pressure is kept where it belongs: it is a TODO on the setup
		// checklist and a warning at every start.
		return p
	}

	u, err := url.Parse(c.Web.AckBaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		p = append(p, fmt.Sprintf("web.ack_base_url %q is not an http(s) URL", c.Web.AckBaseURL))
		return p
	}
	// THE SETTING PEOPLE GET WRONG.
	//
	// An ack URL pointing at loopback works perfectly on the machine running
	// the daemon and is useless in the 3am push notification it is embedded
	// in, because the phone holding that notification is not this machine.
	// Discovered during an alarm, that is the whole product failing.
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		p = append(p, fmt.Sprintf("web.ack_base_url %q points at this machine, so an "+
			"acknowledgement link would not open on a phone; use the LAN address, "+
			"a VPN name, or a tunnel hostname", c.Web.AckBaseURL))
	}
	return p
}

// voiceOnNoLadderWarning says so when the voice channel is switched on and
// nothing will ever use it.
//
// This is the one channel where enabling it is not enough. The shipped ladders
// deliberately do not name voice -- a default that phones somebody at 3am is
// not something to switch on for everybody -- so an operator who enables it
// and writes no rung has a channel that tests green, reports healthy, appears
// on the status page, and never calls anyone. That is indistinguishable from a
// working setup right up until the night it matters.
//
// A warning and not a problem: the configuration is valid, everything else
// still delivers, and refusing to start over a rung somebody has not written
// yet would be worse than saying it out loud.
func (c Config) voiceOnNoLadderWarning() []string {
	v := c.Channels.Voice
	if v == nil || !v.Enabled {
		return nil
	}
	for _, p := range c.Policies {
		for _, st := range p.Stages {
			for _, ch := range st.Channels {
				if strings.EqualFold(strings.TrimSpace(ch), "voice") {
					return nil
				}
			}
		}
	}
	return []string{"channel voice is enabled and no escalation rung names it, " +
		"so nothing will ever place a call -- the shipped ladders leave voice out " +
		"on purpose, because a default that phones somebody at 3am is not one to " +
		"choose for you. Add voice to a stage of the policy you want it on."}
}

func (c Config) anyChannelEnabled() bool { return len(c.EnabledChannelNames()) > 0 }

// EnabledChannelNames lists the channels this config would construct.
func (c Config) EnabledChannelNames() []string {
	var out []string
	if c.Channels.Ntfy != nil && c.Channels.Ntfy.Enabled {
		out = append(out, "ntfy")
	}
	if c.Channels.Email != nil && c.Channels.Email.Enabled {
		out = append(out, "email")
	}
	if c.Channels.Pushover != nil && c.Channels.Pushover.Enabled {
		out = append(out, "pushover")
	}
	if c.Channels.Voice != nil && c.Channels.Voice.Enabled {
		out = append(out, "voice")
	}
	for _, h := range c.WebhookEndpoints() {
		if h.Enabled {
			out = append(out, webhookName(h))
		}
	}
	sort.Strings(out)
	return out
}

func (c Config) validatePolicies() Problems {
	var p Problems
	enabled := c.EnabledChannelNames()

	// An EXPLICIT policy is checked against the enabled channels before
	// anything else, because it is the operator's stated intent. A rung naming
	// a channel they have not configured delivers nothing, reports nothing,
	// and looks exactly like a rung that worked -- so the daemon refuses to
	// start rather than discovering it during an alarm.
	have := map[string]bool{}
	for _, ch := range enabled {
		have[strings.ToLower(ch)] = true
	}
	names := make([]string, 0, len(c.Policies))
	for name := range c.Policies {
		names = append(names, name)
	}
	sort.Strings(names) // stable message across runs
	// Naming a channel that is not available is a WARNING, not a refusal.
	//
	// It used to be fatal, on the reasoning that a rung delivering nothing
	// looks exactly like a rung that worked. That reasoning is right about the
	// risk and wrong about the remedy: it meant one unconfigured channel made
	// the entire configuration invalid, so an operator could not save a
	// perfectly good email setup while ntfy was half-finished, and a ladder
	// that could have delivered through the channels that DID work delivered
	// through none of them.
	//
	// The risk is covered better below: a severity whose whole ladder filters
	// away to nothing is still fatal. So "somewhere to send it" stays a
	// refusal, and "exactly these channels" becomes advice.
	_ = names

	policies, err := c.BuildPolicies(enabled)
	if err != nil {
		return append(p, err.Error())
	}

	for name, pol := range policies {
		sev := incident.Severity(name)
		if !sev.Valid() {
			p = append(p, fmt.Sprintf(
				"policy %q is not a severity (want critical, high, medium, low or info)", name))
			continue
		}
		if err := pol.Validate(sev); err != nil {
			p = append(p, err.Error())
		}
	}

	// With channels enabled, every severity must still have somewhere to go.
	// A severity whose whole ladder filtered away would never alert at all,
	// which is the silence this product exists to prevent -- and it is
	// invisible, because nothing errors at delivery time.
	if len(enabled) > 0 {
		for _, sev := range []incident.Severity{
			incident.SeverityCritical, incident.SeverityHigh, incident.SeverityMedium,
			incident.SeverityLow, incident.SeverityInfo,
		} {
			if _, ok := policies[string(sev)]; !ok {
				p = append(p, fmt.Sprintf(
					"severity %q has no escalation stage left after matching against "+
						"the enabled channels (%s), so incidents at that severity "+
						"would never be delivered", sev, strings.Join(enabled, ", ")))
			}
		}
	}
	return p
}
