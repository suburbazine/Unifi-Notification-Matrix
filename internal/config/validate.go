package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

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
		for _, src := range con.Sources {
			if strings.EqualFold(strings.TrimSpace(src), "network") {
				w = append(w, where+": lists source \"network\", which this build does "+
					"not implement yet -- nothing on this console's Network application "+
					"will be reported")
			}
		}
	}
	return w
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
			case "protect", "access":
			case "network":
				// Usable, and reported by Warnings rather than refused here:
				// taking away a console's working Protect and Access coverage
				// because one entry is unimplemented helps nobody.
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
		if u, err := url.Parse(n.ServerURL); err != nil || u.Host == "" ||
			(u.Scheme != "http" && u.Scheme != "https") {
			p = append(p, fmt.Sprintf("channel ntfy: server_url %q is not an http(s) URL", n.ServerURL))
		}
	}
	if e := c.Channels.Email; e != nil && e.Enabled {
		if strings.TrimSpace(e.Host) == "" {
			p = append(p, "channel email: needs an SMTP host")
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
	return p
}

func (c Config) validateWeb() Problems {
	var p Problems
	if _, _, err := net.SplitHostPort(c.Web.Listen); err != nil {
		p = append(p, fmt.Sprintf("web.listen %q is not host:port", c.Web.Listen))
	}

	if c.Web.AckBaseURL == "" {
		if c.anyChannelEnabled() {
			p = append(p, "web.ack_base_url is not set, so alerts would carry no "+
				"acknowledgement link and nothing could stop them repeating "+
				"except the web UI")
		}
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

func (c Config) anyChannelEnabled() bool {
	return (c.Channels.Ntfy != nil && c.Channels.Ntfy.Enabled) ||
		(c.Channels.Email != nil && c.Channels.Email.Enabled)
}

// EnabledChannelNames lists the channels this config would construct.
func (c Config) EnabledChannelNames() []string {
	var out []string
	if c.Channels.Ntfy != nil && c.Channels.Ntfy.Enabled {
		out = append(out, "ntfy")
	}
	if c.Channels.Email != nil && c.Channels.Email.Enabled {
		out = append(out, "email")
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
	for _, name := range names {
		for i, st := range c.Policies[name].Stages {
			for _, ch := range st.Channels {
				if !have[strings.ToLower(ch)] {
					p = append(p, fmt.Sprintf(
						"policy %q stage %d names channel %q, which is not configured or not enabled",
						name, i, ch))
				}
			}
		}
	}

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
