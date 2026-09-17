// Package config is the operator's configuration, and the source of truth.
//
// YAML on disk, written by the web UI and readable — and editable — by hand.
// ARCHITECTURE.md §6a: nothing the operator configures should be hidden in a
// file they cannot see.
//
// Serialisation goes through sigs.k8s.io/yaml, which converts YAML to JSON and
// uses the json marshalers. That is deliberate rather than incidental:
// secret.Secret's redaction lives in MarshalJSON/UnmarshalJSON, and a separate
// YAML marshaler would be a second place for it to be got wrong. One contract,
// one code path.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel/webhook"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// SchemaVersion is the config format this build writes.
//
// Open refuses a NEWER version outright rather than reading what it recognises
// and ignoring the rest: a downgraded binary silently dropping a channel or a
// console is how a site stops being monitored without anyone being told.
const SchemaVersion = 1

// Config is the whole file.
type Config struct {
	Version int `json:"version"`

	Consoles []Console `json:"consoles,omitempty"`

	// Hooks are inbound webhook endpoints, one per UniFi Alarm Manager rule.
	//
	// They exist because Alarm Manager rules can be created only in the UniFi
	// UI -- no API creates them -- so this product cannot provision its own
	// push path and a person has to make the rule by hand. See internal/inbound.
	Hooks []Hook `json:"hooks,omitempty"`

	Channels Channels `json:"channels,omitempty"`

	// Policies overrides the shipped defaults, keyed by severity. Absent means
	// escalate.DefaultPolicies().
	Policies map[string]Policy `json:"policies,omitempty"`

	// Rules adjust severity and silence noise. Ordered: last match wins for
	// severity, and an ignore by any rule wins outright.
	Rules rule.Set `json:"rules,omitempty"`

	QuietHours escalate.QuietHours `json:"quiet_hours,omitempty"`
	Web        Web                 `json:"web,omitempty"`

	// Secrets records how the secrets in this file were protected and which
	// machine protected them. See fingerprint.go.
	Secrets SecretsMeta `json:"secrets,omitempty"`

	// PlaintextFields names credential fields that were found unprotected in
	// the file this config was loaded from. Never serialised: it describes the
	// file as it was READ, and the next Save encrypts them.
	PlaintextFields []string `json:"-"`
}

// Console is one UniFi OS host.
//
// One entry per host, not per application: Protect, Access and Network are
// applications behind the same console, sharing one certificate, one pin and
// one rate budget (DESIGN-RULES.md §1).
type Console struct {
	// Name identifies this console in incidents and in the UI. Must be unique.
	Name string `json:"name"`

	Host string `json:"host"`

	// APIKey is the console's integration API key.
	//
	// Encrypted at rest by the secret package. It is a secret.Secret rather
	// than a string so it cannot reach a log through %v.
	APIKey secret.Secret `json:"api_key,omitempty"`

	// APIKeyCredential names a service-manager credential to read instead —
	// systemd's LoadCredentialEncrypted. When present AND available it WINS
	// over APIKey, because an administrator who went to the trouble of
	// provisioning one has stated an intent, and silently preferring a
	// UI-written key would override it (ARCHITECTURE.md §9a).
	APIKeyCredential string `json:"api_key_credential,omitempty"`

	// Fingerprint is the pinned certificate SHA-256. Empty means no pin.
	//
	// Learning a pin is an OPERATOR action, never automatic: a client that
	// silently learns one on first connection has no protection on the one
	// connection an attacker would target.
	Fingerprint string `json:"fingerprint,omitempty"`

	// InsecureSkipVerify turns off chain validation. Ordinary for a
	// self-signed console — the pin is what provides the security there, which
	// is why pinning keeps working regardless of this flag.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// Sources to run against this console: "protect", "access", "network".
	Sources []string `json:"sources,omitempty"`
}

// Channels are the ways to reach a human. A nil entry is not configured; an
// entry with Enabled false is configured and switched off, which the UI shows
// differently and diagnostics report differently.
type Channels struct {
	Ntfy     *Ntfy     `json:"ntfy,omitempty"`
	Email    *Email    `json:"email,omitempty"`
	Pushover *Pushover `json:"pushover,omitempty"`
	Voice    *Voice    `json:"voice,omitempty"`

	// Webhook is the ORIGINAL single outbound endpoint, kept so existing
	// configurations keep working. It is folded into Webhooks on load and
	// written back as part of that list, so it disappears from the file the
	// first time anything is saved.
	Webhook *Webhook `json:"webhook,omitempty"`

	// Webhooks are outbound endpoints, each addressable by name from an
	// escalation rung.
	//
	// A list rather than one, because pushing to a home-automation box and to
	// an on-call service are different jobs wanted at different severities,
	// and a single endpoint forces a site to pick one or to fan out somewhere
	// else. The name is what a policy stage refers to.
	Webhooks []Webhook `json:"webhooks,omitempty"`
}

// Ntfy configures the ntfy channel.
type Ntfy struct {
	Enabled bool `json:"enabled"`

	// ServerURL defaults to https://ntfy.sh. A self-hosted server is the right
	// answer for anyone whose alerts matter, because ntfy.sh rate-limits per
	// visitor IP and one noisy neighbour on the same egress address can 429 a
	// genuine alarm.
	ServerURL string `json:"server_url,omitempty"`

	Topic string        `json:"topic"`
	Token secret.Secret `json:"token,omitempty"`
}

// Email configures the SMTP channel.
type Email struct {
	Enabled bool `json:"enabled"`

	Host     string        `json:"host"`
	Port     int           `json:"port,omitempty"`
	Username string        `json:"username,omitempty"`
	Password secret.Secret `json:"password,omitempty"`

	// TLS is "auto" (default), "starttls", "implicit" or "none".
	//
	// "auto" picks implicit TLS on 465 and MANDATORY STARTTLS everywhere else.
	// It never picks opportunistic STARTTLS: a mode that silently delivers in
	// the clear when the server offers no STARTTLS is indistinguishable from a
	// working one until somebody is reading the mail.
	TLS string `json:"tls,omitempty"`

	From       string   `json:"from"`
	Recipients []string `json:"recipients"`

	// LogoPath is an optional image attached inline to the HTML part.
	LogoPath string `json:"logo_path,omitempty"`
}

// Pushover configures the Pushover channel.
type Pushover struct {
	Enabled bool `json:"enabled"`

	// Token is the APPLICATION token, created once at pushover.net/apps/build.
	// User is the user or group key, shown on the Pushover dashboard.
	//
	// Two different credentials that both look like a random string, which is
	// the mistake people make: swapping them produces "application token is
	// invalid", which reads as a bad token rather than as the pair being the
	// wrong way round.
	Token secret.Secret `json:"token,omitempty"`
	User  secret.Secret `json:"user,omitempty"`

	// Device restricts delivery to one of the account's devices. Empty means
	// all of them, which is what an alarm wants.
	Device string `json:"device,omitempty"`

	// Sound overrides the account default.
	Sound string `json:"sound,omitempty"`
}

// Voice configures the Twilio voice channel: a phone call that speaks the
// alert and hangs up.
//
// It is the only channel that costs money per alert and the only one that
// wakes a household, so it is never on a shipped escalation ladder -- an
// operator has to put it on a rung themselves. See escalate.DefaultPolicies.
type Voice struct {
	Enabled bool `json:"enabled"`

	// AccountSID is the identifier beginning "AC" on the Twilio console's home
	// page. AuthToken is the token shown next to it.
	//
	// Two values that sit side by side in the console and look alike, which is
	// the mistake people make: the token pasted into the account_sid box gets
	// a 401 "permission denied" out of Twilio, which reads as a bad token and
	// sends the operator off to rotate the one thing that was not wrong.
	// Validation checks the "AC" prefix here so that never reaches Twilio.
	//
	// THE YAML KEY IS "token", not the "auth_token" Twilio's own documentation
	// uses, and that is deliberate rather than sloppy: PlaintextSecrets scans
	// the raw file for the literal key names api_key, token and password, so a
	// credential pasted into this file in the clear under any other name is
	// never reported as exposed and the operator is never told to rotate it.
	// account_sid already has that hole; it is the lesser half of the pair and
	// useless on its own, and the half that can place calls does not.
	AccountSID secret.Secret `json:"account_sid,omitempty"`
	AuthToken  secret.Secret `json:"token,omitempty"`

	// From is the caller ID in E.164 (+15552223214). It must be a number
	// bought from Twilio or a verified outgoing caller ID on the account --
	// anything else is refused at call time with Twilio error 21210, which
	// reads like a credentials problem and is not one.
	From string `json:"from"`

	// Recipients are the numbers called, in E.164. Every one is called on
	// every alert, seconds apart, rather than minutes apart the way separate
	// escalation rungs would space them.
	Recipients []string `json:"recipients"`

	// Voice and Language pick the text-to-speech voice. Empty means the
	// channel's defaults ("man", "en-US"), which ApplyDefaults writes in so
	// that what the file says is what goes on the wire.
	//
	// Both are sent explicitly on every call because Twilio's account-level
	// default, set in a web console this product cannot see, otherwise
	// overrides the documented one. An invalid voice, or a voice paired with a
	// language it does not speak, fails AFTER Twilio has returned its 201 --
	// a clean success followed by silence -- so the UI offers a list rather
	// than a text box.
	Voice    string `json:"voice,omitempty"`
	Language string `json:"language,omitempty"`
}

// Webhook configures the generic webhook channel: one JSON POST per alert, to
// whatever the operator runs -- Home Assistant, Node-RED, a bridge of their
// own.
type Webhook struct {
	// Name is how an escalation rung refers to this endpoint.
	//
	// Empty means "webhook", which is what the single original endpoint was
	// called and what any policy written before this list existed still says.
	Name string `json:"name,omitempty"`

	Enabled bool `json:"enabled"`

	URL string `json:"url"`

	// Secret signs each request so a receiver can prove it came from here and
	// reject a replay. Optional, and worth setting: an unauthenticated webhook
	// endpoint is one anybody who learns the URL can feed false alarms to.
	Secret secret.Secret `json:"secret,omitempty"`

	// Headers are static headers added to every request -- an API key for the
	// receiving service, a tenant id. The signature and timestamp headers
	// cannot be overridden here; validation refuses that rather than letting
	// an operator silently break every receiver's verification.
	Headers map[string]string `json:"headers,omitempty"`

	// InsecureSkipVerify turns off certificate verification, for a LAN
	// receiver with a self-signed certificate. It is a real setting with a
	// real cost, so it is named for what it does.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// Policy overrides one severity's escalation ladder.
type Policy struct {
	Stages            []Stage `json:"stages"`
	RepeatEvery       string  `json:"repeat_every,omitempty"`
	GiveUpAfter       string  `json:"give_up_after,omitempty"`
	RespectQuietHours bool    `json:"respect_quiet_hours,omitempty"`
}

// WebhookEndpoints is every configured outbound webhook, including one still
// written in the original singular form.
//
// Reading through this rather than the fields directly means nothing has to
// remember which shape a particular config file is in.
func (c Config) WebhookEndpoints() []Webhook {
	out := make([]Webhook, 0, len(c.Channels.Webhooks)+1)
	if c.Channels.Webhook != nil {
		out = append(out, *c.Channels.Webhook)
	}
	out = append(out, c.Channels.Webhooks...)
	return out
}

// webhookName is the channel name for an endpoint, defaulting to the name the
// single original endpoint has always had.
func webhookName(h Webhook) string {
	if n := strings.TrimSpace(h.Name); n != "" {
		return n
	}
	return webhook.DefaultName
}

// Stage is one rung. After is a Go duration string ("2m", "10m").
type Stage struct {
	After    string   `json:"after"`
	Channels []string `json:"channels"`
}

// Web is the local operator interface.
type Web struct {
	// Listen defaults to 127.0.0.1:8322 — LAN-only unless the operator says
	// otherwise. The consoles connect OUTBOUND to us and need nothing exposed
	// (ARCHITECTURE.md §8a).
	Listen string `json:"listen,omitempty"`

	// PasswordHash gates the settings surface. Status is readable without it;
	// changing anything is not.
	//
	// A HASH, never a password, and self-describing
	// (pbkdf2-sha256$iterations$salt$key) so the iteration count can be raised
	// later without invalidating what is already stored. Empty means no
	// password is set, which does NOT mean everyone is authenticated -- the
	// first one is set with a one-time token the daemon prints at startup.
	PasswordHash string `json:"password_hash,omitempty"`

	// AckKey signs acknowledgement links. Generated on first save; never
	// entered by hand.
	//
	// Rotating it invalidates every link already sent, which for alerts still
	// repeating means the only way left to acknowledge them is the web UI.
	// That is a real cost, so it is not done automatically.
	AckKey secret.Secret `json:"ack_key,omitempty"`

	// AckListen is a SECOND listener that serves the acknowledgement routes
	// and nothing else. Empty means one listener for everything.
	//
	// It exists for one situation, and it is a common one: somebody who is not
	// at the site has to be able to stop an alarm. That means the ack surface
	// has to be reachable from outside, and the ordinary way people do that is
	// a NAT port forward.
	//
	// A NAT FORWARD CANNOT SCOPE BY PATH. Forwarding the main listener
	// publishes the status page -- which names cameras, doors and open alarms
	// -- and the settings sign-in, to the entire internet. ARCHITECTURE.md
	// section 8b accepts a public status page on the reasoning that anyone on
	// that LAN can query the console directly anyway; that reasoning does not
	// survive contact with the open internet.
	//
	// So this gives the forward something safe to point at: a port on which
	// /ack/ is the only thing that exists. Everything else 404s, including the
	// status page and the settings API.
	//
	// It is still plain HTTP, and the acknowledgement token travels in the
	// URL. Put TLS in front of it, or use a VPN instead -- see docs/SETUP.md.
	AckListen string `json:"ack_listen,omitempty"`

	// AckBaseURL is the externally reachable base for acknowledgement links.
	//
	// Required once a channel embeds ack links, and it is the one setting
	// people get wrong: if it points at 127.0.0.1, the link in a 3am push
	// notification opens nothing on the phone holding it. Validation says so
	// rather than letting it be discovered during an alarm.
	AckBaseURL string `json:"ack_base_url,omitempty"`
}

// SecretsMeta records how this file's secrets were protected.
type SecretsMeta struct {
	// Mechanism is the prefix the secrets were written with ("dpapi:",
	// "sdcreds:", "agekey:", "plain:"). Informational; the prefix on each
	// value is authoritative.
	Mechanism string `json:"mechanism,omitempty"`

	// HostFingerprint identifies the machine that wrote them.
	//
	// This exists for one failure: a config copied to another machine cannot
	// be decrypted there, and without this the decrypt error escapes
	// UnmarshalJSON and is reported by Open as a PARSE error. The operator
	// then goes looking for a corrupt file instead of a foreign one. See
	// fingerprint.go.
	HostFingerprint string `json:"host_fingerprint,omitempty"`
}

// Default returns a config that is valid, safe, and does nothing.
//
// Deliberately has no consoles and no channels: a fresh install must not
// invent a destination for alerts, and the setup flow is what fills these in.
func Default() Config {
	return Config{
		Version: SchemaVersion,
		Web: Web{
			Listen: "127.0.0.1:8322",
		},
	}
}

// ResolveAPIKey returns the console's key, preferring a service-provisioned
// credential over the one in the file.
//
// The second return value names where it came from, which diagnostics must
// show: "I changed the key in the UI and nothing happened" is baffling unless
// the product says an administrator-provisioned credential is overriding it.
func (c Console) ResolveAPIKey() (secret.Secret, string) {
	if c.APIKeyCredential != "" {
		if s, ok := secret.FromServiceCredential(c.APIKeyCredential); ok {
			return s, "service credential " + c.APIKeyCredential
		}
	}
	return c.APIKey, "config file"
}

// BuildPolicies materialises the escalation policies for this config, given
// the channels that are actually enabled.
//
// The two sources of policy are treated DIFFERENTLY, on purpose:
//
//   - The shipped defaults are ours, and are FILTERED to the enabled channels.
//     A site running ntfy only should not be refused because our default
//     critical ladder also mentions email; it should simply escalate through
//     what exists. A stage left with no channels is dropped, and a policy left
//     with no stages is omitted.
//
//   - An operator's explicit policy is their stated INTENT and is never
//     filtered. Naming a channel they have not configured is a mistake worth
//     refusing (see validatePolicies), because the alternative is a rung that
//     delivers nothing and looks exactly like one that worked.
func (c Config) BuildPolicies(enabled []string) (map[string]escalate.Policy, error) {
	have := map[string]bool{}
	for _, ch := range enabled {
		have[strings.ToLower(strings.TrimSpace(ch))] = true
	}

	out := map[string]escalate.Policy{}
	for sev, p := range escalate.DefaultPolicies() {
		if len(have) == 0 {
			// Nothing configured yet -- a fresh install. Keep the ladders
			// intact rather than filtering them to nothing: the scheduler
			// still has to start and still has to schedule, and the delivery
			// function refuses explicitly, so no alert is quietly dropped.
			// Filtering here instead produced an empty policy set and a daemon
			// that would not start at all on first run.
			out[string(sev)] = p
			continue
		}
		if filtered, ok := filterToEnabled(p, have); ok {
			out[string(sev)] = filtered
			continue
		}
		// The shipped ladder names ntfy and email, so a site whose only
		// channel is something else -- a Pushover account, a webhook called
		// "home-assistant" -- filtered every default away to nothing and was
		// told, five times over, that no severity had anywhere to go.
		//
		// A DEFAULT means "tell me on whatever exists". It is only the
		// operator's own policy that means "these channels and no others", and
		// that one is still honoured exactly, including when it empties.
		out[string(sev)] = everyChannelLadder(p, enabled)
	}
	for sev, p := range c.Policies {
		built, err := p.build(sev)
		if err != nil {
			return nil, err
		}
		if len(have) == 0 {
			// Nothing configured yet. Keep the ladder whole, for the same
			// reason the defaults are kept: the scheduler still has to start.
			out[sev] = built
			continue
		}
		// Filtered against what actually exists, exactly as the shipped
		// defaults are.
		//
		// It used to be kept whole on the reasoning that the operator said
		// this -- and the effect was that naming a channel which was disabled,
		// broken or simply not set up yet made the WHOLE configuration
		// invalid. One unconfigured channel then blocked saving a different,
		// perfectly good one, and an escalation ladder that could have
		// delivered through the channels that did work delivered through none.
		//
		// The ladder now uses whatever is available. The guarantee that
		// matters is kept elsewhere and is stronger: validatePolicies still
		// refuses a severity whose ladder filters away to nothing, so
		// "somewhere to send it" remains fatal while "exactly these channels"
		// does not.
		// An explicit policy REPLACES the default for that severity, including
		// when it filters away to nothing.
		//
		// Without the delete, a ladder that narrowed to nothing left the
		// SHIPPED default sitting there -- so the operator's stated policy was
		// silently discarded, an untouched default quietly took over, and the
		// "no stage left" check never fired because a ladder was technically
		// present. That is worse than either answer: it neither honours what
		// they wrote nor tells them it could not.
		delete(out, sev)
		if filtered, ok := filterToEnabled(built, have); ok {
			out[sev] = filtered
		}
	}
	return out, nil
}

// everyChannelLadder is the fallback for a shipped default that named nothing
// this installation has: one rung, immediately, to everything configured.
//
// The timing fields are kept, because they are the part of a default ladder
// that is about severity rather than about which services happen to be set up:
// critical still repeats every five minutes and still never gives up.
func everyChannelLadder(p escalate.Policy, enabled []string) escalate.Policy {
	out := p
	out.Stages = []escalate.Stage{{After: 0, Channels: append([]string(nil), enabled...)}}
	return out
}

// filterToEnabled drops channels that do not exist, then stages left empty.
// ok is false when nothing survives.
func filterToEnabled(p escalate.Policy, have map[string]bool) (escalate.Policy, bool) {
	out := p
	out.Stages = nil
	for _, st := range p.Stages {
		var keep []string
		for _, ch := range st.Channels {
			if have[strings.ToLower(ch)] {
				keep = append(keep, ch)
			}
		}
		if len(keep) > 0 {
			out.Stages = append(out.Stages, escalate.Stage{After: st.After, Channels: keep})
		}
	}
	if len(out.Stages) == 0 {
		return out, false
	}
	// Stage offsets are preserved, so a ladder whose first rung was dropped
	// now starts later than zero. That is correct: the rung that would have
	// fired at zero had nowhere to deliver.
	return out, true
}

func (p Policy) build(name string) (escalate.Policy, error) {
	out := escalate.Policy{Name: name, RespectQuietHours: p.RespectQuietHours}
	for i, s := range p.Stages {
		d, err := parseDuration(s.After)
		if err != nil {
			return out, fmt.Errorf("policy %q stage %d: after: %w", name, i, err)
		}
		out.Stages = append(out.Stages, escalate.Stage{After: d, Channels: s.Channels})
	}
	var err error
	if out.RepeatEvery, err = parseDuration(p.RepeatEvery); err != nil {
		return out, fmt.Errorf("policy %q: repeat_every: %w", name, err)
	}
	// "never" is spelled explicitly rather than as an omitted field, so that a
	// policy which never gives up says so out loud in the file.
	if p.GiveUpAfter != "" && p.GiveUpAfter != "never" {
		if out.GiveUpAfter, err = parseDuration(p.GiveUpAfter); err != nil {
			return out, fmt.Errorf("policy %q: give_up_after: %w", name, err)
		}
	}
	return out, nil
}

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (try 30s, 5m, 2h)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is negative", s)
	}
	return d, nil
}
