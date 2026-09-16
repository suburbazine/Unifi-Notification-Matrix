package web

import (
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/rule"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// The settings surface is two separate shapes, deliberately.
//
// What goes OUT (settingsView and friends) has nowhere to put a secret: there
// is no field of type secret.Secret and no field that carries one as a string.
// A console's API key leaves this process as the boolean APIKeySet and nothing
// else. That is the guard -- not the redacting String() on secret.Secret, which
// is a backstop for logs rather than a design.
//
// What comes IN (settingsUpdate and friends) does carry new secret values,
// because setting one is the point of the form. Those fields are write-only:
// they are never populated on the way out, and the types they live in are never
// serialised into a response.

type settingsView struct {
	Consoles   []consoleView            `json:"consoles"`
	Channels   channelsView             `json:"channels"`
	Hooks      []hookView               `json:"hooks"`
	Policies   map[string]config.Policy `json:"policies,omitempty"`
	Rules      rule.Set                 `json:"rules"`
	QuietHours escalate.QuietHours      `json:"quiet_hours"`
	Web        webView                  `json:"web"`

	// SecretsMechanism names how the stored credentials were protected
	// ("dpapi:", "sdcreds:", "plain:"). The mechanism, never a value: an
	// operator has to be able to see that a config claiming protection has it.
	SecretsMechanism string `json:"secrets_mechanism,omitempty"`

	// PlaintextFields names credentials found UNPROTECTED in the file. Names
	// only. A key that sat in a readable file should be treated as exposed,
	// and the UI says so loudly.
	PlaintextFields []string `json:"plaintext_fields,omitempty"`

	// HookConditions is what an inbound hook may be told it means.
	//
	// Served rather than written into the page, so the dropdown cannot drift
	// from the list the validator enforces. A condition becomes part of a
	// stored dedup key, so an unrecognised one is not a cosmetic mistake: the
	// same alarm would never merge with itself and would nag separately for
	// ever.
	HookConditions []string `json:"hook_conditions,omitempty"`
}

type consoleView struct {
	Name string `json:"name"`
	Host string `json:"host"`

	// APIKeySet is the whole of what this interface will say about the key.
	APIKeySet bool `json:"api_key_set"`

	APIKeyCredential   string   `json:"api_key_credential,omitempty"`
	Fingerprint        string   `json:"fingerprint,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	Sources            []string `json:"sources"`
}

type channelsView struct {
	Ntfy     *ntfyView     `json:"ntfy,omitempty"`
	Email    *emailView    `json:"email,omitempty"`
	Pushover *pushoverView `json:"pushover,omitempty"`
	Webhooks []webhookView `json:"webhooks"`
}

// Every credential here is reported as a BOOLEAN, never as a value. The
// settings response is the one place a secret could plausibly be echoed back
// -- a form wants to show what is stored -- and it is the one place it must
// not be.
type pushoverView struct {
	Enabled  bool   `json:"enabled"`
	TokenSet bool   `json:"token_set"`
	UserSet  bool   `json:"user_set"`
	Device   string `json:"device,omitempty"`
	Sound    string `json:"sound,omitempty"`
}

type webhookView struct {
	// Name is how an escalation rung addresses this endpoint.
	Name               string            `json:"name"`
	Enabled            bool              `json:"enabled"`
	URL                string            `json:"url"`
	SecretSet          bool              `json:"secret_set"`
	Headers            map[string]string `json:"headers,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
}

type ntfyView struct {
	Enabled   bool   `json:"enabled"`
	ServerURL string `json:"server_url,omitempty"`
	Topic     string `json:"topic"`
	TokenSet  bool   `json:"token_set"`
}

type emailView struct {
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Username    string   `json:"username,omitempty"`
	PasswordSet bool     `json:"password_set"`
	TLS         string   `json:"tls,omitempty"`
	From        string   `json:"from"`
	Recipients  []string `json:"recipients"`
	LogoPath    string   `json:"logo_path,omitempty"`
}

// hookView is one inbound webhook, WITHOUT its credentials.
//
// The URL carries the token and the header carries the bearer, and both are
// shown on the setup checklist, gated behind a session. They are deliberately
// not repeated here: a credential with two ways out has two ways to leak, and
// the checklist is the surface already designed and tested for it. This one
// manages what a hook MEANS.
type hookView struct {
	Name      string `json:"name"`
	Product   string `json:"product,omitempty"`
	Condition string `json:"condition,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Entity    string `json:"entity,omitempty"`

	TokenSet  bool `json:"token_set"`
	BearerSet bool `json:"bearer_set"`
}

type webView struct {
	Listen     string `json:"listen"`
	AckBaseURL string `json:"ack_base_url,omitempty"`
	AckListen  string `json:"ack_listen,omitempty"`
	AckKeySet  bool   `json:"ack_key_set"`
}

// ---- inbound ----

type settingsUpdate struct {
	// Consoles and Channels are pointers for the same reason Hooks and
	// Policies are: absent has to mean "leave alone", not "delete".
	//
	// As plain values, a request that did not mention them -- an older page, a
	// script, anything posting one section -- silently removed every console
	// and disabled every channel. That is the whole product turned off by
	// omission, and it became reachable the moment saves stopped being
	// all-or-nothing.
	Consoles *[]consoleUpdate `json:"consoles"`
	Channels *channelsUpdate  `json:"channels"`

	// Rules are the operator's overrides. A pointer for the same reason as
	// everything else here: the Webhooks tab posts only the two sections it
	// owns, and as a plain value that save deleted every rule on the site.
	Rules *rule.Set `json:"rules"`

	// Hooks are the inbound webhook endpoints. A pointer, so a client that
	// does not mention them leaves them alone rather than deleting every
	// Alarm Manager endpoint the site depends on.
	Hooks *[]hookUpdate `json:"hooks"`

	// Policies are the escalation ladders, keyed by severity.
	//
	// A pointer to the map, so a client that does not mention policies leaves
	// them alone rather than deleting every one. They were readable and not
	// writable at all before this -- the only way to change an escalation
	// ladder was to edit YAML, on the setting that decides whether anybody is
	// told a second time.
	Policies *map[string]config.Policy `json:"policies"`

	// QuietHours, likewise a pointer. As a plain value an unrelated save
	// silently re-enabled overnight alerting that the operator had turned off.
	QuietHours *escalate.QuietHours `json:"quiet_hours"`

	Web webUpdate `json:"web"`
}

type consoleUpdate struct {
	Name               string   `json:"name"`
	Host               string   `json:"host"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	Sources            []string `json:"sources"`
	APIKeyCredential   string   `json:"api_key_credential"`

	// APIKeyNew replaces the stored key. Empty means KEEP what is stored --
	// the form cannot echo the current value back, so "unchanged" has to be
	// expressible as "sent nothing".
	APIKeyNew string `json:"api_key_new"`
}

type channelsUpdate struct {
	Ntfy     *ntfyUpdate      `json:"ntfy"`
	Email    *emailUpdate     `json:"email"`
	Pushover *pushoverUpdate  `json:"pushover"`
	Webhooks *[]webhookUpdate `json:"webhooks"`
}

type pushoverUpdate struct {
	Enabled  bool   `json:"enabled"`
	TokenNew string `json:"token_new"`
	UserNew  string `json:"user_new"`
	Device   string `json:"device"`
	Sound    string `json:"sound"`
}

type webhookUpdate struct {
	Name               string            `json:"name"`
	Enabled            bool              `json:"enabled"`
	URL                string            `json:"url"`
	SecretNew          string            `json:"secret_new"`
	Headers            map[string]string `json:"headers"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
}

type ntfyUpdate struct {
	Enabled   bool   `json:"enabled"`
	ServerURL string `json:"server_url"`
	Topic     string `json:"topic"`
	TokenNew  string `json:"token_new"`
}

type emailUpdate struct {
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Username    string   `json:"username"`
	PasswordNew string   `json:"password_new"`
	TLS         string   `json:"tls"`
	From        string   `json:"from"`
	Recipients  []string `json:"recipients"`
	LogoPath    string   `json:"logo_path"`
}

type hookUpdate struct {
	Name      string `json:"name"`
	Product   string `json:"product"`
	Condition string `json:"condition"`
	Severity  string `json:"severity"`
	Entity    string `json:"entity"`

	// Regenerate mints a new token and bearer for this hook.
	//
	// It BREAKS the Alarm Manager rule pointing at the old URL, immediately and
	// silently -- the console keeps posting and this end keeps refusing. That
	// is the right behaviour for a credential believed to be exposed, and it
	// is why it is a deliberate per-hook action rather than something a save
	// does on its own.
	Regenerate bool `json:"regenerate"`
}

type webUpdate struct {
	Listen string `json:"listen"`

	// A pointer, so a save that never mentions it leaves it alone. As a plain
	// string, any partial save blanked it -- which does not stop alerts going
	// out, but strips the acknowledge link off every one of them, so the only
	// way left to acknowledge is to be at the web UI.
	AckBaseURL *string `json:"ack_base_url"`
	// A pointer, so "the client did not mention it" is distinguishable from
	// "the client cleared it". AckListen is what stops a port forward from
	// publishing the status page alongside the acknowledgement routes, and a
	// plain string would let any client that omits the field silently re-widen
	// an exposure the operator deliberately narrowed.
	AckListen *string `json:"ack_listen"`
}

// webhookViewName is the endpoint's name, defaulting to what the original
// single endpoint has always been called.
func webhookViewName(h config.Webhook) string {
	if n := strings.TrimSpace(h.Name); n != "" {
		return n
	}
	return "webhook"
}

// viewSettings projects a config into the secret-free outbound shape.
func viewSettings(c *config.Config) settingsView {
	v := settingsView{
		Policies:         c.Policies,
		Rules:            c.Rules,
		QuietHours:       c.QuietHours,
		SecretsMechanism: c.Secrets.Mechanism,
		PlaintextFields:  c.PlaintextFields,
		Consoles:         []consoleView{},
		Web: webView{
			Listen:     c.Web.Listen,
			AckBaseURL: c.Web.AckBaseURL,
			AckListen:  c.Web.AckListen,
			AckKeySet:  !c.Web.AckKey.IsZero(),
		},
	}
	v.HookConditions = config.KnownConditions
	for _, h := range c.Hooks {
		v.Hooks = append(v.Hooks, hookView{
			Name: h.Name, Product: h.Product, Condition: h.Condition,
			Severity: h.Severity, Entity: h.Entity,
			TokenSet: !h.Token.IsZero(), BearerSet: !h.Bearer.IsZero(),
		})
	}
	if v.Hooks == nil {
		v.Hooks = []hookView{}
	}
	if v.Rules == nil {
		v.Rules = rule.Set{}
	}
	for _, con := range c.Consoles {
		sources := con.Sources
		if sources == nil {
			sources = []string{}
		}
		v.Consoles = append(v.Consoles, consoleView{
			Name:               con.Name,
			Host:               con.Host,
			APIKeySet:          !con.APIKey.IsZero(),
			APIKeyCredential:   con.APIKeyCredential,
			Fingerprint:        con.Fingerprint,
			InsecureSkipVerify: con.InsecureSkipVerify,
			Sources:            sources,
		})
	}
	if n := c.Channels.Ntfy; n != nil {
		v.Channels.Ntfy = &ntfyView{
			Enabled:   n.Enabled,
			ServerURL: n.ServerURL,
			Topic:     n.Topic,
			TokenSet:  !n.Token.IsZero(),
		}
	}
	if o := c.Channels.Pushover; o != nil {
		v.Channels.Pushover = &pushoverView{
			Enabled:  o.Enabled,
			TokenSet: !o.Token.IsZero(),
			UserSet:  !o.User.IsZero(),
			Device:   o.Device,
			Sound:    o.Sound,
		}
	}
	for _, h := range c.WebhookEndpoints() {
		v.Channels.Webhooks = append(v.Channels.Webhooks, webhookView{
			Name:    webhookViewName(h),
			Enabled: h.Enabled,
			// The URL may itself carry a token in its query string, which is
			// how a good many receivers authenticate. It is shown because the
			// operator has to be able to see and edit what they typed -- and
			// this response is already behind the session gate for exactly
			// that reason.
			URL:                h.URL,
			SecretSet:          !h.Secret.IsZero(),
			Headers:            h.Headers,
			InsecureSkipVerify: h.InsecureSkipVerify,
		})
	}
	if e := c.Channels.Email; e != nil {
		recips := e.Recipients
		if recips == nil {
			recips = []string{}
		}
		v.Channels.Email = &emailView{
			Enabled:     e.Enabled,
			Host:        e.Host,
			Port:        e.Port,
			Username:    e.Username,
			PasswordSet: !e.Password.IsZero(),
			TLS:         e.TLS,
			From:        e.From,
			Recipients:  recips,
			LogoPath:    e.LogoPath,
		}
	}
	return v
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, viewSettings(s.deps.Config()))
}

// handleSaveSettings applies an update and hands it to the injected SaveFunc.
//
// This package never writes a config file. It builds the next Config and passes
// it on, which means it can never leave a half-written one behind, and the
// daemon keeps ownership of when and how the file is replaced.
func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var upd settingsUpdate
	if err := readJSON(r, &upd); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("that request could not be read"))
		return
	}

	cur := s.deps.Config()
	if cur == nil {
		s.fail(w, r, "reading the current config", errors.New("no config available"))
		return
	}
	next, touched := applyUpdate(cur, upd)

	// Validate here as well as in SaveConfig. A validation failure is meant to
	// be SHOWN -- refusing a bad config with an explanation is the whole point
	// of validating it -- so the message must survive whatever the injected
	// save function does with errors.
	//
	// But only problems this save INTRODUCES may refuse it.
	//
	// The rule used to be "any problem refuses the save", and the effect was
	// that a half-finished channel locked the whole settings page: an operator
	// could not save a perfectly good email configuration because ntfy was
	// mid-setup, so the only way out of a broken config was to fix every part
	// of it in one edit. Reported from the field, and it is the opposite of
	// what a settings page is for.
	//
	// So: you may not make it worse, and you are not held hostage by damage
	// that is already there. Pre-existing problems are carried and reported.
	if err := refusedBy(cur, next); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}

	if err := s.deps.SaveConfig(next); err != nil {
		if errors.Is(err, config.ErrInvalid) {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		s.fail(w, r, "saving the configuration", err)
		return
	}

	// WHAT changed, never the values. A config diff in an audit file is a
	// credential in an audit file.
	sections := changedSections(viewSettings(cur), viewSettings(next), touched)
	s.record(r, audit.Entry{
		Kind:    audit.KindConfigChanged,
		Summary: "settings saved from the web UI",
		Fields:  map[string]string{"changed": strings.Join(sections, ",")},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": viewSettings(next)})
}

// applyUpdate builds the next config from the current one plus an update.
//
// Secrets that were not resent are CARRIED OVER. The form cannot echo a stored
// key back -- that is the rule this whole surface is built around -- so a save
// that dropped anything the operator did not retype would wipe the console API
// key every time somebody fixed a typo in a hostname.
//
// Consoles are matched to their previous selves by name, falling back to
// position. Renaming a console and changing nothing else therefore keeps its
// key; renaming AND reordering in one save does not, and the UI says the key
// must be re-entered rather than pretending otherwise.
func applyUpdate(cur *config.Config, upd settingsUpdate) (*config.Config, []string) {
	next := *cur
	next.PlaintextFields = nil
	var touched []string

	byName := map[string]config.Console{}
	for _, c := range cur.Consoles {
		byName[c.Name] = c
	}

	consoles := []consoleUpdate{}
	if upd.Consoles != nil {
		consoles = *upd.Consoles
		next.Consoles = nil
	}
	for i, in := range consoles {
		prev, ok := byName[in.Name]
		if !ok && i < len(cur.Consoles) {
			prev = cur.Consoles[i]
		}
		con := config.Console{
			Name:               strings.TrimSpace(in.Name),
			Host:               strings.TrimSpace(in.Host),
			APIKey:             prev.APIKey,
			APIKeyCredential:   strings.TrimSpace(in.APIKeyCredential),
			Fingerprint:        strings.TrimSpace(in.Fingerprint),
			InsecureSkipVerify: in.InsecureSkipVerify,
			Sources:            in.Sources,
		}
		if in.APIKeyNew != "" {
			con.APIKey = secret.Secret(in.APIKeyNew)
			touched = append(touched, "console "+con.Name+" api key")
		}
		next.Consoles = append(next.Consoles, con)
	}

	// Each channel below is replaced only when the update MENTIONS it.
	//
	// This used to clear next.Channels wholesale first, so that a save
	// mentioning "channels" at all deleted every channel it did not name. The
	// Webhooks tab posts exactly one -- channels.webhooks -- and so deleted
	// ntfy, email and Pushover on a site that had them, reporting "Saved."
	// Nothing was delivered again until somebody noticed and retyped it all.
	//
	// A channel is turned OFF by its enabled flag, never by omission, so
	// absent can safely mean "leave alone" for every one of them.
	chans := channelsUpdate{}
	if upd.Channels != nil {
		chans = *upd.Channels
	}
	if in := chans.Ntfy; in != nil {
		n := config.Ntfy{
			Enabled:   in.Enabled,
			ServerURL: strings.TrimSpace(in.ServerURL),
			Topic:     strings.TrimSpace(in.Topic),
		}
		if cur.Channels.Ntfy != nil {
			n.Token = cur.Channels.Ntfy.Token
		}
		if in.TokenNew != "" {
			n.Token = secret.Secret(in.TokenNew)
			touched = append(touched, "ntfy token")
		}
		next.Channels.Ntfy = &n
	}
	if in := chans.Email; in != nil {
		e := config.Email{
			Enabled:    in.Enabled,
			Host:       strings.TrimSpace(in.Host),
			Port:       in.Port,
			Username:   in.Username,
			TLS:        strings.TrimSpace(in.TLS),
			From:       strings.TrimSpace(in.From),
			Recipients: in.Recipients,
			LogoPath:   in.LogoPath,
		}
		if cur.Channels.Email != nil {
			e.Password = cur.Channels.Email.Password
		}
		if in.PasswordNew != "" {
			e.Password = secret.Secret(in.PasswordNew)
			touched = append(touched, "email password")
		}
		next.Channels.Email = &e
	}
	if in := chans.Pushover; in != nil {
		o := config.Pushover{
			Enabled: in.Enabled,
			Device:  strings.TrimSpace(in.Device),
			Sound:   strings.TrimSpace(in.Sound),
		}
		// Carried forward unless replaced. The form cannot echo the stored
		// value back, so "unchanged" has to be expressible as "sent nothing".
		if cur.Channels.Pushover != nil {
			o.Token, o.User = cur.Channels.Pushover.Token, cur.Channels.Pushover.User
		}
		if in.TokenNew != "" {
			o.Token = secret.Secret(in.TokenNew)
			touched = append(touched, "pushover token")
		}
		if in.UserNew != "" {
			o.User = secret.Secret(in.UserNew)
			touched = append(touched, "pushover user key")
		}
		next.Channels.Pushover = &o
	}
	if chans.Webhooks != nil {
		// Signing secrets are carried across by NAME, for the same reason hook
		// credentials are: the browser is never sent one and so cannot send
		// one back. Renaming an endpoint therefore drops its secret, which is
		// visible in the form rather than silent.
		bySecret := map[string]secret.Secret{}
		for _, prev := range cur.WebhookEndpoints() {
			bySecret[strings.ToLower(webhookViewName(prev))] = prev.Secret
		}
		next.Channels.Webhook = nil
		next.Channels.Webhooks = nil
		for _, in := range *chans.Webhooks {
			h := config.Webhook{
				Name:               strings.TrimSpace(in.Name),
				Enabled:            in.Enabled,
				URL:                strings.TrimSpace(in.URL),
				Headers:            in.Headers,
				InsecureSkipVerify: in.InsecureSkipVerify,
				Secret:             bySecret[strings.ToLower(strings.TrimSpace(in.Name))],
			}
			if in.SecretNew != "" {
				h.Secret = secret.Secret(in.SecretNew)
				touched = append(touched, "webhook "+h.Name+" signing secret")
			}
			next.Channels.Webhooks = append(next.Channels.Webhooks, h)
		}
	}

	if upd.Rules != nil {
		next.Rules = *upd.Rules
	}
	if upd.QuietHours != nil {
		next.QuietHours = *upd.QuietHours
	}

	if upd.Hooks != nil {
		// Credentials are carried across by NAME, because that is the only
		// stable handle the browser has -- it is never sent the token, so it
		// cannot send one back. Renaming a hook therefore mints new
		// credentials and breaks its Alarm Manager rule, which is stated in
		// the interface rather than discovered at 3am.
		byName := map[string]config.Hook{}
		for _, h := range cur.Hooks {
			byName[h.Name] = h
		}
		next.Hooks = nil
		for _, in := range *upd.Hooks {
			name := strings.TrimSpace(in.Name)
			prev := byName[name]
			h := config.Hook{
				Name:      name,
				Product:   strings.TrimSpace(in.Product),
				Condition: strings.TrimSpace(in.Condition),
				Severity:  strings.TrimSpace(in.Severity),
				Entity:    strings.TrimSpace(in.Entity),
				Token:     prev.Token,
				Bearer:    prev.Bearer,
			}
			if in.Regenerate {
				// Cleared rather than minted here: config.Save mints what is
				// missing, so there is one place that decides how long a hook
				// credential is and what it is made of.
				h.Token, h.Bearer = "", ""
				touched = append(touched, "hook "+name+" credentials")
			}
			next.Hooks = append(next.Hooks, h)
		}
	}

	if upd.Policies != nil {
		// An empty map means "use the shipped defaults for everything", which
		// is a real thing to want and is how the config starts out. Stored as
		// nil so the file says nothing rather than saying {}.
		if len(*upd.Policies) == 0 {
			next.Policies = nil
		} else {
			next.Policies = *upd.Policies
		}
	}

	// The ack signing key is never editable here. Rotating it invalidates every
	// acknowledgement link already sent, which for alerts still repeating means
	// the only way left to acknowledge them is this UI -- a real cost, and not
	// one to incur as a side effect of saving a form.
	// Assigned field by field onto the COPY rather than built fresh.
	//
	// Building a fresh config.Web here zeroed every field this function does
	// not name -- which silently wiped PasswordHash on every save. Saving any
	// setting logged the operator out of their own installation, and on a
	// service install the setup token that would let them back in is printed
	// to a stdout that does not exist, so it was a lockout. AckListen went the
	// same way, taking the scoping that keeps a port forward from publishing
	// the status page with it.
	//
	// Whole-struct assignment is what made a new field silently droppable, so
	// it does not happen here any more.
	next.Web.Listen = strings.TrimSpace(upd.Web.Listen)
	if upd.Web.AckBaseURL != nil {
		next.Web.AckBaseURL = strings.TrimSpace(*upd.Web.AckBaseURL)
	}
	if upd.Web.AckListen != nil {
		next.Web.AckListen = strings.TrimSpace(*upd.Web.AckListen)
	}
	next.Web.AckKey = cur.Web.AckKey
	next.Web.PasswordHash = cur.Web.PasswordHash
	if next.Web.Listen == "" {
		next.Web.Listen = cur.Web.Listen
	}

	// The same defaults the load path applies.
	//
	// They only ran on load, so a field left blank in the interface was
	// refused while the identical field left blank in the file was filled in.
	// A brand-new email channel posted tls:"" and came back with "tls "" is
	// not auto, starttls, implicit or none" -- which reads as a typo rather
	// than as a field the form never asked for -- and a blank port saved as 0
	// and then displayed as 0.
	next.ApplyDefaults()

	return &next, touched
}

// refusedBy reports the problems this save would ADD, or nil when it adds
// none.
//
// Problems already present in the current configuration are not the new
// edit's fault and must not block it, or a configuration can become
// impossible to repair one field at a time.
func refusedBy(cur, next *config.Config) error {
	before := map[string]bool{}
	if err := cur.Validate(); err != nil {
		for _, p := range problemsOf(err) {
			before[p] = true
		}
	}

	var added config.Problems
	if err := next.Validate(); err != nil {
		for _, p := range problemsOf(err) {
			if !before[p] {
				added = append(added, p)
			}
		}
	}
	if len(added) == 0 {
		return nil
	}
	return added
}

// problemsOf unpacks a validation error into its individual problems.
func problemsOf(err error) []string {
	var probs config.Problems
	if errors.As(err, &probs) {
		return probs
	}
	return []string{err.Error()}
}

// changedSections names what moved, for the audit record. Computed from the
// SECRET-FREE views, so there is no path by which a value could reach it.
func changedSections(before, after settingsView, touched []string) []string {
	var out []string
	if !reflect.DeepEqual(before.Consoles, after.Consoles) {
		out = append(out, "consoles")
	}
	if !reflect.DeepEqual(before.Channels, after.Channels) {
		out = append(out, "channels")
	}
	if !reflect.DeepEqual(before.Rules, after.Rules) {
		out = append(out, "rules")
	}
	if !reflect.DeepEqual(before.Hooks, after.Hooks) {
		out = append(out, "hooks")
	}
	if !reflect.DeepEqual(before.Policies, after.Policies) {
		out = append(out, "policies")
	}
	if !reflect.DeepEqual(before.QuietHours, after.QuietHours) {
		out = append(out, "quiet_hours")
	}
	if !reflect.DeepEqual(before.Web, after.Web) {
		out = append(out, "web")
	}
	out = append(out, touched...)
	if len(out) == 0 {
		out = append(out, "nothing")
	}
	sort.Strings(out)
	return out
}
