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
	Webhook  *webhookView  `json:"webhook,omitempty"`
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

type webView struct {
	Listen     string `json:"listen"`
	AckBaseURL string `json:"ack_base_url,omitempty"`
	AckKeySet  bool   `json:"ack_key_set"`
}

// ---- inbound ----

type settingsUpdate struct {
	Consoles   []consoleUpdate     `json:"consoles"`
	Channels   channelsUpdate      `json:"channels"`
	Rules      rule.Set            `json:"rules"`
	QuietHours escalate.QuietHours `json:"quiet_hours"`
	Web        webUpdate           `json:"web"`
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
	Ntfy     *ntfyUpdate     `json:"ntfy"`
	Email    *emailUpdate    `json:"email"`
	Pushover *pushoverUpdate `json:"pushover"`
	Webhook  *webhookUpdate  `json:"webhook"`
}

type pushoverUpdate struct {
	Enabled  bool   `json:"enabled"`
	TokenNew string `json:"token_new"`
	UserNew  string `json:"user_new"`
	Device   string `json:"device"`
	Sound    string `json:"sound"`
}

type webhookUpdate struct {
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

type webUpdate struct {
	Listen     string `json:"listen"`
	AckBaseURL string `json:"ack_base_url"`
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
			AckKeySet:  !c.Web.AckKey.IsZero(),
		},
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
	if h := c.Channels.Webhook; h != nil {
		v.Channels.Webhook = &webhookView{
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
		}
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
	if err := next.Validate(); err != nil {
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

	next.Consoles = nil
	for i, in := range upd.Consoles {
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

	next.Channels = config.Channels{}
	if in := upd.Channels.Ntfy; in != nil {
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
	if in := upd.Channels.Email; in != nil {
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
	if in := upd.Channels.Pushover; in != nil {
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
	if in := upd.Channels.Webhook; in != nil {
		h := config.Webhook{
			Enabled:            in.Enabled,
			URL:                strings.TrimSpace(in.URL),
			Headers:            in.Headers,
			InsecureSkipVerify: in.InsecureSkipVerify,
		}
		if cur.Channels.Webhook != nil {
			h.Secret = cur.Channels.Webhook.Secret
		}
		if in.SecretNew != "" {
			h.Secret = secret.Secret(in.SecretNew)
			touched = append(touched, "webhook signing secret")
		}
		next.Channels.Webhook = &h
	}

	next.Rules = upd.Rules
	next.QuietHours = upd.QuietHours

	// The ack signing key is never editable here. Rotating it invalidates every
	// acknowledgement link already sent, which for alerts still repeating means
	// the only way left to acknowledge them is this UI -- a real cost, and not
	// one to incur as a side effect of saving a form.
	next.Web = config.Web{
		Listen:     strings.TrimSpace(upd.Web.Listen),
		AckKey:     cur.Web.AckKey,
		AckBaseURL: strings.TrimSpace(upd.Web.AckBaseURL),
	}
	if next.Web.Listen == "" {
		next.Web.Listen = cur.Web.Listen
	}
	return &next, touched
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
