package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/inbound"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// Hook is one inbound webhook: one URL that UniFi posts to, with one meaning.
//
// There is one of these per Alarm Manager rule, because Alarm Manager rules
// can only be made in the UniFi UI -- no API creates them -- and because the
// payload they send is undocumented and has changed field names between
// firmware revisions. Pointing each rule at its own URL is what lets this
// product be certain what arrived without parsing a body it cannot trust.
type Hook struct {
	// Name identifies the hook. Match it to the name of the Alarm Manager rule
	// that posts to it, so the two are findable from each other at 3am.
	Name string `json:"name"`

	// Token is the secret in the URL. It says WHICH hook an arrival is for.
	//
	// Generated automatically when a hook is added without one, because an
	// operator inventing their own is an operator inventing a short one.
	Token secret.Secret `json:"token,omitempty"`

	// Bearer is the Authorization header the console must send, and it is
	// required -- a hook without one accepts nothing.
	//
	// Also generated automatically. A URL is not an authenticator: it goes
	// through the Alarm Manager form, the console's configuration backup,
	// browser history, and every proxy log on the path. A header does not.
	// UniFi's Alarm Manager webhook action supports custom headers, so this
	// costs the operator one extra paste and closes the case where somebody
	// who merely LEARNS the URL can raise false alarms here.
	Bearer secret.Secret `json:"bearer,omitempty"`

	// Product is which UniFi application this rule lives in, for the setup
	// instructions and for diagnostics: "network", "protect" or "access".
	Product string `json:"product,omitempty"`

	// Condition is what an arrival at this URL MEANS. Empty means a generic
	// inbound alarm.
	Condition string `json:"condition,omitempty"`

	// Severity is this hook's proposal. Empty means high -- an alarm somebody
	// went to the trouble of configuring a rule for is not informational.
	Severity string `json:"severity,omitempty"`

	// Entity names what the incident is about, when the payload names nothing.
	Entity string `json:"entity,omitempty"`
}

// hookTokenBytes is the size of a generated token.
//
// 32 bytes. This is the whole authentication on an endpoint that can raise an
// alarm, it is never typed by a human, and it costs nothing to make guessing
// hopeless.
const hookTokenBytes = 32

// NewHookToken mints a URL-safe token.
func NewHookToken() (secret.Secret, error) {
	b := make([]byte, hookTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("config: generating a hook token: %w", err)
	}
	return secret.Secret(base64.RawURLEncoding.EncodeToString(b)), nil
}

// KnownConditions are the meanings a hook may be given.
//
// A fixed list rather than free text, because the condition becomes part of a
// stored dedup key: a typo would make an alarm that never merges with the
// identical alarm from the same rule, so every occurrence would nag separately
// forever.
var KnownConditions = []string{
	event.ConditionInboundAlarm,
	event.ConditionWANDown,
	event.ConditionThreat,
	event.ConditionPoEFault,
	event.ConditionClientLost,
	event.ConditionOffline,
	event.ConditionDoorForced,
	event.ConditionSmoke,
	event.ConditionPanic,
	event.ConditionTamper,
}

// BuildHooks turns configured hooks into receiver hooks.
func BuildHooks(c *Config) []inbound.Hook {
	out := make([]inbound.Hook, 0, len(c.Hooks))
	for _, h := range c.Hooks {
		if h.Token.IsZero() || h.Bearer.IsZero() {
			// Without a token there is no URL to post to; without a bearer
			// there is nothing authenticating what arrives. Either way the
			// hook is not served -- a blank credential would be an endpoint
			// anybody could hit, which is the whole failure being avoided.
			continue
		}
		cond := strings.TrimSpace(h.Condition)
		if cond == "" {
			cond = event.ConditionInboundAlarm
		}
		sev := incident.Severity(strings.TrimSpace(h.Severity))
		if sev == "" {
			sev = incident.SeverityHigh
		}
		out = append(out, inbound.Hook{
			Name: h.Name, Token: h.Token, Bearer: h.Bearer, Product: h.Product,
			Condition: cond, Severity: sev, EntityName: h.Entity,
		})
	}
	return out
}

// validateHooks refuses hooks that cannot work.
func (c Config) validateHooks() Problems {
	var p Problems
	seen := map[string]bool{}
	for i, h := range c.Hooks {
		where := fmt.Sprintf("hook %d", i)
		if n := strings.TrimSpace(h.Name); n != "" {
			where = fmt.Sprintf("hook %q", n)
		} else {
			p = append(p, where+": needs a name (use the name of the Alarm Manager rule)")
		}
		if seen[h.Name] {
			// Two hooks with one name make the receipts ambiguous, and the
			// receipts are how an operator knows their rule works at all.
			p = append(p, fmt.Sprintf("hook name %q is used more than once", h.Name))
		}
		seen[h.Name] = true

		if !h.Token.IsZero() && len(h.Token.Reveal()) < 16 {
			p = append(p, where+": the token is too short for an endpoint that "+
				"can raise an alarm; clear it and one will be generated")
		}
		if !h.Bearer.IsZero() && len(h.Bearer.Reveal()) < 16 {
			p = append(p, where+": the bearer token is too short; clear it and "+
				"one will be generated")
		}
		if cond := strings.TrimSpace(h.Condition); cond != "" && !knownCondition(cond) {
			p = append(p, fmt.Sprintf("%s: condition %q is not one this build knows (want one of: %s)",
				where, cond, strings.Join(KnownConditions, ", ")))
		}
		if sev := strings.TrimSpace(h.Severity); sev != "" && !incident.Severity(sev).Valid() {
			p = append(p, fmt.Sprintf("%s: severity %q is not valid", where, sev))
		}
	}
	return p
}

func knownCondition(s string) bool {
	for _, k := range KnownConditions {
		if k == s {
			return true
		}
	}
	return false
}
