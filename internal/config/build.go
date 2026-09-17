package config

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ack"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel/email"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel/ntfy"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel/pushover"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel/voice"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel/webhook"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Delivery owns the live channels and hands the scheduler a DeliverFunc.
type Delivery struct {
	queues map[string]*channel.Queue
	ackURL string
	signer *ack.Signer

	// site is the wall clock where the cameras are, used for every time a
	// channel shows a person.
	//
	// Times are stored in UTC, which is right for storage and for sorting,
	// and they come back out of the store carrying UTC as their location. A
	// channel that formats one without converting speaks UTC -- reported from
	// a real installation as a voice call announcing an alarm four hours in
	// the future, in a spoken script with no zone in it to give the game away.
	site *time.Location

	// broken records channels that were configured and could not be built.
	//
	// They used to abort the whole construction, which meant one malformed
	// field in one channel stopped the DAEMON from starting: nothing watched,
	// nothing ingested, no incidents raised, over a From address missing its
	// angle brackets. Observed in the field exactly that way, and it is the
	// worst possible response to a typo in an optional channel.
	//
	// A channel that cannot be built cannot deliver, which is worth saying
	// loudly. It is not worth taking the alarm system down for, because
	// everything else still works.
	broken map[string]error
}

// Broken lists the channels that were configured and could not be built, with
// the reason.
//
// Surfaced through Health and the checklist: a channel that silently does not
// exist is precisely the state this product refuses to allow.
func (d *Delivery) Broken() map[string]error {
	out := make(map[string]error, len(d.broken))
	for k, v := range d.broken {
		out[k] = v
	}
	return out
}

// BuildDelivery constructs every enabled channel and starts its queue.
func BuildDelivery(c *Config, onResult func(channel.Result)) (*Delivery, error) {
	d := &Delivery{
		queues: map[string]*channel.Queue{},
		broken: map[string]error{},
		ackURL: c.Web.AckBaseURL,
		// The operator already tells us this for quiet hours, and it means
		// the same thing here: the site's wall clock, not the server's.
		site: c.QuietHours.SiteLocation(),
	}
	if !c.Web.AckKey.IsZero() {
		s, err := ack.NewSigner(c.Web.AckKey)
		if err != nil {
			return nil, fmt.Errorf("ack key: %w", err)
		}
		d.signer = s
	}

	if n := c.Channels.Ntfy; n != nil && n.Enabled {
		ch, err := ntfy.New(ntfy.Config{
			ServerURL: n.ServerURL,
			Topic:     n.Topic,
			Token:     n.Token,
		}, nil)
		if err != nil {
			// Recorded and skipped, never fatal: see Delivery.broken.
			d.broken["ntfy"] = err
		} else {
			d.queues["ntfy"] = channel.NewQueue(ch, channel.DefaultQueueDepth, onResult)
		}
	}

	if e := c.Channels.Email; e != nil && e.Enabled {
		ch, err := email.New(email.Config{
			Host:     e.Host,
			Port:     e.Port,
			Username: e.Username,
			Password: e.Password,
			TLS:      emailTLSMode(e.TLS),
			From:     e.From,
			To:       e.Recipients,
		})
		if err != nil {
			// Recorded and skipped, never fatal: see Delivery.broken.
			d.broken["email"] = err
		} else {
			d.queues["email"] = channel.NewQueue(ch, channel.DefaultQueueDepth, onResult)
		}
	}

	if o := c.Channels.Pushover; o != nil && o.Enabled {
		ch, err := pushover.New(pushover.Config{
			Token:  o.Token,
			User:   o.User,
			Device: o.Device,
			Sound:  o.Sound,
		}, nil)
		if err != nil {
			// Recorded and skipped, never fatal: see Delivery.broken.
			d.broken["pushover"] = err
		} else {
			d.queues["pushover"] = channel.NewQueue(ch, channel.DefaultQueueDepth, onResult)
		}
	}

	if v := c.Channels.Voice; v != nil && v.Enabled {
		ch, err := voice.New(voice.Config{
			AccountSID: v.AccountSID,
			AuthToken:  v.AuthToken,
			From:       v.From,
			Recipients: v.Recipients,
			Voice:      v.Voice,
			Language:   v.Language,
		}, nil)
		if err != nil {
			// Recorded and skipped, never fatal: see Delivery.broken.
			//
			// It matters more here than anywhere else that this does not
			// return. Validate refuses an incomplete voice channel at save
			// time, so reaching this branch means a config that got past that
			// -- hand-edited, or written by an older build -- and the reply to
			// a mistyped phone number cannot be an alarm system that will not
			// start.
			d.broken["voice"] = err
		} else {
			d.queues["voice"] = channel.NewQueue(ch, channel.DefaultQueueDepth, onResult)
		}
	}

	for _, h := range c.WebhookEndpoints() {
		if !h.Enabled {
			continue
		}
		name := webhookName(h)
		ch, err := webhook.New(webhook.Config{
			ChannelName:        name,
			URL:                h.URL,
			Secret:             h.Secret,
			Headers:            h.Headers,
			InsecureSkipVerify: h.InsecureSkipVerify,
		}, nil)
		if err != nil {
			// Recorded and skipped, never fatal: see Delivery.broken.
			d.broken[name] = err
		} else {
			d.queues[name] = channel.NewQueue(ch, channel.DefaultQueueDepth, onResult)
		}
	}

	return d, nil
}

// emailTLSMode maps the config vocabulary onto the channel's.
//
// An unrecognised value maps to TLSAuto rather than TLSNone: validation
// already refuses unknown values, and if one ever reached here, defaulting to
// "send it in the clear" would be the worst possible interpretation of a typo.
func emailTLSMode(s string) email.TLSMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "starttls":
		return email.TLSSTARTTLS
	case "implicit":
		return email.TLSImplicit
	case "none":
		return email.TLSNone
	default:
		return email.TLSAuto
	}
}

// Test sends one channel's proof-of-configuration message and reports what
// actually happened to THIS attempt.
//
// Named channels only. "Test everything" would fire every channel at once,
// which on a site with email is a way to get rate-limited by your own provider
// while checking a typo.
// The string reports what the test ACTUALLY DID, for the channels where that
// is not "delivered a message". Empty means the generic answer is true.
func (d *Delivery) Test(ctx context.Context, name string) (string, error) {
	q, ok := d.queues[name]
	if !ok {
		return "", fmt.Errorf("channel %q is not enabled", name)
	}
	if err := q.Test(ctx); err != nil {
		return "", err
	}
	return q.TestSummary(), nil
}

// Names lists the live channels.
func (d *Delivery) Names() []string {
	out := make([]string, 0, len(d.queues))
	for n := range d.queues {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Stats reports each queue, for diagnostics.
func (d *Delivery) Stats() []channel.Stats {
	out := make([]channel.Stats, 0, len(d.queues))
	for _, n := range d.Names() {
		out = append(out, d.queues[n].Stats())
	}
	return out
}

// Close stops every queue.
func (d *Delivery) Close() {
	for _, q := range d.queues {
		q.Close()
	}
}

// deliverTimeout bounds one incident's whole fan-out.
//
// Generous, because a channel's own budget is already 60s and this must not
// cut a delivery short that was going to succeed. The scheduler tick is not
// ingest, so waiting here costs escalation latency for other incidents, never
// missed events.
const deliverTimeout = 90 * time.Second

// Deliver is the escalate.DeliverFunc for these channels.
//
// Fans out to every channel in the stage CONCURRENTLY. They are separate
// queues with separate workers, so serialising them would mean a slow SMTP
// server delaying the push notification that was going to wake somebody up --
// the exact thing per-channel queues exist to prevent.
//
// Returns nil if AT LEAST ONE channel accepted. That is the contract the
// scheduler needs: a partial success means somebody was told, so the alert
// happened; a total failure means nobody was, so the incident must stay due
// and be retried sooner rather than treated as a completed nag.
func (d *Delivery) Deliver(ctx context.Context, inc *incident.Incident, stage int, chans []string) error {
	if len(chans) == 0 {
		return errors.New("no channels for this stage")
	}
	alert := d.alertFor(inc, stage)

	ctx, cancel := context.WithTimeout(ctx, deliverTimeout)
	defer cancel()

	var wg sync.WaitGroup
	errs := make([]error, len(chans))
	now := time.Now()

	for i, name := range chans {
		q, ok := d.queues[strings.ToLower(name)]
		if !ok {
			// Should be unreachable: config validation refuses a policy naming
			// a channel that is not enabled. Reported rather than skipped, so
			// that if it ever IS reachable it is loud instead of silent.
			errs[i] = fmt.Errorf("channel %q is not configured", name)
			continue
		}
		wg.Add(1)
		go func(i int, q *channel.Queue) {
			defer wg.Done()
			errs[i] = q.SendAndWait(ctx, alert, now)
		}(i, q)
	}
	wg.Wait()

	var failed []string
	for i, err := range errs {
		if err == nil {
			return nil // somebody was told
		}
		failed = append(failed, fmt.Sprintf("%s: %v", chans[i], err))
	}
	return fmt.Errorf("every channel failed -- %s", strings.Join(failed, "; "))
}

// alertFor renders an incident into the shape a channel sends.
func (d *Delivery) alertFor(inc *incident.Incident, stage int) channel.Alert {
	a := channel.Alert{
		IncidentID: inc.ID,
		Severity:   inc.Severity,
		Title:      inc.Title,
		Body:       inc.Detail,
		OpenedAt:   d.inSiteZone(inc.OpenedAt),
		At:         d.inSiteZone(inc.OpenedAt),
		Stage:      stage,
		Repeat:     inc.AlertCount,
	}
	if inc.LastAlertAt != nil {
		a.At = d.inSiteZone(*inc.LastAlertAt)
	}
	a.AckURL = d.AckURL(inc, "")
	return a
}

// inSiteZone converts a stored time into the site's wall clock.
//
// Done HERE, once, rather than in each channel: alertFor is the only place an
// Alert is built, so every channel present and future gets it right, and none
// of them has to know that the store hands back UTC. A channel that wants to
// print the zone still can -- ntfy and Pushover do -- and it now prints the
// site's rather than the server's.
func (d *Delivery) inSiteZone(t time.Time) time.Time {
	if t.IsZero() || d.site == nil {
		return t
	}
	return t.In(d.site)
}

// AckURL builds the signed acknowledgement link for an incident.
//
// Empty when there is no base URL or no key, which config validation already
// refuses for any config with an enabled channel: an alert nobody can
// acknowledge from the notification itself can only be stopped from a web UI,
// and nobody is opening a web UI at 3am.
func (d *Delivery) AckURL(inc *incident.Incident, via string) string {
	if d.ackURL == "" || d.signer == nil {
		return ""
	}
	return d.signer.URL(d.ackURL, inc.ID, inc.OpenedAt, via)
}
