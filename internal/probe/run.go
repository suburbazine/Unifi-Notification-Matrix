package probe

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/source/protect"
)

// Options configures a probe run.
type Options struct {
	// Host is the console. It must be on a local network; CheckHost reports
	// that clearly here, and the dialer enforces it on every connection.
	Host string

	ProtectKey secret.Secret
	AccessKey  secret.Secret
	NetworkKey secret.Secret

	// Listen is the capture window per socket.
	Listen time.Duration

	// Products limits the run. Empty means all of them.
	Products []string

	// Progress reports what is happening, including the prompt that asks the
	// operator to trigger something during the capture window. It is not
	// optional in practice: a probe that listened silently for ninety seconds
	// would collect nothing but idle traffic, because several event classes
	// only exist when somebody does something.
	Progress func(string)

	// Version is the build identifier recorded in the report.
	Version string
}

func (o Options) wants(product string) bool {
	if len(o.Products) == 0 {
		return true
	}
	for _, p := range o.Products {
		if strings.EqualFold(p, product) {
			return true
		}
	}
	return false
}

func (o Options) say(format string, args ...any) {
	if o.Progress != nil {
		o.Progress(fmt.Sprintf(format, args...))
	}
}

// Run probes a console and returns a report with nothing identifying in it.
func Run(ctx context.Context, opts Options) (*Report, error) {
	// The courtesy check, for a clear message at the CLI rather than a dial
	// failure. It is NOT the protection -- a name that resolves locally now
	// and publicly at connect time is caught in the dialer, which is the only
	// place that sees the address actually being connected to.
	if err := CheckHost(ctx, opts.Host); err != nil {
		return nil, err
	}

	p := NewPseudonymiser()
	c, err := NewClient(ClientConfig{
		Host: opts.Host, ProtectKey: opts.ProtectKey,
		AccessKey: opts.AccessKey, NetworkKey: opts.NetworkKey,
		Pseudonymiser: p,
	})
	if err != nil {
		return nil, err
	}

	r := &Report{Meta: Meta{
		Record: "meta", SchemaVersion: SchemaVersion,
		ProbeVersion: opts.Version,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Versions:     map[string]string{},
		Redaction: "names, MACs, IPs, ids, serials and free text replaced with " +
			"per-report counters; timestamps and large numbers replaced with type " +
			"classes; field names, types and vocabulary terms kept",
	}}

	site := ""
	for _, e := range Catalogue {
		if !opts.wants(e.Product) {
			continue
		}
		if e.NeedsSite() {
			if site == "" {
				if id, ok := c.ResolveSite(ctx); ok {
					site = id
				} else {
					r.Endpoints = append(r.Endpoints, EndpointResult{
						Record: "endpoint", Product: e.Product, Path: e.Path,
						Method: "GET", Known: e.Known,
						Error: "skipped: no site id could be resolved",
					})
					continue
				}
			}
			e = e.WithSite(site)
		}
		opts.say("GET %s", e.Path)
		res := c.Get(ctx, e)
		if site != "" {
			// The wire URL carried the real site id; the published one must
			// not. Pseudonymiser.URL labels id-shaped path segments.
			res.Path = strings.ReplaceAll(res.Path, site, p.Value(site))
		}
		r.Endpoints = append(r.Endpoints, res)
		readVersion(r.Meta.Versions, e, res)
	}

	for _, s := range Streams {
		if !opts.wants(s.Product) {
			continue
		}
		listen := opts.Listen
		if listen <= 0 {
			listen = DefaultListen
		}
		opts.say("")
		opts.say("listening on %s/%s for %s", s.Product, s.Name, listen)
		opts.say("TRIGGER THE THING YOU WANT CAPTURED NOW -- walk past a camera, " +
			"open a door, press a doorbell. Several event classes do not exist " +
			"unless somebody does something, and this window is the only chance " +
			"this run has to see one.")
		res := c.Capture(ctx, s, listen)
		opts.say("  %s: %d message(s), %d type(s)", res.Status, res.Messages, len(res.TypeNames))
		r.Streams = append(r.Streams, res)
	}

	r.Findings = diff(r)
	return r, nil
}

// readVersion pulls the firmware version out of a meta endpoint.
//
// Kept in full, unpseudonymised, and that is the point: a report that cannot
// say which firmware produced a shape describes nothing. Version and model are
// the only identifying facts a capability report genuinely needs, so they are
// the only ones it keeps.
func readVersion(into map[string]string, e Endpoint, res EndpointResult) {
	if res.Status != 200 || res.Sample == nil {
		return
	}
	m, ok := res.Sample.(map[string]any)
	if !ok {
		return
	}
	for _, k := range []string{"applicationVersion", "version", "firmwareVersion", "controllerVersion"} {
		if v, ok := m[k].(string); ok && v != "" && !isPseudonym(v) {
			into[e.Product] = v
			return
		}
	}
}

// diff turns the raw capture into the two statements an operator actually
// wants: what this console has that this build does not handle, and what this
// build expects that this console does not have.
func diff(r *Report) []Finding {
	var out []Finding

	for _, e := range r.Endpoints {
		switch {
		case e.Status == 200 && !e.Known:
			out = append(out, Finding{
				Record: "finding", Kind: "endpoint.undocumented", Product: e.Product,
				Detail: e.Path,
				Note:   "answers on this firmware and this build does not use it",
			})
		case e.Status == 404 && e.Known:
			out = append(out, Finding{
				Record: "finding", Kind: "endpoint.missing", Product: e.Product,
				Detail: e.Path,
				Note:   "this build depends on this path and this firmware does not serve it",
			})
		}
	}

	known := map[string]bool{}
	for _, t := range protect.KnownEventTypes() {
		known[t] = true
	}

	for _, s := range r.Streams {
		for _, key := range s.TypeNames {
			if s.Product == "protect" {
				if t, ok := eventTypeFrom(key); ok && !known[t] {
					out = append(out, Finding{
						Record: "finding", Kind: "event.unhandled", Product: "protect",
						Detail: t,
						Note: "arrived on the " + s.Name + " socket and is absent from " +
							"this build's mapping table, so it raises nothing",
					})
				}
				continue
			}
			// For products without a mapping table yet, every type is a
			// finding, because none of them is handled.
			out = append(out, Finding{
				Record: "finding", Kind: "event.unhandled", Product: s.Product,
				Detail: key,
				Note:   "this build has no " + s.Product + " source; the type is recorded, not handled",
			})
		}
		if s.Unreadable > 0 {
			out = append(out, Finding{
				Record: "finding", Kind: "stream.unreadable", Product: s.Product,
				Detail: fmt.Sprintf("%d frame(s) on %s were not JSON", s.Unreadable, s.Name),
				Note:   "content not captured: what cannot be parsed cannot be redacted",
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// eventTypeFrom pulls the Protect event type out of a composite bucket key.
func eventTypeFrom(key string) (string, bool) {
	for _, part := range strings.Split(key, "|") {
		if v, ok := strings.CutPrefix(part, "item.type="); ok {
			return v, v != ""
		}
	}
	return "", false
}
