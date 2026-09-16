package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/unifi"
)

// maxBodyBytes caps what is read from any one response.
//
// A camera list on a large site is genuinely megabytes, and this runs on an
// operator's workstation against hardware nobody here has seen. Reading an
// unbounded body from an unknown endpoint is how a diagnostic tool becomes the
// reason a machine ran out of memory.
const maxBodyBytes = 8 << 20

// requestTimeout matches the inherited probe's 15s. Long enough for a console
// building a large list, short enough that a hung endpoint does not stall a
// survey of thirty paths.
const requestTimeout = 15 * time.Second

// maxAttempts is how many times a single path is tried when the console asks
// for a pause.
const maxAttempts = 4

// Client asks a console read-only questions, paced and pseudonymised.
type Client struct {
	base  string
	hc    *http.Client
	pacer *unifi.Pacer
	p     *Pseudonymiser

	protectKey secret.Secret
	accessKey  secret.Secret
	networkKey secret.Secret
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// Host is whatever the operator typed. It has already passed CheckHost,
	// and every connection is re-checked in the dialer regardless.
	Host string

	ProtectKey secret.Secret
	AccessKey  secret.Secret
	NetworkKey secret.Secret

	// Pseudonymiser is shared with the stream capture so one device carries
	// one label across the whole report.
	Pseudonymiser *Pseudonymiser
}

// NewClient builds a probe client bound to one console.
func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("probe: no console host given")
	}
	p := cfg.Pseudonymiser
	if p == nil {
		p = NewPseudonymiser()
	}
	return &Client{
		base: baseURL(cfg.Host),
		// insecureSkipVerify: UniFi consoles ship self-signed certificates and
		// a probe that refused them would refuse almost every console it
		// exists for. It is safe HERE and nowhere else, because the dialer has
		// already guaranteed the peer is on a local network.
		hc:         HTTPClient(true),
		pacer:      unifi.PacerFor(cfg.Host),
		p:          p,
		protectKey: cfg.ProtectKey,
		accessKey:  cfg.AccessKey,
		networkKey: cfg.NetworkKey,
	}, nil
}

func baseURL(host string) string {
	h := strings.TrimSuffix(strings.TrimSpace(host), "/")
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		return h
	}
	return "https://" + h
}

// EndpointResult is what one path answered, with nothing identifying in it.
type EndpointResult struct {
	Record  string `json:"record"`
	Product string `json:"product"`
	Path    string `json:"path"`
	Method  string `json:"method"`

	// Known says this build already depends on the path. A 404 on a known path
	// and a 200 on an unknown one are the two findings that matter, and they
	// mean opposite things.
	Known bool `json:"known"`

	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`

	// Refused records that this package declined, and why. Reported rather
	// than hidden: an operator comparing the catalogue against the report must
	// be able to see that a path was skipped on purpose.
	Refused string `json:"refused,omitempty"`

	// Error is a transport failure, already stripped of any URL detail.
	Error string `json:"error,omitempty"`

	Bytes  int     `json:"bytes,omitempty"`
	Fields *Schema `json:"schema,omitempty"`
	Sample any     `json:"sample,omitempty"`
}

// Get requests one endpoint and returns a redacted result.
//
// It never returns an error. A survey walks thirty paths against hardware
// nobody here has seen, and one failure must produce a recorded finding rather
// than end the visit -- a 404 IS the answer to "does this firmware have that
// endpoint".
func (c *Client) Get(ctx context.Context, e Endpoint) EndpointResult {
	res := EndpointResult{
		Record: "endpoint", Product: e.Product, Method: http.MethodGet,
		Known: e.Known, Path: e.Path,
	}
	full := c.base + e.Path

	if why := Refuse(http.MethodGet, full); why != "" {
		res.Refused = why
		return res
	}

	var body []byte
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err = c.pacer.Wait(ctx); err != nil {
			res.Error = "cancelled"
			return res
		}
		var retryIn time.Duration
		var retry bool
		body, retryIn, retry, err = c.once(ctx, full, e.Auth, &res)
		if !retry {
			break
		}
		select {
		case <-ctx.Done():
			res.Error = "cancelled"
			return res
		case <-time.After(retryIn):
		}
	}
	if err != nil {
		// The error string is built here rather than wrapped from the
		// transport, because Go's url.Error embeds the full request URL and a
		// substituted site id would then land in the report.
		res.Error = errorSummary(err)
		return res
	}
	if len(body) == 0 {
		return res
	}
	res.Bytes = len(body)

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		// A non-JSON body is a fact about the endpoint and nothing more of it
		// is kept: what cannot be parsed cannot be redacted, and an HTML error
		// page can carry a hostname or a site name in its title.
		res.Error = "response was not JSON"
		return res
	}

	clean := c.p.JSON("", doc)
	sc := NewSchema()
	sc.Observe(clean)
	res.Fields = sc
	res.Sample = firstSample(clean)
	return res
}

// once performs a single attempt, reporting whether it is worth another.
func (c *Client) once(ctx context.Context, full string, auth AuthKind, res *EndpointResult) (body []byte, retryIn time.Duration, retry bool, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, full, nil)
	if err != nil {
		return nil, 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	c.authorise(req, auth)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		_ = resp.Body.Close()
	}()

	res.Status = resp.StatusCode
	res.ContentType = resp.Header.Get("Content-Type")

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		// The Protect Integration API limits to 10 requests per second and an
		// unpaced survey loses roughly half its probes to 429 -- which also
		// skews the result, because whether a camera got measured becomes a
		// function of where it sat in the list.
		d, ok := unifi.RetryAfter(resp, nil)
		if !ok {
			d = time.Second
		}
		return nil, d, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Not an error. "This firmware does not have that endpoint" is the
		// finding, recorded as a status code.
		return nil, 0, false, nil
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, 0, false, err
	}
	return b, 0, false, nil
}

// authorise sets the credential header for a product.
//
// Protect's header is assigned into the map rather than set through
// Header.Set, which canonicalises to "X-Api-Key"; the casing working clients
// send is X-API-KEY, and matching it exactly is why the main client does the
// same thing.
func (c *Client) authorise(req *http.Request, auth AuthKind) {
	switch auth {
	case AuthProtect:
		if !c.protectKey.IsZero() {
			req.Header["X-API-KEY"] = []string{c.protectKey.Reveal()}
		}
	case AuthAccess:
		if !c.accessKey.IsZero() {
			req.Header["X-API-KEY"] = []string{c.accessKey.Reveal()}
		}
	case AuthNetwork:
		if !c.networkKey.IsZero() {
			req.Header["X-API-Key"] = []string{c.networkKey.Reveal()}
		}
	case AuthNone:
	}
}

// errorSummary renders a transport failure without the URL it happened on.
func errorSummary(err error) string {
	switch {
	case errors.Is(err, ErrNotLocal):
		return "refused: not a local address"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	msg := err.Error()
	// net/url and net/http both embed the request URL in their error strings.
	if i := strings.LastIndex(msg, ": "); i > 0 && strings.Contains(msg, "://") {
		msg = msg[i+2:]
	}
	msg = scrubAddresses(msg)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

var (
	addrPortRe = regexp.MustCompile(`\[[0-9a-fA-F:]+\](?::\d+)?|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?`)
	lookupRe   = regexp.MustCompile(`(?i)\blookup\s+\S+`)
)

// scrubAddresses removes the console's address from an error string.
//
// Found by running the probe against a dead local port and reading the output:
// a refused connection produces "dial tcp 192.168.1.1:443: ...", and that
// message was being written into the report as the stream status. Every value
// the console SENDS goes through the pseudonymiser, so it is easy to miss that
// the errors Go generates about the console carry its address too -- the
// redaction has to cover what this process says about the console as well as
// what the console says.
func scrubAddresses(msg string) string {
	msg = addrPortRe.ReplaceAllString(msg, "<addr>")
	return lookupRe.ReplaceAllString(msg, "lookup <host>")
}

// firstSample reduces a decoded body to one representative record.
//
// A forty-camera list describes one shape forty times. The Schema summary has
// already folded in every element, so keeping the whole array would multiply
// the report's size without adding a fact.
func firstSample(v any) any {
	switch t := v.(type) {
	case []any:
		if len(t) == 0 {
			return t
		}
		return t[0]
	case map[string]any:
		for _, k := range []string{"data", "items", "results"} {
			if inner, ok := t[k].([]any); ok && len(inner) > 0 {
				out := map[string]any{}
				for kk, vv := range t {
					if kk == k {
						continue
					}
					out[kk] = vv
				}
				out[k] = []any{inner[0]}
				return out
			}
		}
	}
	return v
}

// ResolveSite finds a site id for the Network paths that need one.
//
// The id is a console identifier rather than a person or a place, but it is
// still identity, so it is substituted into the request and pseudonymised out
// of the report path -- the URL that goes on the wire and the URL that gets
// published are deliberately not the same string.
func (c *Client) ResolveSite(ctx context.Context) (string, bool) {
	e := Endpoint{Product: "network", Auth: AuthNetwork, Path: "/proxy/network/integration/v1/sites"}
	if err := c.pacer.Wait(ctx); err != nil {
		return "", false
	}
	var res EndpointResult
	body, _, _, err := c.once(ctx, c.base+e.Path, AuthNetwork, &res)
	if err != nil || len(body) == 0 {
		return "", false
	}
	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Data) == 0 {
		return "", false
	}
	return doc.Data[0].ID, doc.Data[0].ID != ""
}

// Describe renders a path for the report, with any substituted id replaced.
func (c *Client) Describe(path string) string { return c.p.URL(c.base + path) }
