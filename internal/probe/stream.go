package probe

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// maxCaptureMessages bounds one capture.
//
// The cap exists so an unattended probe against a busy site terminates, not to
// shape what is collected -- per-type bucketing already guarantees a rare type
// survives a flood of common ones, which is what a flat cap could not do.
const maxCaptureMessages = 3000

// DefaultListen is how long a capture runs when the operator says nothing.
//
// Thirty seconds is long enough for a person to walk to a door and trigger
// something, which is the point: several event classes do not exist unless
// somebody does something, so the capture window is an interval of human
// activity rather than a sampling period.
const DefaultListen = 30 * time.Second

// handshakeTimeout is generous because a console under load can be slow to
// upgrade, and a failed handshake is indistinguishable from an absent endpoint
// in the report -- which would turn "your console was busy" into "this
// firmware has no such socket".
const handshakeTimeout = 20 * time.Second

// Stream is one push surface to listen on.
type Stream struct {
	Product string
	Name    string
	Path    string
	Auth    AuthKind
	Known   bool
	Expect  string
}

// Streams are the push surfaces this probe knows to ask about.
//
// The unofficial wss://.../proxy/protect/ws/updates socket is deliberately
// absent. It is not part of any supported surface, this product does not build
// on it, and a capability report that encouraged others to would be doing
// harm rather than research.
var Streams = []Stream{
	{Product: "protect", Name: "events", Known: true, Auth: AuthProtect,
		Path:   "/proxy/protect/integration/v1/subscribe/events",
		Expect: "the event vocabulary -- 16 types at v6.2.83, 39 at v7.3.53"},
	{Product: "protect", Name: "devices", Known: true, Auth: AuthProtect,
		Path:   "/proxy/protect/integration/v1/subscribe/devices",
		Expect: "state flips; camera disconnect lives here, not in events"},
	{Product: "access", Name: "notifications", Known: true, Auth: AuthAccess,
		Path:   "/proxy/access/api/v1/developer/devices/notifications",
		Expect: "only two message shapes have ever been captured; see SOURCES.md"},

	// THE SAME SOCKET, WHERE IT MIGHT HAVE MOVED TO.
	//
	// The REST base says `integration` and the socket says `api`, which is
	// real and documented in internal/source/access. On an ENVR running
	// Access 1.x the `api` path answered 404 to a key that the `integration`
	// REST paths accepted -- so either the socket moved to the REST base or
	// it is gone from that firmware, and those are very different facts.
	//
	// Asking both is how a report answers that. Not Known: this build does
	// not subscribe here, and if it ever does, the entry above changes rather
	// than this one.
	{Product: "access", Name: "notifications-integration", Auth: AuthAccess,
		Path:   "/proxy/access/integration/v1/developer/devices/notifications",
		Expect: "whether the notifications socket lives under the REST base on this firmware"},
}

// StreamResult is one capture, with nothing identifying in it.
type StreamResult struct {
	Record  string `json:"record"`
	Product string `json:"product"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Known   bool   `json:"known"`

	// Status is always set and is never an error return -- see Capture.
	Status string `json:"status"`

	ListenSeconds int `json:"listen_seconds"`
	Messages      int `json:"messages"`
	Unreadable    int `json:"unreadable,omitempty"`
	Dropped       int `json:"dropped,omitempty"`

	// Types is every distinct message type, each with its own count, samples
	// and schema.
	Types map[string]*Bucket `json:"types"`

	// TypeNames is the sorted key list, so a reader sees the vocabulary
	// without decoding the map and two reports diff cleanly.
	TypeNames []string `json:"type_names"`
}

// Capture listens on one socket for d and returns what arrived.
//
// IT NEVER RETURNS AN ERROR. A capture that could not connect is a finding
// about the console, and a probe that aborted a survey because one socket was
// absent would be least useful against exactly the firmware it most needs to
// describe. Every outcome is a well-formed record.
func (c *Client) Capture(ctx context.Context, s Stream, d time.Duration) StreamResult {
	if d <= 0 {
		d = DefaultListen
	}
	// Buckets are per capture, never shared: one socket's message cap must
	// not consume another's. The PSEUDONYMISER is shared, which is what keeps
	// one device carrying one label across the whole report.
	b := NewBuckets(c.p)
	res := StreamResult{
		Record: "stream", Product: s.Product, Name: s.Name,
		Path: s.Path, Known: s.Known, ListenSeconds: int(d.Seconds()),
		Types: map[string]*Bucket{},
	}

	dialer := captureDialer()

	hdr := http.Header{}
	switch s.Auth {
	case AuthProtect, AuthAccess:
		key := c.protectKey
		if s.Auth == AuthAccess {
			key = c.accessKey
		}
		if !key.IsZero() {
			hdr["X-API-KEY"] = []string{key.Reveal()}
		}
	case AuthNetwork:
		if !c.networkKey.IsZero() {
			hdr["X-API-Key"] = []string{c.networkKey.Reveal()}
		}
	case AuthNone:
	}

	if err := c.pacer.Wait(ctx); err != nil {
		res.Status = "cancelled"
		return res
	}

	wsURL := "wss://" + strings.TrimPrefix(c.base, "https://") + s.Path
	conn, resp, err := dialer.DialContext(ctx, wsURL, hdr)
	if err != nil {
		res.Status = "handshake failed: " + errorSummary(err)
		if resp != nil {
			res.Status += " (HTTP " + strconv.Itoa(resp.StatusCode) + ")"
			_ = resp.Body.Close()
		}
		return res
	}
	defer conn.Close()
	res.Status = "connected"

	deadline := time.Now().Add(d)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Closing the socket from a watchdog is what makes the read loop
	// interruptible: gorilla's ReadMessage does not take a context, so a
	// cancelled probe would otherwise sit until the read deadline.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	conn.SetReadLimit(1 << 20)
	for b.Total() < maxCaptureMessages {
		if time.Now().After(deadline) {
			break
		}
		_ = conn.SetReadDeadline(deadline)
		_, data, err := conn.ReadMessage()
		if err != nil {
			// Expected at the end of every successful capture: the deadline
			// expires and the read fails. Reported only when it happened
			// early, because "closed at the end of the window" is not news.
			if time.Now().Before(deadline.Add(-time.Second)) {
				res.Status = "connected, then: " + errorSummary(err)
			}
			break
		}
		b.Observe(data)
	}

	res.Messages = b.Total()
	res.Unreadable = b.Unreadable()
	res.Dropped = b.Dropped()
	res.Types = b.All()
	res.TypeNames = b.Types()
	sort.Strings(res.TypeNames)
	return res
}

// captureDialer builds the websocket dialer every capture uses.
//
// A FUNCTION RATHER THAN A LITERAL INSIDE Capture, so a test can assert the
// local-network guard is still attached to it. gorilla's Dialer has its own
// default net.Dial, so a NetDialContext deleted in a refactor does not fail to
// compile and does not fail to connect -- it silently leaves the socket half of
// the probe able to reach the whole internet while the HTTP half stays
// restricted. That is the failure worth a test of its own.
func captureDialer() *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		NetDialContext:   Dialer().DialContext,
		TLSClientConfig:  tlsConfig(true),
		// No proxy. A proxy would make the connection go to the PROXY's
		// address -- possibly local -- while the request reaches an arbitrary
		// host beyond it, and would receive API-key-bearing traffic nobody
		// chose to send it.
		Proxy: nil,
	}
}
