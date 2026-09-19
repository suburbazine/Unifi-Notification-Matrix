package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// THE PORT THE OPERATOR IS TOLD TO FORWARD.
//
// `web.ack_listen` exists so a port forward has something safe to point at: a
// listener on which /ack/ is the only thing that exists. Safe in terms of what
// it SERVES -- it has been safe in terms of what it COSTS only by accident.
//
// A forwarded port is found by background scanning within days and probed
// indefinitely afterwards. Three things in the default http.Server shape are
// wrong for that:
//
//   - MaxHeaderBytes unset means Go's 1 MiB default, per request;
//   - a bare listener accepts connections without limit, each holding a
//     goroutine, two buffers and a file descriptor for up to IdleTimeout;
//   - nothing bounds how many requests are inside the handler at once, and
//     the handler shares a process, a SQLite pool and a write lock with the
//     escalation engine.
//
// The third is the one that matters. The failure worth preventing here is not
// a refused acknowledgement -- that is cheap and recoverable -- it is an ALARM
// THAT CANNOT BE DELIVERED because the ack port is busy. Measured under load,
// unbounded concurrency pushed the engine's compare-and-swap p99 from 2ms to
// 4.6ms; unbounded connections are worse than that, because they exhaust file
// descriptors for the whole daemon rather than slowing one part of it.
//
// Everything below is stdlib. This product has no third-party runtime
// dependencies and is not gaining one for twenty-five lines.

// maxAckHeaderBytes caps the request head.
//
// A real acknowledgement URL is about 120 bytes and the whole request is a
// line, a Host and a User-Agent. Eight kilobytes is roomy for a browser
// carrying cookies and nothing else needs more.
const maxAckHeaderBytes = 8 << 10

// maxAckConns is how many connections this listener will hold open at once.
//
// Past it, accept simply waits: the connection sits in the kernel backlog
// rather than costing a goroutine here. A refused acknowledgement retried a
// second later is invisible to a person tapping a link; a daemon out of file
// descriptors is not.
const maxAckConns = 256

// maxAckInFlight is how many requests may be inside the handler at once.
//
// The number that protects the rest of the product. Past it, callers get a
// 503 and a Retry-After -- which is honest, cheap, and above all does not
// queue behind the SQLite write lock the escalation engine needs.
const maxAckInFlight = 64

// inFlight bounds concurrent requests, refusing rather than queueing.
//
// Refusing is the point. A queue converts a flood into latency for everybody
// including the legitimate tap, and the handler behind it contends for a
// database the alarm path is using.
func inFlight(n int, next http.Handler) http.Handler {
	sem := make(chan struct{}, n)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			next.ServeHTTP(w, r)
		default:
			// The same no-store as every other answer here: this port's
			// responses are about a URL that is a credential, and an
			// intermediary must not keep any of them.
			w.Header().Set("Cache-Control", "no-store, private")
			w.Header().Set("Retry-After", "2")
			http.Error(w, "busy", http.StatusServiceUnavailable)
		}
	})
}

// ackOnly serves /ack/ and answers everything else itself.
//
// A ServeMux rather than this was answering some malformed paths with a 307
// redirect to the cleaned path -- generated before the handler runs, so
// without the Cache-Control and Referrer-Policy every other answer on this
// port carries, and with the token already in the request line. Harmless in
// practice and completely unnecessary: this listener serves one prefix, so it
// does not need a router at all.
func ackOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/ack/") {
			w.Header().Set("Cache-Control", "no-store, private")
			w.Header().Set("Referrer-Policy", "no-referrer")
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// limitedListener caps concurrent connections.
//
// golang.org/x/net/netutil.LimitListener, inlined. Accept blocks while the cap
// is reached, so an excess connection waits in the kernel rather than costing
// a goroutine, a read buffer and a descriptor here.
type limitedListener struct {
	net.Listener
	sem chan struct{}
}

func limitListener(l net.Listener, n int) net.Listener {
	return &limitedListener{Listener: l, sem: make(chan struct{}, n)}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Close releases the slot exactly once. net/http closes a connection on more
// than one path, and a double release would hand out a slot that was never
// taken -- which over a long run removes the limit entirely.
func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
