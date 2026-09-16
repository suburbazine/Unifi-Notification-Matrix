package unifi

import (
	"context"
	"net/http"
	"time"
)

// Console is one UniFi OS host: one certificate, one pin, one rate budget.
//
// It exists so that the correct thing is also the short thing. A caller that
// takes a Console gets the SHARED pacer for that host and the SAME pin every
// other application behind it uses, without having to know that either is a
// per-host fact. Building a private pacer or a second TLS config for the same
// host remains possible, and is a decision a reviewer should ask about rather
// than something that happens by writing the obvious code.
type Console struct {
	// Host is whatever the operator typed: "10.0.0.1", "10.0.0.1:443" or
	// "https://unifi.example.com".
	Host string

	// TLS is the console's certificate policy. Per host, not per application.
	TLS TLS
}

// Key is this console's identity, with scheme and default port normalised
// away.
func (c Console) Key() string { return ConsoleKey(c.Host) }

// Pacer returns the shared pacer for this console.
func (c Console) Pacer() *Pacer { return PacerFor(c.Host) }

// Pace is the pacer's Wait, in the func(context.Context) error shape sources
// take as an injection point.
func (c Console) Pace(ctx context.Context) error { return c.Pacer().Wait(ctx) }

// HTTPClient is a client that verifies this console's pin and is paced by
// nothing -- pacing is the caller's, because only the caller knows which of
// its requests are a burst.
func (c Console) HTTPClient(timeout time.Duration) (*http.Client, error) {
	return c.TLS.HTTPClient(timeout)
}
