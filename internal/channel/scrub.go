package channel

import (
	"errors"
	"net/url"
)

// ScrubTransportError removes the URL that net/http puts in every error.
//
// http.Client.Do wraps failures in *url.Error, whose Error() prints the full
// request URL, query string and path included. For several channels that URL
// IS the credential -- an ntfy topic is enough to subscribe to somebody's
// alarms and to publish fake ones, and a webhook receiver usually carries its
// token in the path. Every one of those channels already prints a redacted
// URL of its own; wrapping the *url.Error alongside it handed back the part
// that had just been removed.
//
// That matters more than it looks, because a delivery error does not stay in a
// log. It is stored on the incident as LastDeliveryError and served from
// /api/incidents, which is deliberately readable without signing in so that a
// wall display works. One failed publish therefore published the topic to
// every device on the network.
//
// Unwrapping keeps the cause -- connection refused, a TLS failure, a refused
// redirect -- and drops only the part the caller already prints redacted.
func ScrubTransportError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}
