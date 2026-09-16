package protect

import "net/url"

// redactURL renders a URL as scheme://host[:port] and nothing else.
//
// Protect's stream and snapshot URLs embed a path token that is all anyone on
// the network needs to watch a camera, so no path, query or fragment from this
// console ever reaches a log line or an error string. It costs nothing to
// apply the rule to every URL rather than only to the ones known to carry one.
func redactURL(u *url.URL) string {
	if u == nil {
		return "<nil>"
	}
	r := url.URL{Scheme: u.Scheme, Host: u.Host}
	return r.String()
}
