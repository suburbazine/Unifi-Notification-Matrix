package protect

import (
	"net/url"
	"testing"
)

// Some Protect URLs embed a path token that is all anyone on the network needs
// to watch a camera, so nothing past the authority ever reaches a log.
func TestRedactedURLKeepsOnlySchemeHostAndPort(t *testing.T) {
	u, err := url.Parse("wss://10.0.0.1:443/proxy/protect/integration/v1/subscribe/events?token=SUPERSECRET#frag")
	if err != nil {
		t.Fatal(err)
	}
	got := redactURL(u)
	const want = "wss://10.0.0.1:443"
	if got != want {
		t.Fatalf("redactURL = %q, want %q", got, want)
	}
}

func TestRedactingNothingIsNotACrash(t *testing.T) {
	if got := redactURL(nil); got != "<nil>" {
		t.Fatalf("redactURL(nil) = %q", got)
	}
}
