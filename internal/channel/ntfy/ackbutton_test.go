package ntfy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ack"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
)

// PRESS THE BUTTON.
//
// The Acknowledge button was an ntfy http action with method=GET. ntfy sends
// that in the background and shows nobody the response; the ack route answers
// a GET with a confirmation page, so the button acknowledged nothing -- and
// clear=true then removed the notification, so the operator believed it had.
// Found on a real site's ntfy topic.
//
// The tests that existed compared the action STRING, and passed. This one
// does what a phone does: parses the action the way ntfy does, sends that
// request to the real acknowledgement handler, and asks the store whether the
// incident is acknowledged.
func TestTheAcknowledgeButtonAcknowledges(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := ack.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ack.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	opened := time.Now().Add(-time.Minute)
	inc := incident.Open("inc-ntfy", "internal/peer_sentry/source-silent",
		incident.SeverityHigh, "internal", "Peer link: sentry has gone silent", "", opened)
	if err := db.Put(context.Background(), inc); err != nil {
		t.Fatal(err)
	}
	h, err := ack.New(db, signer)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	action, ok := ackAction(signer.URL(srv.URL, inc.ID, inc.OpenedAt, ""))
	if !ok {
		t.Fatal("no action was built for an ordinary ack URL")
	}

	// Parse it as ntfy does: "<type>, <label>, <url>, key=value, ...".
	parts := strings.Split(action, ", ")
	if len(parts) < 3 || parts[0] != "http" {
		t.Fatalf("action %q is not an ntfy http action", action)
	}
	target := strings.Trim(parts[2], `"'`)
	method := http.MethodPost // ntfy's default for an http action
	for _, p := range parts[3:] {
		if k, v, ok := strings.Cut(p, "="); ok && k == "method" {
			method = v
		}
	}
	if _, err := url.Parse(target); err != nil {
		t.Fatalf("the button's URL does not parse: %v", err)
	}

	// The phone presses it: a background request, response shown to nobody.
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("the button's request answered %d; ntfy would show an error", resp.StatusCode)
	}

	got, err := db.Get(context.Background(), inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Acknowledged() {
		t.Fatalf("the Acknowledge button was pressed (%s %s, answered %d) and the incident "+
			"is NOT acknowledged -- and clear=true has just removed the notification, so "+
			"the operator believes it is", method, target, resp.StatusCode)
	}
	if got.AckVia != "ntfy" {
		t.Errorf("acknowledged via %q; the audit record should say ntfy", got.AckVia)
	}
}
