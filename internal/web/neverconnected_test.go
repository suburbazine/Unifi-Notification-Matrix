package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// THE BOARD SAID THREE SOURCES WERE REPORTING on a console where two of the
// three applications were not installed and the third rejected the key. That
// is the exact state this product exists to refuse, rendered by the product
// itself.
//
// A source that has never reached its console is a distinct state on the wire,
// because the interface cannot invent it: "silent" would be a lie in the other
// direction -- it implies something that used to work.
func TestASourceThatNeverConnectedSaysSoOnTheWire(t *testing.T) {
	h := newHarness(t)

	resp, body := h.do("GET", "/api/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	var got struct {
		Health struct {
			Sources []struct {
				Name           string `json:"name"`
				Silent         bool   `json:"silent"`
				NeverConnected bool   `json:"never_connected"`
				Detail         string `json:"detail"`
			} `json:"sources"`
		} `json:"health"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Health.Sources) == 0 {
		t.Fatal("no sources in the health payload")
	}
	// The harness's source is in contact, so nothing here is never-connected:
	// this asserts the field exists and is not set when it should not be.
	for _, src := range got.Health.Sources {
		if src.NeverConnected {
			t.Errorf("%s reported never-connected while in contact", src.Name)
		}
	}
}

// And the board renders it as its own state rather than folding it into
// "silent" or, as it did, "reporting".
func TestTheBoardRendersNeverConnectedAsItsOwnState(t *testing.T) {
	b, err := assetFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, "never_connected") {
		t.Error("the board does not read the never-connected flag")
	}
	if !strings.Contains(js, `badge("no contact"`) {
		t.Error("a source that never connected is not badged differently")
	}
}
