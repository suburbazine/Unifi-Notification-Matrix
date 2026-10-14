package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The wall display says partner events are being refused, without a sign-in.
func TestTheStatusSaysPartnerEventsAreRefused(t *testing.T) {
	h := newHarness(t)
	h.srv.deps.CommercialRejecting = func() bool { return true }
	_, raw := h.do("GET", "/api/status", nil)
	var st struct {
		On bool `json:"commercial_rejecting"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if !st.On {
		t.Error("the public status does not say partner events are being refused")
	}
}

// Every tab, Peer link first, each partner's word, and the receipt.
func TestTheRefusalIsShownEverywhereItMatters(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)
	if !strings.Contains(fnBody(src, "function refreshStatus("), "renderCommercialBanner(d.commercial_rejecting)") {
		t.Error("the status poll does not draw the refusal banner")
	}
	if !strings.Contains(fnBody(src, "function renderLinkSection("),
		`if (st.commercial_rejecting) {`) {
		t.Error("the Peer link section does not lead with the refusal")
	}
	if !strings.Contains(src, `badge("commercial use: " + (p.commercial || "not heard yet")`) {
		t.Error("a paired product no longer shows what it said about commercial use")
	}
	if !strings.Contains(src, `"no-commercial-permission":`) {
		t.Error("the receipt for the refusal has no words")
	}
}
