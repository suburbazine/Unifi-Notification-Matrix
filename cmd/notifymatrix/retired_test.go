package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

func sentryPeer(id string) link.Peer {
	return link.Peer{Slug: "sentry", LinkID: id, Manifest: link.Manifest{
		Capability: "access",
		Conditions: []link.ConditionSpec{{Name: "sentry-access-denied",
			Meaning: "a door refused somebody", Severity: incident.SeverityHigh, Momentary: true}},
	}}
}

// THE SEQUENCE FROM THE FIELD: Sentry pairs, re-pairs, and part of it keeps
// the first credential. The receiver must be able to say whose it was.
func TestAReplacedCredentialIsRetiredByName(t *testing.T) {
	cfg := &config.Config{}
	d := linkDeps{
		cfg:      func() *config.Config { return cfg },
		saveCfg:  func(c *config.Config) error { cfg = c; return nil },
		state:    newLinkState(nil),
		auditLog: &capturingLog{},
	}
	if err := d.storePeer(sentryPeer("lnk_FIRST"), make([]byte, link.KeyBytes)); err != nil {
		t.Fatal(err)
	}
	if _, retired := cfg.Retired("lnk_FIRST"); retired {
		t.Fatal("a first pairing retired its own credential")
	}
	if err := d.storePeer(sentryPeer("lnk_SECOND"), make([]byte, link.KeyBytes)); err != nil {
		t.Fatal(err)
	}

	old, ok := d.build().Retired("lnk_FIRST")
	if !ok {
		t.Fatal("the credential a re-pair replaced is not known as retired, so a product " +
			"still using it is reported as a stranger")
	}
	if old.Slug != "sentry" || old.Why != "re-paired" {
		t.Errorf("retired as %+v, want sentry / re-paired", old)
	}
	if _, stillRetired := d.build().Retired("lnk_SECOND"); stillRetired {
		t.Error("the CURRENT credential is listed as retired")
	}
}

// And an unpair: the product may never have been told.
func TestAnUnpairedCredentialIsRetiredByName(t *testing.T) {
	cur := &config.Config{Links: []config.Link{{Slug: "lsprotect", LinkID: "lnk_P"}}}
	next, _, found := forgetPeer(cur, "lsprotect")
	if !found {
		t.Fatal("setup: the peer was not found")
	}
	r, ok := next.Retired("lnk_P")
	if !ok || r.Slug != "lsprotect" || r.Why != "unpaired" {
		t.Errorf("after unpairing, retired = %+v (found %v), want lsprotect / unpaired", r, ok)
	}
	if len(cur.RetiredLinks) != 0 {
		t.Error("unpairing wrote into the configuration the daemon is still using")
	}
}

// Bounded, and a new list every time rather than an append into a slice the
// running configuration may share.
func TestTheRetiredListIsBoundedAndNeverShared(t *testing.T) {
	c := &config.Config{}
	at := time.Date(2026, 9, 30, 7, 0, 0, 0, time.UTC)
	for i := 0; i < config.MaxRetiredLinks+5; i++ {
		c.RetireLink(fmt.Sprintf("lnk_%02d", i), "sentry", at, "re-paired")
	}
	if len(c.RetiredLinks) != config.MaxRetiredLinks {
		t.Fatalf("kept %d retired ids, want %d", len(c.RetiredLinks), config.MaxRetiredLinks)
	}
	if _, ok := c.Retired("lnk_00"); ok {
		t.Error("the oldest was kept and the list is not bounded from the right end")
	}
	if _, ok := c.Retired(fmt.Sprintf("lnk_%02d", config.MaxRetiredLinks+4)); !ok {
		t.Error("the newest was dropped")
	}

	// Retiring, on a COPY, an id the list already holds moves entries -- the
	// case where writing into a shared backing array reorders the original
	// under whoever is still using it.
	running := config.Config{}
	for _, id := range []string{"lnk_A", "lnk_B", "lnk_C"} {
		running.RetireLink(id, "sentry", at, "re-paired")
	}
	before := fmt.Sprint(running.RetiredLinks)
	copyOf := running
	copyOf.RetireLink("lnk_A", "sentry", at.Add(time.Hour), "unpaired")
	if after := fmt.Sprint(running.RetiredLinks); after != before {
		t.Errorf("retiring on a copy rewrote the original's list: before %s, after %s", before, after)
	}
}
