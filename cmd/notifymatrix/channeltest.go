package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// A channel test that exercises acknowledgement.
//
// The test button used to send each channel's own hand-written message --
// built by different code from a real alert, and carrying no acknowledgement
// at all. So it proved the message arrived and nothing about the one action
// that matters when it does, and ntfy's Acknowledge button acknowledged
// nothing for months while every test passed.
//
// Now, for a channel a person acknowledges from, the test is a REAL alert about
// a REAL incident, built by the same code as every alert, with the same button
// or link on it. Pressing it acknowledges that incident, and the settings page,
// which is watching it, says so.

// testKey is the dedup key of a channel's test incident: one per channel, so
// a second press supersedes the first rather than accumulating.
func testKey(channel string) string {
	return incident.Key("internal", "channel-test-"+channel, "channel-test")
}

// openChannelTest makes the incident a test alert is about.
//
// RESOLVED FROM THE START, which is what keeps it out of the escalation
// ladder: the scheduler never alerts on a resolved incident, so the test is
// delivered exactly once -- by this -- however long nobody presses the button.
// Acknowledging it then closes it, as acknowledging any resolved incident
// does. An earlier test of the same channel still waiting is closed first,
// both because only one may be live per key and because it is not the one the
// operator is now looking at.
func openChannelTest(ctx context.Context, st incident.Store, channel string,
	now time.Time) (*incident.Incident, error) {
	key := testKey(channel)
	if prev, err := st.OpenByDedupKey(ctx, key); err == nil {
		prev.Close(now, "superseded by a newer test of "+channel)
		if err := st.Put(ctx, prev); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, incident.ErrNotFound) {
		return nil, err
	}

	id, err := testID()
	if err != nil {
		return nil, err
	}
	inc := incident.Open(id, key, incident.SeverityInfo, "internal",
		"Channel test: "+channel,
		"A test from the settings page. Nothing is wrong. Acknowledge this to "+
			"prove acknowledgement works from "+channel+".", now)
	if err := inc.Resolve(now); err != nil {
		return nil, err
	}
	if err := st.Put(ctx, inc); err != nil {
		return nil, err
	}
	return inc, nil
}

func testID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a test incident id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// testWithAck sends a real alert about a fresh test incident through one
// channel, and reports what the page needs to watch for its acknowledgement.
func testWithAck(ctx context.Context, st incident.Store, d *config.Delivery,
	channel string, now time.Time) (web.ChannelTest, error) {
	inc, err := openChannelTest(ctx, st, channel, now)
	if err != nil {
		return web.ChannelTest{}, err
	}
	if err := d.SendTest(ctx, channel, inc); err != nil {
		// Not left waiting for an acknowledgement that cannot come.
		inc.Close(now, "the test alert could not be sent")
		_ = st.Put(ctx, inc)
		return web.ChannelTest{}, err
	}
	res := web.ChannelTest{IncidentID: inc.ID, AckLink: d.AckURL(inc, channel) != ""}
	if !res.AckLink {
		res.AckReason = "The alert carries no acknowledgement, because web.ack_base_url " +
			"is not set -- so no alert from this channel can be acknowledged from the " +
			"device. Set it under Web, then test again."
		// Nothing on it can ever acknowledge it, so it is not left on the
		// board waiting.
		inc.Close(now, "the test alert carried no acknowledgement")
		_ = st.Put(ctx, inc)
	}
	return res, nil
}

// testAckWindow is how long a test waits to be acknowledged before it is
// closed. The page watching it gives up at the same point.
const testAckWindow = 15 * time.Minute

// expireChannelTest closes a test nobody acknowledged, so it does not sit on
// the wall board for ever as a resolved incident still wanting attention.
//
// Compare-and-swap, because the moment this runs is exactly when somebody may
// be pressing the button: an acknowledgement that lands first wins, and one
// that lands after finds the test closed.
func expireChannelTest(ctx context.Context, st incident.Store, id string, now time.Time) error {
	return closeWaitingTest(ctx, st, id, now,
		"nobody acknowledged the test within fifteen minutes")
}

// closeWaitingTest closes a test still waiting for its acknowledgement, and
// leaves one that has had it alone.
func closeWaitingTest(ctx context.Context, st incident.Store, id string, now time.Time,
	reason string) error {
	inc, err := st.Get(ctx, id)
	if err != nil {
		return err
	}
	// A test is resolved from the start, so an acknowledged one is already
	// closed by derivation: Terminal covers both.
	if inc.Terminal() {
		return nil
	}
	expect := inc.UpdatedAt
	inc.Close(now, reason)
	return st.PutIfUnchanged(ctx, inc, expect)
}

// closeLeftoverChannelTests closes tests a restart interrupted: the timer that
// would have expired them did not survive it. Said as that, not as the
// fifteen minutes it may well not have been.
func closeLeftoverChannelTests(ctx context.Context, st incident.Store, now time.Time) error {
	active, err := st.Active(ctx)
	if err != nil {
		return err
	}
	for _, inc := range active {
		if inc.Source != "internal" || inc.Condition() != "channel-test" {
			continue
		}
		if err := closeWaitingTest(ctx, st, inc.ID, now,
			"a restart interrupted the test before it was acknowledged"); err != nil &&
			!errors.Is(err, incident.ErrConflict) {
			return err
		}
	}
	return nil
}
