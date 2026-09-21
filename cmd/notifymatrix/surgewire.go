package main

import (
	"context"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/surge"
)

// Wiring the activity measurement to the events it measures.
//
// COUNTED AT THE INGEST BOUNDARY, before rules run. A site whose motion is
// silenced by a rule is still a site with motion in it, and the silenced
// events are exactly what a jammer removes -- counting after the rule engine
// would make the busiest camera on site invisible to the one measurement that
// cares how busy it is.

// siteActivity counts events and answers how busy the site is.
type siteActivity struct {
	rec  *surge.Recorder
	rep  *surge.Reporter
	flag func(start time.Time, v surge.Verdict) error
}

func newSiteActivity(rec *surge.Recorder, rep *surge.Reporter,
	flag func(time.Time, surge.Verdict) error) *siteActivity {
	return &siteActivity{rec: rec, rep: rep, flag: flag}
}

// observe counts one event, or declines to.
//
// TWO EXCLUSIONS, each because counting them would measure something other
// than the site:
//
// This product talking about itself -- a source deadman, an unclean shutdown,
// an update available -- is not site activity. Left in, a daemon restarting
// during an outage would look like the site getting busier.
//
// And a CLEAR is the end of something already counted. "Motion stopped" is not
// a second thing happening, and counting both ends doubles every transient
// while leaving a genuine drop-off burst -- which produces offline events and
// no clears at all -- looking comparatively smaller.
func (a *siteActivity) observe(ev event.Event) {
	if a == nil {
		return
	}
	if ev.Clears || strings.EqualFold(ev.Source, "internal") {
		return
	}
	at := ev.At
	if at.IsZero() {
		at = ev.ReceivedAt
	}
	key := ev.Source + "/" + ev.Entity.ID
	a.rec.Observe(key, at)
	a.rep.Observe(key, at)
}

// note is what an alert asks for.
func (a *siteActivity) note(at time.Time) string {
	if a == nil {
		return ""
	}
	return a.rep.Note(at)
}

// run closes buckets on a timer and judges each as it closes.
//
// The timer exists because a site that goes SILENT stops producing events, and
// a silent stretch is a measurement rather than the absence of one. Judging
// happens here rather than in the recorder so that the verdict is computed
// against the history as it stood -- and so the recorder stays a counter with
// no opinions.
func (a *siteActivity) run(ctx context.Context) {
	if a == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()

	last := a.rec.Open().Start
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.rec.Tick()
			open := a.rec.Open().Start
			if open.Equal(last) || last.IsZero() {
				last = open
				continue
			}
			// The bucket that just closed is the one that was open before
			// this tick. Judged from the store rather than from memory: what
			// was written is what the baseline will see.
			a.judge(last)
			last = open
		}
	}
}

func (a *siteActivity) judge(start time.Time) {
	if a.flag == nil {
		return
	}
	// Read the row back rather than judging from memory: what was written is
	// what the baseline will see, including whether it was marked degraded
	// while it was open.
	got, err := a.rep.BucketsIn(start, start.Add(surge.Width))
	if err != nil || len(got) == 0 {
		return
	}
	if v := a.rep.JudgeClosed(got[0]); v != surge.Ordinary {
		_ = a.flag(start, v)
	}
}
