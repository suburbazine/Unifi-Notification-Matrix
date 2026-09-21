package network

import (
	"context"
	"strings"
	"testing"
	"time"
)

// AN OFFLINE INCIDENT USED TO QUOTE A CONSTANT AS IF IT WERE A MEASUREMENT.
//
// The detail was "the console has reported this device down for " +
// d.downFor.String(), and downFor is the three-minute wait before an outage
// counts at all. So every offline incident this source has ever raised said
// "down for 3m0s" -- on a real site, for access points that had been off for
// weeks, eleven minutes after the daemon was restarted.
//
// Two separate faults wearing one sentence, and they need different fixes:
// the figure was the threshold rather than the elapsed time, AND the elapsed
// time is not the age of the outage for a device that was already down when
// this process started. The Integration API carries no events and, on the
// hardware this has been observed on, no timestamp on a device at all -- no
// lastSeen, no uptime, no disconnectedAt -- so the age of a pre-existing
// outage is genuinely unknown, and the incident has to say so rather than
// quote the only number it happens to have.
func TestAWatchedOutageQuotesHowLongItHasRunNotTheThreshold(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.DownFor = 3 * time.Minute
	})
	c := &collector{}

	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","state":"ONLINE"}`)
	s.poll(context.Background(), c)

	// Down at t0+1m, and nothing polls again until t0+9m -- so it has been
	// down for eight minutes, not for the three the threshold names. A gap
	// like this is ordinary: the daemon is asleep, the console is unreachable,
	// or the poll interval is long.
	f.devicesBody = devicesPage(`{"id":"d1","name":"Core Switch","state":"OFFLINE"}`)
	now = t0.Add(time.Minute)
	s.poll(context.Background(), c)
	now = t0.Add(9 * time.Minute)
	s.poll(context.Background(), c)

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1: %+v", len(got), got)
	}
	detail := got[0].Detail
	if !strings.Contains(detail, "8m0s") {
		t.Errorf("detail = %q; it does not say how long the device has actually "+
			"been down (8m0s)", detail)
	}
	if strings.Contains(detail, "3m0s") {
		t.Errorf("detail = %q; that is the threshold, which is a constant. Every "+
			"outage this source raises would report the same figure, whatever its "+
			"real length.", detail)
	}
}

// AND AN OUTAGE THAT WAS ALREADY RUNNING HAS NO KNOWABLE START.
//
// This is the case from the field. The daemon restarts -- an upgrade, a
// reboot, a service recovery -- polls, and finds devices that have been off
// for weeks. It has no evidence of when they went down, and its own clock
// starts at the restart, so every figure it can compute is a figure about
// itself. Saying "down for 3m0s" there is worse than saying nothing: the
// operator reads it as a new outage and goes looking for what just broke.
func TestAnOutageThatWasAlreadyRunningSaysItsAgeIsUnknown(t *testing.T) {
	f := newFakeConsole(t)
	now := t0
	s := newTestSource(t, f, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.DownFor = 3 * time.Minute
	})
	c := &collector{}

	// The first thing this process ever learns about the device is that it is
	// down. It has been down for three weeks; nothing on the wire says so.
	f.devicesBody = devicesPage(`{"id":"d1","name":"Dean U7 Outdoor","state":"OFFLINE"}`)
	s.poll(context.Background(), c)
	now = t0.Add(4 * time.Minute)
	s.poll(context.Background(), c)

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1: %+v", len(got), got)
	}
	detail := got[0].Detail
	if !strings.Contains(detail, "already down when this started watching") {
		t.Errorf("detail = %q; a device that was already down when this process "+
			"started has an outage of unknown age, and the incident has to say so "+
			"-- otherwise the only time on the card is when WE noticed, and it "+
			"reads as when the device failed.", detail)
	}
	if !strings.Contains(detail, "may be") {
		t.Errorf("detail = %q; it states an elapsed time without saying that the "+
			"real outage may be far older", detail)
	}
}

// The two sentences must not be the same sentence. A fix that made both
// branches say "down for 4m0s" would pass the first test and fail a reader.
func TestTheTwoOutagesDoNotReadTheSame(t *testing.T) {
	watched := &deviceState{everOnline: true, offlineSince: t0}
	cold := &deviceState{everOnline: false, offlineSince: t0}
	at := t0.Add(4 * time.Minute)
	if watched.downDetail(at) == cold.downDetail(at) {
		t.Errorf("an outage this process watched begin and one that was already "+
			"running read identically: %q", watched.downDetail(at))
	}
}
