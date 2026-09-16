package escalate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

func at(hh, mm int) time.Time {
	return time.Date(2026, 9, 15, hh, mm, 0, 0, time.UTC)
}

func TestQuietHoursWindow(t *testing.T) {
	utc := QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: "UTC"}
	day := QuietHours{Enabled: true, Start: "09:00", End: "17:00", Zone: "UTC"}

	for _, tc := range []struct {
		name string
		q    QuietHours
		t    time.Time
		want bool
	}{
		// The wrapping window is the one that is easy to get wrong.
		{"wrap: just before start", utc, at(21, 59), false},
		{"wrap: at start is inside", utc, at(22, 0), true},
		{"wrap: late evening", utc, at(23, 30), true},
		{"wrap: across midnight", utc, at(0, 30), true},
		{"wrap: small hours", utc, at(3, 0), true},
		{"wrap: just before end", utc, at(6, 59), true},
		{"wrap: at end is outside", utc, at(7, 0), false},
		{"wrap: midday", utc, at(12, 0), false},

		{"same-day: before", day, at(8, 59), false},
		{"same-day: at start", day, at(9, 0), true},
		{"same-day: inside", day, at(13, 0), true},
		{"same-day: at end is outside", day, at(17, 0), false},
		{"same-day: after", day, at(18, 0), false},

		{"disabled is never quiet", QuietHours{Start: "00:00", End: "23:59"}, at(3, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.q.Contains(tc.t); got != tc.want {
				t.Errorf("Contains(%s) = %v, want %v", tc.t.Format("15:04"), got, tc.want)
			}
		})
	}
}

// The daemon often runs on a UTC server watching a site that is not on UTC.
// Quiet hours derived from the wrong zone are silent at the wrong times, and
// nobody notices until an alert they wanted did not arrive.
func TestQuietHoursUsesTheConfiguredZoneNotTheHostZone(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	q := QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: "Asia/Tokyo"}

	// 14:00 UTC is 23:00 in Tokyo -- quiet there, mid-afternoon here.
	utcAfternoon := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)
	if !q.Contains(utcAfternoon) {
		t.Errorf("14:00 UTC is %s in Tokyo and should be quiet",
			utcAfternoon.In(tokyo).Format("15:04"))
	}
	// 00:00 UTC is 09:00 in Tokyo -- not quiet there, small hours here.
	utcMidnight := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	if q.Contains(utcMidnight) {
		t.Errorf("00:00 UTC is %s in Tokyo and should NOT be quiet",
			utcMidnight.In(tokyo).Format("15:04"))
	}
}

func TestQuietHoursValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		q    QuietHours
		want error
	}{
		{"ok", QuietHours{Enabled: true, Start: "22:00", End: "07:00"}, nil},
		{"disabled is not checked", QuietHours{Start: "nonsense"}, nil},
		{"bad start", QuietHours{Enabled: true, Start: "25:00", End: "07:00"}, ErrBadQuietTime},
		{"bad end", QuietHours{Enabled: true, Start: "22:00", End: "7pm"}, ErrBadQuietTime},
		{"unknown zone", QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: "Mars/Olympus"}, ErrBadQuietZone},
		// Ambiguous between "no window" and "all day", which are opposites.
		{"empty window", QuietHours{Enabled: true, Start: "22:00", End: "22:00"}, ErrEmptyWindow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.q.Validate()
			if tc.want == nil && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
}

// A held alert is DEFERRED, never cancelled: it fires on the first tick after
// the window ends.
func TestQuietHoursHoldsThenReleases(t *testing.T) {
	st := newFakeStore()
	// Low severity respects quiet hours by default.
	inc := incident.Open("i1", "network/ap-3/offline", incident.SeverityLow,
		"network", "AP offline", "", at(23, 0))
	if err := st.Put(t.Context(), inc); err != nil {
		t.Fatal(err)
	}

	clk := at(23, 0)
	var delivered int
	s, err := NewScheduler(st, DefaultPolicies(),
		func(context.Context, *incident.Incident, int, []string) error {
			delivered++
			return nil
		},
		WithClock(func() time.Time { return clk }),
		WithQuietHours(QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: "UTC"}))
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if delivered != 0 {
		t.Fatalf("delivered %d alerts inside quiet hours, want 0", delivered)
	}
	if got := s.Stats().Held; got != 1 {
		t.Errorf("Stats().Held = %d, want 1 -- a held alert must be visible, "+
			"because \"it was quiet hours\" is the answer to \"why was I not paged\"", got)
	}
	// Held, not failed: nothing broke.
	if got := s.Stats().Failed; got != 0 {
		t.Errorf("Stats().Failed = %d, want 0; a hold is not a failure", got)
	}
	held := st.must(t, "i1")
	if held.LastAlertAt != nil {
		t.Error("a held alert must not record as delivered")
	}
	if held.LastDeliveryError != "" {
		t.Errorf("a hold recorded a delivery error: %q", held.LastDeliveryError)
	}

	// Window ends the NEXT morning -- the incident opened at 23:00, so 07:01
	// on the same date would be before it existed.
	clk = at(7, 1).AddDate(0, 0, 1)
	if err := s.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("delivered %d after quiet hours ended, want 1 -- a held alert "+
			"is deferred, never cancelled", delivered)
	}
}

// Critical must be unreachable by this feature, at every layer.
func TestQuietHoursCannotSilenceCritical(t *testing.T) {
	t.Run("the config cannot express it", func(t *testing.T) {
		p := DefaultPolicies()[incident.SeverityCritical]
		p.RespectQuietHours = true
		if err := p.Validate(incident.SeverityCritical); !errors.Is(err, ErrCriticalQuietHours) {
			t.Fatalf("Validate = %v, want ErrCriticalQuietHours", err)
		}
	})

	t.Run("a critical alert fires at 3am inside the window", func(t *testing.T) {
		st := newFakeStore()
		inc := incident.Open("i1", "access/front-door/forced-open",
			incident.SeverityCritical, "access", "Door forced open", "", at(3, 0))
		if err := st.Put(t.Context(), inc); err != nil {
			t.Fatal(err)
		}
		clk := at(3, 0)
		var delivered int
		s, err := NewScheduler(st, DefaultPolicies(),
			func(context.Context, *incident.Incident, int, []string) error {
				delivered++
				return nil
			},
			WithClock(func() time.Time { return clk }),
			WithQuietHours(QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: "UTC"}))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		if delivered != 1 {
			t.Fatalf("a forced door at 3am delivered %d times inside quiet "+
				"hours, want 1", delivered)
		}
	})
}

func TestSchedulerRefusesAMalformedQuietWindow(t *testing.T) {
	st := newFakeStore()
	_, err := NewScheduler(st, DefaultPolicies(),
		func(context.Context, *incident.Incident, int, []string) error { return nil },
		WithQuietHours(QuietHours{Enabled: true, Start: "22:00", End: "not a time"}))
	if !errors.Is(err, ErrBadQuietTime) {
		t.Fatalf("NewScheduler = %v, want ErrBadQuietTime -- a typo must refuse "+
			"at startup, not go silent at times nobody chose", err)
	}
}

func TestValidateAgainstChannels(t *testing.T) {
	t.Run("defaults name only implemented channels", func(t *testing.T) {
		if err := ValidateAgainstChannels(DefaultPolicies(), ImplementedChannels()); err != nil {
			t.Fatalf("the shipped defaults do not validate: %v", err)
		}
	})

	t.Run("a stage naming a missing channel is refused", func(t *testing.T) {
		p := DefaultPolicies()
		crit := p[incident.SeverityCritical]
		crit.Stages = append(crit.Stages, Stage{
			After: time.Hour, Channels: []string{"voice"},
		})
		p[incident.SeverityCritical] = crit

		err := ValidateAgainstChannels(p, ImplementedChannels())
		if !errors.Is(err, ErrUnknownChannel) {
			t.Fatalf("ValidateAgainstChannels = %v, want ErrUnknownChannel", err)
		}
		// The message has to say which severity, which stage and which
		// channel, or the operator cannot fix it.
		for _, want := range []string{"critical", "voice"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error message does not mention %q: %v", want, err)
			}
		}
	})

	t.Run("channel names are matched case-insensitively", func(t *testing.T) {
		p := map[incident.Severity]Policy{
			incident.SeverityHigh: {Name: "high", Stages: []Stage{
				{After: 0, Channels: []string{"NTFY"}}}},
		}
		if err := ValidateAgainstChannels(p, []string{"ntfy"}); err != nil {
			t.Errorf("case mismatch rejected: %v", err)
		}
	})

	t.Run("reports every problem, not just the first", func(t *testing.T) {
		p := map[incident.Severity]Policy{
			incident.SeverityHigh: {Name: "high", Stages: []Stage{
				{After: 0, Channels: []string{"voice", "pushover"}}}},
		}
		err := ValidateAgainstChannels(p, []string{"ntfy"})
		for _, want := range []string{"voice", "pushover"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not mention %q: %v", want, err)
			}
		}
	})
}

func TestChannelsUsed(t *testing.T) {
	got := ChannelsUsed(DefaultPolicies())
	want := []string{"email", "ntfy"}
	if len(got) != len(want) {
		t.Fatalf("ChannelsUsed() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ChannelsUsed() = %v, want %v", got, want)
		}
	}
}
