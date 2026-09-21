package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
)

// A source that can say why it is failing, as the two real ones now can.
type diagnosableSource struct {
	*fakeSource
	err string
}

func (d *diagnosableSource) LastError() string { return d.err }

var _ event.Diagnosable = (*diagnosableSource)(nil)

// The daemon already holds the sentence that explains a dead source. This is
// the wire that carries it to the screen; without it the interface can only
// say "no contact", which sends an operator to investigate something the
// process already knew.
func TestTheSupervisorCarriesWhyASourceIsFailing(t *testing.T) {
	src := &diagnosableSource{
		fakeSource: &fakeSource{name: "protect", liveness: 30 * time.Minute, block: true},
		err:        "response was not JSON",
	}
	r := &recorder{}
	s, _ := New([]event.Source{src}, r.deps(func() time.Time { return t0 }))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	waitFor(t, func() bool { return len(s.Statuses()) == 1 })

	got := s.Statuses()
	if got[0].LastError != "response was not JSON" {
		t.Errorf("LastError = %q, want the source's own reason", got[0].LastError)
	}
	cancel()
	<-done
}
