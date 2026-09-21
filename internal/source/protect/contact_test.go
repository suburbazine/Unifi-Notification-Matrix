package protect

import (
	"context"
	"errors"
	"testing"
)

// A UDM with no Protect installed answers /proxy/protect/... with the UniFi OS
// web page, so every read fails. The board said "in contact; nothing to report
// yet", and the source badge said REPORTING, on a console where this product
// could not possibly see anything ever.
//
// "We tried" is not "we reached". LastContact is what the interface turns into
// a green badge, so a sweep that read nothing at all must not move it.
func TestASweepThatReachedNothingIsNotContact(t *testing.T) {
	src, err := New(Config{Host: "10.0.0.1", APIKey: "k", SweepDebounce: -1})
	if err != nil {
		t.Fatal(err)
	}
	states := &fakeStates{}
	states.set(nil, errors.New("response was not JSON"))
	src.cfg.States = states

	if err := src.Reconcile(context.Background(), newCollector()); err == nil {
		t.Fatal("a sweep against a console with no Protect returned no error")
	}
	if got := src.LastContact(); !got.IsZero() {
		t.Errorf("LastContact = %v after a sweep that read nothing; the "+
			"interface renders that as being in touch with the console", got)
	}
	if src.Health().LastSweepErr == "" {
		t.Error("the failure was not recorded anywhere")
	}
}

// And the reason the fix is not simply "never stamp on error": a partial read
// IS contact. Some devices came back, so the console answered.
func TestAPartialSweepIsStillContact(t *testing.T) {
	src, err := New(Config{Host: "10.0.0.1", APIKey: "k", SweepDebounce: -1})
	if err != nil {
		t.Fatal(err)
	}
	states := &fakeStates{}
	states.set([]DeviceState{{ID: "cam-1", Kind: "camera", State: stateDisconnected}},
		errors.New("sensors read failed"))
	src.cfg.States = states

	_ = src.Reconcile(context.Background(), newCollector())
	if src.LastContact().IsZero() {
		t.Error("a sweep that read some devices was not counted as contact")
	}
}

// What the interface needs in order to say something true about a source that
// has never once succeeded.
func TestTheSourceCanSayWhyItLastFailed(t *testing.T) {
	src, err := New(Config{Host: "10.0.0.1", APIKey: "k", SweepDebounce: -1})
	if err != nil {
		t.Fatal(err)
	}
	states := &fakeStates{}
	states.set(nil, errors.New("response was not JSON"))
	src.cfg.States = states
	_ = src.Reconcile(context.Background(), newCollector())

	if got := src.LastError(); got == "" {
		t.Error("a source that cannot read anything reports no reason")
	}
}
