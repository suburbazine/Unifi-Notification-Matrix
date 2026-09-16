package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func observe(b *Buckets, msgs ...string) {
	for _, m := range msgs {
		b.Observe([]byte(m))
	}
}

// THE REASON THIS PACKAGE BUCKETS AT ALL.
//
// These sockets are dominated by repeated state-sync traffic. A flat capture
// of the first N messages fills with it and never sees the rare class being
// probed for -- which is how an earlier in-house capture concluded that Access
// emits only two message shapes, after hitting a flat 50-message cap on spam.
func TestARareTypeSurvivesAFloodOfCommonOnes(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())

	// One thousand state-sync messages, then the single event that matters.
	for i := 0; i < 1000; i++ {
		b.Observe([]byte(`{"type":"update","item":{"modelKey":"camera","state":"CONNECTED"}}`))
	}
	b.Observe([]byte(`{"type":"add","item":{"type":"sensorSmokeEndOfLife","modelKey":"sensor"}}`))

	var found *Bucket
	for _, k := range b.Types() {
		if strings.Contains(k, "sensorSmokeEndOfLife") {
			found = b.Bucket(k)
		}
	}
	if found == nil {
		t.Fatalf("the one-in-a-thousand type was lost among %v", b.Types())
	}
	if len(found.Samples) != 1 {
		t.Errorf("rare type kept %d samples, want 1", len(found.Samples))
	}

	// And the flood is counted in full, not merely sampled: a type seen 1000
	// times and a type seen once must stay distinguishable.
	var flood *Bucket
	for _, k := range b.Types() {
		if strings.Contains(k, "state") || strings.Contains(k, "update") {
			flood = b.Bucket(k)
		}
	}
	if flood == nil || flood.Count != 1000 {
		t.Errorf("the common type counted %v, want 1000", flood)
	}
	if flood != nil && len(flood.Samples) > samplesPerType {
		t.Errorf("kept %d samples of the common type; the cap is %d", len(flood.Samples), samplesPerType)
	}
	if b.Total() != 1001 {
		t.Errorf("total = %d, want 1001 -- every message must be counted", b.Total())
	}
}

// A COMPOSITE KEY, and this is why. Protect puts a frame verb at the top level
// and the event type underneath; bucketing on the top level alone collapses
// every event into two buckets and reproduces exactly the crowding-out that
// bucketing exists to prevent.
func TestProtectEventTypesDoNotCollapseIntoTheFrameVerb(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	observe(b,
		`{"type":"add","item":{"type":"smartDetectZone"}}`,
		`{"type":"add","item":{"type":"sensorWaterLeak"}}`,
		`{"type":"add","item":{"type":"alarmHubSmoke"}}`,
	)
	if got := len(b.Types()); got != 3 {
		t.Fatalf("three distinct event types produced %d bucket(s): %v\n"+
			"bucketing on the frame verb alone hides the vocabulary", got, b.Types())
	}
	for _, want := range []string{"smartDetectZone", "sensorWaterLeak", "alarmHubSmoke"} {
		if !strings.Contains(strings.Join(b.Types(), " "), want) {
			t.Errorf("%s is missing from %v", want, b.Types())
		}
	}
}

// Access puts its type in a top-level `event`, and one rule has to cover both
// products without either one's parser.
func TestAccessMessagesBucketOnTheirOwnField(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	observe(b,
		`{"event":"access.data.v2.device.update","data":{"unique_id":"aabbccddeeff"}}`,
		`{"event":"access.data.v2.location.update","data":{}}`,
		`{"event":"access.data.v2.device.update","data":{}}`,
	)
	if got := len(b.Types()); got != 2 {
		t.Fatalf("got %d buckets, want 2: %v", got, b.Types())
	}
}

// Bucketing on a device id would produce one bucket per device, which is the
// same failure as one bucket for everything, reached from the other side.
func TestAnIdentifierIsNeverUsedAsAType(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	observe(b,
		`{"type":"68cdb33400578403e401e390"}`,
		`{"type":"78cdb33400578403e401e391"}`,
		`{"type":"88cdb33400578403e401e392"}`,
	)
	if got := len(b.Types()); got != 1 {
		t.Errorf("three messages from three devices made %d buckets: %v\n"+
			"an id was mistaken for a type", got, b.Types())
	}
}

// What cannot be parsed cannot be redacted, so it is counted and discarded.
func TestUnparseableFramesAreCountedButNotKept(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	b.Observe([]byte("\x00\x01binary frame with Nursery in it"))
	if b.Unreadable() != 1 {
		t.Errorf("unreadable = %d, want 1", b.Unreadable())
	}
	blob, err := json.Marshal(b.All())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "Nursery") {
		t.Errorf("an unparseable frame's content was retained: %s", blob)
	}
}

// A console that puts something unique in a discriminator must not be able to
// exhaust memory during an unattended capture.
func TestTheTypeCapIsEnforcedAndReported(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	for i := 0; i < maxBucketTypes+50; i++ {
		b.Observe([]byte(fmt.Sprintf(`{"event":"type-%d"}`, i)))
	}
	if got := len(b.Types()); got != maxBucketTypes {
		t.Errorf("tracked %d types, cap is %d", got, maxBucketTypes)
	}
	if b.Dropped() != 50 {
		t.Errorf("dropped = %d, want 50 -- a silent drop is the failure", b.Dropped())
	}
}

// Redaction happens at capture time. There must be no window in which a raw
// frame is retained anywhere in this package.
func TestCapturedSamplesAreAlreadyRedacted(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	b.Observe([]byte(protectFrame))

	blob, err := json.Marshal(b.All())
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"Nursery", "A8:9C:6C:B2:27:FA", "jane.doe@example.com", "9wYQ8vTkK2mNpLxR"} {
		if strings.Contains(string(blob), canary) {
			t.Errorf("%q was retained in the capture: %s", canary, blob)
		}
	}
	if !strings.Contains(string(blob), "smartDetectZone") {
		t.Errorf("the event type was lost from the capture: %s", blob)
	}
}

// The schema summary covers every message, not only the sampled ones -- that
// is what makes it, rather than the samples, the payload of a report.
func TestTheSummaryCoversMessagesNoSampleWasKeptFor(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	for i := 0; i < 10; i++ {
		b.Observe([]byte(`{"event":"e","state":"CONNECTED"}`))
	}
	// The eleventh carries a field the first ten did not.
	b.Observe([]byte(`{"event":"e","state":"DISCONNECTED","lastSeen":1758000000000}`))

	bkt := b.Bucket("event=e")
	if bkt == nil {
		t.Fatalf("no bucket in %v", b.Types())
	}
	if len(bkt.Samples) != samplesPerType {
		t.Fatalf("samples = %d, want %d", len(bkt.Samples), samplesPerType)
	}
	if _, ok := bkt.Fields.Fields["lastSeen"]; !ok {
		t.Error("a field that appeared only after the sample cap was reached is " +
			"missing from the summary; the samples would then be the only record")
	}
	st := bkt.Fields.Fields["state"]
	if st == nil || st.Distinct != 2 {
		t.Errorf("state distinct = %v, want 2", st)
	}
	if !containsString(st.Values, "CONNECTED") || !containsString(st.Values, "DISCONNECTED") {
		t.Errorf("state values = %v, want both enum terms", st.Values)
	}
}

// A field that is a string on one firmware and an array on another is the trap
// that silently drops messages, so the summary has to surface it.
func TestAFieldWithTwoTypesIsReported(t *testing.T) {
	b := NewBuckets(NewPseudonymiser())
	observe(b,
		`{"event":"e","id":"abc"}`,
		`{"event":"e","id":["abc","def"]}`,
	)
	f := b.Bucket("event=e").Fields.Fields["id"]
	if f == nil || len(f.Types) != 2 {
		t.Fatalf("id types = %v, want two; this is the bulk-envelope trap", f)
	}
}

// THE GUARD, on the socket path. gorilla's Dialer has its own default net.Dial,
// so a deleted NetDialContext still compiles and still connects -- it just
// stops being restricted, silently.
func TestTheCaptureDialerRefusesARemoteAddress(t *testing.T) {
	d := captureDialer()
	if d.NetDialContext == nil {
		t.Fatal("the websocket dialer has no NetDialContext; the local-network " +
			"guard covers only the HTTP half of the probe")
	}
	_, err := d.NetDialContext(context.Background(), "tcp", "8.8.8.8:443")
	if !errors.Is(err, ErrNotLocal) {
		t.Errorf("dialling a public address gave %v, want ErrNotLocal", err)
	}
	if d.Proxy != nil {
		t.Error("the websocket dialer consults a proxy; a proxy receives the " +
			"API key and reaches hosts the guard never sees")
	}
}

// Every catalogue entry must satisfy the probe's own rules. The entry that
// breaks them will be added by somebody in a hurry, to a table that looks like
// a list of harmless strings.
func TestEveryCatalogueEntryIsAllowed(t *testing.T) {
	for _, e := range Catalogue {
		if why := Refuse(http.MethodGet, "https://10.0.0.1"+e.Path); why != "" {
			t.Errorf("catalogue entry %s is refused by this package's own rules: %s", e.Path, why)
		}
		if !strings.HasPrefix(e.Path, "/") {
			t.Errorf("catalogue entry %q is not a path", e.Path)
		}
		switch e.Product {
		case "protect", "access", "network", "unifi-os":
		default:
			t.Errorf("catalogue entry %s has product %q, which no report groups by", e.Path, e.Product)
		}
	}
}

func TestStateChangingMethodsAreRefused(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "post"} {
		if why := Refuse(m, "https://10.0.0.1/proxy/protect/integration/v1/cameras"); why == "" {
			t.Errorf("%s was allowed; a probe that can change a console is not a probe", m)
		}
	}
	if why := Refuse("GET", "https://10.0.0.1/proxy/protect/integration/v1/cameras"); why != "" {
		t.Errorf("an ordinary GET was refused: %s", why)
	}
}

// The inherited refusal, made structural. An earlier probe refused this in
// prose and by simply not writing the call, which is one careless edit away
// from being wrong.
func TestTheIrreversibleEndpointIsRefused(t *testing.T) {
	why := Refuse("GET", "https://10.0.0.1/proxy/protect/integration/v1/cameras/abc/disable-mic-permanently")
	if why == "" {
		t.Fatal("disable-mic-permanently was allowed; it needs a factory reset to undo")
	}
	if !strings.Contains(why, "factory reset") {
		t.Errorf("the refusal does not say why: %q", why)
	}
}

// Rosters buy the schema nothing once pseudonymised, and pulling the
// credential table into a process that writes files is a bad shape even when
// the writing is safe.
func TestPeopleEndpointsAreRefused(t *testing.T) {
	for _, p := range []string{
		"/proxy/access/integration/v1/developer/users",
		"/proxy/access/integration/v1/developer/credentials",
		"/proxy/access/integration/v1/developer/visitors",
		"/proxy/network/integration/v1/sites/default/clients",
	} {
		if why := Refuse("GET", "https://10.0.0.1"+p); why == "" {
			t.Errorf("%s was allowed; it is a list of people", p)
		}
	}
}

// The redaction has to cover what this process says ABOUT the console, not
// only what the console says. Found by running the probe against a dead local
// port: a refused connection produced "dial tcp 192.168.1.1:443: ..." and that
// string was being written into the report as the stream status.
func TestErrorStringsCarryNoAddress(t *testing.T) {
	cases := map[string]string{
		"dial tcp 192.168.1.1:443: connectex: refused":     "192.168.1.1",
		"dial tcp [fd00::1]:443: i/o timeout":              "fd00::1",
		"dial tcp: lookup unifi.example.com: no such host": "unifi.example.com",
		"read tcp 10.0.0.5:51234->10.0.0.1:443: reset":     "10.0.0.1",
	}
	for in, leak := range cases {
		got := scrubAddresses(in)
		if strings.Contains(got, leak) {
			t.Errorf("scrubAddresses(%q) = %q, which still names %q", in, got, leak)
		}
		if got == "" {
			t.Errorf("scrubAddresses(%q) removed everything; the operator needs "+
				"to know WHAT failed, only not where", in)
		}
	}

	// The useful part of the message has to survive.
	if got := scrubAddresses("dial tcp 192.168.1.1:443: connectex: refused"); !strings.Contains(got, "refused") {
		t.Errorf("the reason was lost: %q", got)
	}
}
