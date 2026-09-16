package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeConsole answers the way a real one would, including the two cases the
// report exists to distinguish: an endpoint this build does not use that
// answers, and one it depends on that does not.
func newFakeConsole(seen *[]string) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/proxy/protect/integration/v1/meta/info", func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Header.Get("X-API-KEY"))
		writeJSON(w, `{"applicationVersion":"7.3.53"}`)
	})
	mux.HandleFunc("/proxy/protect/integration/v1/cameras", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[
		  {"id":"68cdb33400578403e401e390","name":"Nursery","type":"UVC G6 PTZ",
		   "modelKey":"camera","state":"CONNECTED","mac":"A8:9C:6C:B2:27:FA",
		   "host":"192.168.1.50","featureFlags":{"hasSpeaker":true,"hasMic":true}},
		  {"id":"78cdb33400578403e401e391","name":"Master Bedroom","type":"UVC G5 Bullet",
		   "modelKey":"camera","state":"DISCONNECTED","mac":"A8:9C:6C:B2:27:FB",
		   "host":"192.168.1.51","featureFlags":{"hasSpeaker":false,"hasMic":true}}
		]`)
	})
	// A path this build does not use, present on this firmware: the discovery.
	mux.HandleFunc("/proxy/protect/integration/v1/lights", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"id":"88cdb33400578403e401e392","name":"Driveway Flood","modelKey":"light","isLightOn":false}]`)
	})
	// Everything else, including /sensors -- which this build depends on.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	})

	return httptest.NewTLSServer(mux)
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

// The survey is run ONCE for the whole file and the result shared.
//
// Not premature tidying: the probe paces itself at the console's documented
// rate limit, so a full survey takes seconds of deliberate waiting, and
// repeating it per test spent twenty seconds of every CI run proving the
// pacer works. Every test below only reads the report, so sharing it changes
// nothing about what they assert.
var (
	fixtureOnce   sync.Once
	fixtureReport *Report
	fixtureSeen   []string
	fixtureErr    error
)

func runAgainst(t *testing.T) *Report {
	t.Helper()
	fixtureOnce.Do(func() {
		var seen []string
		srv := newFakeConsole(&seen)
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		fixtureReport, fixtureErr = Run(ctx, Options{
			Host:       strings.TrimPrefix(srv.URL, "https://"),
			ProtectKey: "test-key", Products: []string{"protect"},
			// Short: the fake console does not speak WebSocket, so the capture
			// fails its handshake immediately and the window never opens.
			Listen: time.Second, Version: "test",
		})
		fixtureSeen = seen
	})
	if fixtureErr != nil {
		t.Fatalf("Run: %v", fixtureErr)
	}
	return fixtureReport
}

// THE END-TO-END VERSION OF THE ONE THAT MATTERS. Every unit is tested above;
// this asserts the property survives assembly, which is where it would be lost.
func TestAWholeReportCarriesNothingIdentifying(t *testing.T) {
	r := runAgainst(t)

	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, canary := range []string{
		"Nursery", "Master Bedroom", "Driveway Flood", // rooms
		"A8:9C:6C:B2:27:FA", "A8:9C:6C:B2:27:FB", // hardware
		"192.168.1.50", "192.168.1.51", // topology
		"68cdb33400578403e401e390", "test-key", // identity, credential
	} {
		if strings.Contains(got, canary) {
			t.Errorf("%q reached the report file:\n%s", canary, got)
		}
	}
}

// The credential travels in a header and never in the report. Asserted on both
// sides: the console saw it, the file did not.
func TestTheAPIKeyReachesTheConsoleAndNotTheReport(t *testing.T) {
	r := runAgainst(t)

	if len(fixtureSeen) == 0 || fixtureSeen[0] != "test-key" {
		t.Fatalf("console saw %v, want the key in X-API-KEY with that exact casing", fixtureSeen)
	}
	var buf bytes.Buffer
	_ = r.Write(&buf)
	if strings.Contains(buf.String(), "test-key") {
		t.Error("the API key reached the report")
	}
}

// The payload. A report that cannot say which firmware produced a shape
// describes nothing, so version is the identifying fact kept on purpose.
func TestTheFirmwareVersionIsKept(t *testing.T) {
	r := runAgainst(t)
	if got := r.Meta.Versions["protect"]; got != "7.3.53" {
		t.Errorf("protect version = %q, want 7.3.53 -- without it the report is unusable", got)
	}
}

// The two findings that mean opposite things.
func TestDiscoveriesAndRegressionsAreBothReported(t *testing.T) {
	r := runAgainst(t)

	var gotNew, gotGone bool
	for _, f := range r.Findings {
		if f.Kind == "endpoint.undocumented" && strings.Contains(f.Detail, "/lights") {
			gotNew = true
		}
		if f.Kind == "endpoint.missing" && strings.Contains(f.Detail, "/sensors") {
			gotGone = true
		}
	}
	if !gotNew {
		t.Errorf("an endpoint this build does not use answered and was not reported: %+v", r.Findings)
	}
	if !gotGone {
		t.Errorf("an endpoint this build depends on is absent and was not reported: %+v", r.Findings)
	}
}

// The schema is the deliverable, so it has to actually arrive.
func TestTheSchemaReachesTheReport(t *testing.T) {
	r := runAgainst(t)

	var cameras *EndpointResult
	for i := range r.Endpoints {
		if strings.HasSuffix(r.Endpoints[i].Path, "/cameras") {
			cameras = &r.Endpoints[i]
		}
	}
	if cameras == nil || cameras.Fields == nil {
		t.Fatal("no schema for /cameras")
	}
	for _, want := range []string{"[].name", "[].mac", "[].featureFlags.hasSpeaker", "[].state"} {
		if _, ok := cameras.Fields.Fields[want]; !ok {
			t.Errorf("field %s is missing from the schema: %v", want, keysOf(cameras.Fields))
		}
	}
	// The values that may be published are, and the ones that may not are not.
	if st := cameras.Fields.Fields["[].state"]; st == nil || len(st.Values) != 2 {
		t.Errorf("state values = %v, want both enum terms", st)
	}
	if nm := cameras.Fields.Fields["[].name"]; nm == nil || len(nm.Values) != 0 {
		t.Errorf("camera name values = %v, want none published", nm)
	} else if nm.Distinct != 2 {
		t.Errorf("camera name distinct = %d, want 2 -- cardinality is safe to "+
			"report and is what shows a field is not an enum", nm.Distinct)
	}
}

// A capture that could not connect is a finding about the console, not a
// failure of the run. This fake console speaks no WebSocket at all.
func TestAFailedCaptureIsRecordedNotFatal(t *testing.T) {
	r := runAgainst(t)

	if len(r.Streams) == 0 {
		t.Fatal("no stream records; a socket that refused must still be reported")
	}
	for _, s := range r.Streams {
		if s.Status == "" {
			t.Errorf("stream %s/%s has no status", s.Product, s.Name)
		}
		if s.Types == nil {
			t.Errorf("stream %s/%s has a nil type map; every record must be "+
				"well-formed even when the capture failed", s.Product, s.Name)
		}
	}
}

// JSONL is the format, and it is the format because a maintainer receiving
// contributions can grep, count and concatenate them with no tooling.
func TestTheReportIsOneJSONObjectPerLine(t *testing.T) {
	r := runAgainst(t)

	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			t.Fatal("a blank line in JSONL breaks every tool that reads it by line")
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", n, err, line)
		}
		if rec["record"] == nil {
			t.Errorf("line %d has no record type, so nothing can sort it: %s", n, line)
		}
		if n == 0 && rec["record"] != "meta" {
			t.Errorf("the first record is %v, want meta -- the firmware version "+
				"has to be readable without parsing the whole file", rec["record"])
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Errorf("report has %d records, which is too few to have run", n)
	}
}

// Angle brackets, not unicode escapes. The file exists to be read and grepped.
func TestPseudonymsAreReadableInTheFile(t *testing.T) {
	r := runAgainst(t)
	var buf bytes.Buffer
	_ = r.Write(&buf)
	// Built rather than written out, so nothing between here and the file can
	// helpfully turn the escape back into the character it stands for.
	escaped := string([]byte{'\\'}) + "u003c"
	got := buf.String()
	if strings.Contains(got, escaped) {
		t.Error("labels were HTML-escaped; grepping the file for <text- would find nothing")
	}
	if !strings.Contains(got, "<") {
		t.Error("no pseudonym in the report at all, so this proves nothing")
	}
}

func TestSaveWritesPrivately(t *testing.T) {
	r := runAgainst(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "probe.jsonl")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeIsUnix() && st.Mode().Perm() != 0o600 {
		t.Errorf("report mode = %v, want 0600", st.Mode().Perm())
	}
}

// THE SECURITY RAIL, at the level an operator meets it. A probe pointed at an
// address the operator does not own is an unauthorised scan run from their
// machine and their address.
func TestRunRefusesARemoteConsole(t *testing.T) {
	_, err := Run(context.Background(), Options{Host: "8.8.8.8", Products: []string{"protect"}})
	if err == nil {
		t.Fatal("a public address was accepted")
	}
	if !strings.Contains(err.Error(), "local") {
		t.Errorf("error = %v, want one that says why", err)
	}
}

func keysOf(s *Schema) []string {
	out := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		out = append(out, k)
	}
	return out
}
