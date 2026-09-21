package probe

import (
	"bytes"
	"strings"
	"testing"
)

// All four of these come from one real run against a console the operator had
// never issued an API key for. Every request was refused, and the report
// nevertheless offered four discoveries and said nothing about the refusal.
//
// The shape of the bug: the probe could not tell "I was not let in" from "this
// firmware does not have it", which for a tool whose entire output is a claim
// about what a console has is the one distinction that has to hold.

// The login page. Four Access paths answered 200 with 1513 bytes of
// text/html -- the same page four times -- and were written up as endpoints
// that answer on this firmware.
func TestAPageIsNotAnEndpointAnswering(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{{
		Record: "endpoint", Product: "access", Method: "GET",
		Path: "/proxy/access/integration/v1/developer/doors", Known: false,
		Status: 200, ContentType: "text/html",
		Error: "response was not JSON", Bytes: 1513,
	}}}

	for _, f := range diff(r) {
		if f.Kind == "endpoint.undocumented" {
			t.Errorf("an HTML page was reported as an undocumented endpoint: %+v", f)
		}
	}
}

// The same path answering as an API is still the discovery it always was.
// Without this the fix above could be "report nothing" and the suite would
// not notice.
func TestJSONFromAnUnknownPathIsStillADiscovery(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{{
		Record: "endpoint", Product: "access", Method: "GET",
		Path: "/proxy/access/integration/v1/developer/doors", Known: false,
		Status: 200, ContentType: "application/json", Bytes: 900,
	}}}

	var found bool
	for _, f := range diff(r) {
		if f.Kind == "endpoint.undocumented" {
			found = true
		}
	}
	if !found {
		t.Error("an unknown path answering JSON is the discovery this tool exists for")
	}
}

// A JSON content type is not enough on its own. A body that arrived with the
// right header and could not be read means the endpoint answered with
// something nobody has parsed -- which is not the same as a discovery, and
// would be written up as one by a check that trusted the header alone.
func TestABodyThatCouldNotBeReadIsNotADiscovery(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{{
		Record: "endpoint", Product: "network", Method: "GET",
		Path: "/proxy/network/integration/v1/info", Known: false,
		Status: 200, ContentType: "application/json",
		Error: "response was not JSON", Bytes: 40,
	}}}

	for _, f := range diff(r) {
		if f.Kind == "endpoint.undocumented" {
			t.Errorf("an unreadable body was reported as a discovery: %+v", f)
		}
	}
}

// Being refused is a finding. The comment at the call site has said so since
// the probe was written; nothing implemented it.
func TestAProductThatRefusedEverythingSaysSo(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{
		{Record: "endpoint", Product: "protect", Path: "/a", Known: true, Status: 401, ContentType: "application/json"},
		{Record: "endpoint", Product: "protect", Path: "/b", Known: true, Status: 401, ContentType: "application/json"},
	}}

	var found bool
	for _, f := range diff(r) {
		if f.Kind == "auth.refused" && f.Product == "protect" {
			found = true
		}
	}
	if !found {
		t.Errorf("every request was refused and the report did not say so: %+v", r.Findings)
	}
}

// A key that works for one path and not another is a different situation, and
// calling it "refused" would hide the half that answered.
func TestAProductThatAnsweredIsNotReportedAsRefused(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{
		{Record: "endpoint", Product: "protect", Path: "/a", Known: true, Status: 200, ContentType: "application/json"},
		{Record: "endpoint", Product: "protect", Path: "/b", Known: false, Status: 401, ContentType: "application/json"},
	}}

	for _, f := range diff(r) {
		if f.Kind == "auth.refused" {
			t.Errorf("a product that answered was reported as refused: %+v", f)
		}
	}
}

// The summary is what an operator reads. A run that was never let in must say
// that before it says anything else, because every other line is then a
// statement about this build's catalogue rather than about their console.
func TestTheSummaryLeadsWithNotHavingBeenLetIn(t *testing.T) {
	r := &Report{
		Meta: Meta{Record: "meta", Versions: map[string]string{}},
		Endpoints: []EndpointResult{
			{Record: "endpoint", Product: "protect", Path: "/a", Known: true, Status: 401, ContentType: "application/json"},
		},
	}
	r.Findings = diff(r)

	var buf bytes.Buffer
	r.Summarise(&buf)
	got := buf.String()

	if !strings.Contains(strings.ToUpper(got), "NOT AUTHENTICATED") {
		t.Errorf("the summary of an unauthenticated run does not say so:\n%s", got)
	}
	if i := strings.Index(strings.ToUpper(got), "NOT AUTHENTICATED"); i > strings.Index(got, "endpoints") {
		t.Error("the warning arrives after the findings it explains")
	}
}

// And says nothing of the sort when a key worked, or it becomes noise nobody
// reads on the run that matters.
func TestTheSummaryIsQuietWhenAKeyWorked(t *testing.T) {
	r := &Report{
		Meta: Meta{Record: "meta", Versions: map[string]string{"protect": "7.3.53"}},
		Endpoints: []EndpointResult{
			{Record: "endpoint", Product: "protect", Path: "/a", Known: true, Status: 200, ContentType: "application/json"},
		},
	}

	var buf bytes.Buffer
	r.Summarise(&buf)
	if strings.Contains(strings.ToUpper(buf.String()), "NOT AUTHENTICATED") {
		t.Errorf("an authenticated run was warned about:\n%s", buf.String())
	}
}

// submit reads the file back rather than trusting a flag from the run that
// wrote it, because the file is what would be published and the run may have
// been days ago.
func TestAuthenticatedIsReadableBackFromTheFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *Report
		want bool
	}{
		{"refused", &Report{
			Meta: Meta{Record: "meta", SchemaVersion: SchemaVersion, Versions: map[string]string{}},
			Endpoints: []EndpointResult{
				{Record: "endpoint", Product: "protect", Path: "/a", Status: 401, ContentType: "application/json"},
			},
		}, false},
		{"answered", &Report{
			Meta: Meta{Record: "meta", SchemaVersion: SchemaVersion, Versions: map[string]string{"protect": "7.3.53"}},
			Endpoints: []EndpointResult{
				{Record: "endpoint", Product: "protect", Path: "/a", Status: 200, ContentType: "application/json"},
			},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.r.Write(&buf); err != nil {
				t.Fatal(err)
			}
			got, err := ScanAuthenticated(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("ScanAuthenticated = %v, want %v, from:\n%s", got, tc.want, buf.String())
			}
		})
	}
}
