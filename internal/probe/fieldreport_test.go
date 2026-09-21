package probe

import (
	"strings"
	"testing"
)

// Three things a real run against a real console found that no fixture had.
// The report came from a UCG-Fiber with Protect and Network answering and
// Access not enabled.

// A DISCOVERY IS A PATH THIS BUILD DOES NOT USE, and the catalogue is the only
// thing that says which those are. Network's site and device lists are the two
// paths the Network source polls on a timer, and they were marked unknown --
// so a real run reported them as discoveries.
//
// The half that matters more is the other direction: a path marked unknown
// can never produce endpoint.missing, so the day a firmware stops serving one
// of these, the report that exists to catch that says nothing.
func TestTheCatalogueKnowsWhatThisBuildActuallyUses(t *testing.T) {
	// Each of these is requested by a source in this repository. Adding one
	// here without adding it to the source is as wrong as the reverse; the
	// point is that the two agree.
	used := map[string]string{
		"/proxy/protect/integration/v1/cameras":              "internal/source/protect/reconcile.go",
		"/proxy/protect/integration/v1/sensors":              "internal/source/protect/reconcile.go",
		"/proxy/protect/integration/v1/nvrs":                 "internal/source/protect/reconcile.go",
		"/proxy/access/integration/v1/developer/doors":       "internal/source/access/access.go",
		"/proxy/network/integration/v1/sites":                "internal/source/network/network.go",
		"/proxy/network/integration/v1/sites/{site}/devices": "internal/source/network/network.go",
	}

	inCatalogue := map[string]bool{}
	for _, e := range Catalogue {
		inCatalogue[e.Path] = e.Known
	}
	for path, where := range used {
		known, listed := inCatalogue[path]
		if !listed {
			t.Errorf("%s is requested by %s and is not in the catalogue at all", path, where)
			continue
		}
		if !known {
			t.Errorf("%s is requested by %s, so it is not a discovery and its "+
				"disappearance is a regression this report could never report",
				path, where)
		}
	}
}

// A product whose every path answered with a web page is a product whose
// integration API is not enabled -- and nothing in the report said so, because
// a login page is not a 401 and the run was authenticated elsewhere.
func TestAProductThatOnlyServedPagesIsReported(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{
		// Protect answered properly on the same run.
		{Record: "endpoint", Product: "protect", Path: "/p", Known: true,
			Status: 200, ContentType: "application/json; charset=utf-8"},
		// Access served the console's login page twice over.
		{Record: "endpoint", Product: "access", Path: "/a", Status: 200,
			ContentType: "text/html", Error: "response was not JSON", Bytes: 1513},
		{Record: "endpoint", Product: "access", Path: "/b", Status: 200,
			ContentType: "text/html", Error: "response was not JSON", Bytes: 1513},
	}}

	findings := diff(r)
	var products []string
	for _, f := range findings {
		if f.Kind == "product.unavailable" {
			products = append(products, f.Product)
		}
	}
	if len(products) != 1 || products[0] != "access" {
		t.Errorf("product.unavailable reported for %v, want [access] exactly: %+v",
			products, findings)
	}
}

// One odd path among working ones is not an unavailable product. Without this
// the check above could fire on any product that ever served a page, which on
// a console that answers most paths and redirects one would be a finding
// telling an operator their working application is not installed.
func TestOneOddPathDoesNotCondemnAWorkingProduct(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{
		{Record: "endpoint", Product: "protect", Path: "/p", Known: true,
			Status: 200, ContentType: "application/json; charset=utf-8"},
		{Record: "endpoint", Product: "protect", Path: "/q", Status: 200,
			ContentType: "text/html", Error: "response was not JSON", Bytes: 1513},
	}}

	for _, f := range diff(r) {
		if f.Kind == "product.unavailable" {
			t.Errorf("a product that answered on another path was called unavailable: %+v", f)
		}
	}
}

// Nor is a product that was refused: that already has a finding, and saying
// both would describe one console two contradictory ways.
func TestARefusedProductIsNotAlsoCalledUnavailable(t *testing.T) {
	r := &Report{Endpoints: []EndpointResult{
		{Record: "endpoint", Product: "access", Path: "/a", Status: 401,
			ContentType: "application/json"},
		{Record: "endpoint", Product: "access", Path: "/b", Status: 200,
			ContentType: "text/html", Error: "response was not JSON", Bytes: 1513},
	}}

	var refused, unavailable bool
	for _, f := range diff(r) {
		switch f.Kind {
		case "auth.refused":
			refused = true
		case "product.unavailable":
			unavailable = true
		}
	}
	if !refused {
		t.Error("a refusal was not reported")
	}
	if unavailable {
		t.Error("a refused product was also called unavailable")
	}
}

// The detection vocabulary is what the rule engine keys on, and it arrives
// under three different field names. Two of them were being replaced with
// counters, so a contribution lost the exact enum it exists to carry -- and
// disagreed with itself, since the same five terms survived under
// smartDetectTypes and vanished under objectTypes.
func TestTheDetectionVocabularySurvivesUnderEveryNameItArrivesUnder(t *testing.T) {
	p := NewPseudonymiser()
	payload := map[string]any{
		"featureFlags": map[string]any{
			"smartDetectTypes":      []any{"person", "vehicle"},
			"smartDetectAudioTypes": []any{"alrmSmoke", "alrmCmonx"},
		},
		"smartDetectSettings": map[string]any{
			"objectTypes": []any{"person", "licensePlate"},
			"audioTypes":  []any{"alrmSmoke"},
		},
	}
	got := render(t, p.JSON("", payload))

	for _, want := range []string{"person", "vehicle", "licensePlate", "alrmSmoke", "alrmCmonx"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q was replaced; it is the vocabulary the report exists to carry:\n%s", want, got)
		}
	}
}

// And the reason the list stays short: a field that happens to sit beside them
// is not covered by them.
func TestTheDetectionFieldsDoNotOpenUpTheirNeighbours(t *testing.T) {
	p := NewPseudonymiser()
	got := render(t, p.JSON("", map[string]any{
		"smartDetectSettings": map[string]any{
			"objectTypes": []any{"person"},
			"zoneName":    "Back Gate",
		},
	}))
	if strings.Contains(got, "Back Gate") {
		t.Errorf("a room name beside the vocabulary was published:\n%s", got)
	}
}
