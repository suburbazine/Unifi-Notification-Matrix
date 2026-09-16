package probe

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// decode is the same tolerant decode the capture path uses.
func decode(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("test fixture is not JSON: %v", err)
	}
	return v
}

// render encodes the way the report writer does: HTML escaping off, so a
// pseudonym reads as <text-1> rather than as a pair of unicode escapes. A test
// that encoded differently from the writer would be asserting about bytes
// nobody ever publishes.
func render(t *testing.T, v any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(buf.String())
}

// A realistic Protect frame, carrying every class of thing that must not be
// published alongside the vocabulary that must be.
const protectFrame = `{
  "type": "add",
  "item": {
    "id": "68cdb33400578403e401e390",
    "type": "smartDetectZone",
    "modelKey": "camera",
    "name": "Nursery",
    "mac": "A8:9C:6C:B2:27:FA",
    "host": "192.168.1.50",
    "state": "CONNECTED",
    "start": 1758000000000,
    "smartDetectTypes": ["person"],
    "metadata": {"alarmType": {"text": "smoke"}},
    "owner": "jane.doe@example.com",
    "streamUrl": "rtsps://192.168.1.1:7441/9wYQ8vTkK2mNpLxR?enableSrtp",
    "apiToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij"
  }
}`

// THE ONE THAT MATTERS. A raw probe of a UniFi console is a map of somebody's
// building, and this file is meant to be published to a public repository.
func TestNothingIdentifyingSurvives(t *testing.T) {
	canaries := []string{
		"Nursery",                  // a camera name is a room name
		"A8:9C:6C:B2:27:FA",        // hardware identity
		"a89c6cb227fa",             // the same MAC, spelled the other way
		"192.168.1.50",             // site topology
		"192.168.1.1",              // the console itself
		"jane.doe@example.com",     // a person
		"9wYQ8vTkK2mNpLxR",         // a stream token: anyone on the LAN can watch
		"68cdb33400578403e401e390", // device identity
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij",
		"1758000000000", // when somebody was home
	}

	p := NewPseudonymiser()
	got := render(t, p.JSON("", decode(t, protectFrame)))

	for _, c := range canaries {
		if strings.Contains(got, c) {
			t.Errorf("%q reached the report:\n%s", c, got)
		}
	}
}

// Over-redacting costs a less informative report. Under-redacting publishes
// somebody's floor plan. But a report with no vocabulary in it is worthless,
// so the useful half has to survive intact.
func TestTheVocabularySurvives(t *testing.T) {
	p := NewPseudonymiser()
	got := render(t, p.JSON("", decode(t, protectFrame)))

	for _, want := range []string{
		"smartDetectZone", // the event type: the entire point of the report
		"camera",          // modelKey
		"CONNECTED",       // the state enum
		"person",          // a smart-detect type
		"smoke",           // the alarm type that decides severity
		"add",             // the frame verb
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q was redacted; without it the report says nothing:\n%s", want, got)
		}
	}

	// Field names are the schema and must all survive, including the ones
	// whose values were replaced.
	for _, want := range []string{"streamUrl", "mac", "name", "owner", "apiToken"} {
		if !strings.Contains(got, `"`+want+`"`) {
			t.Errorf("the field name %q was lost; the schema is the payload:\n%s", want, got)
		}
	}
}

// THE DESIGN DECISION, asserted directly. A denylist fails on the field nobody
// anticipated -- and finding fields nobody anticipated is the entire purpose
// of a probe, so a denylist would fail exactly where this tool is used.
func TestAnUnknownFieldIsRedactedWithoutBeingNamedAnywhere(t *testing.T) {
	const future = `{"somethingNobodyHasSeenYet": "Reception Door", "occupantName": "Ada"}`
	p := NewPseudonymiser()
	got := render(t, p.JSON("", decode(t, future)))

	for _, c := range []string{"Reception Door", "Ada"} {
		if strings.Contains(got, c) {
			t.Errorf("%q survived in a field this package has never heard of; "+
				"the allowlist has become a denylist:\n%s", c, got)
		}
	}
	if !strings.Contains(got, "somethingNobodyHasSeenYet") || !strings.Contains(got, "occupantName") {
		t.Errorf("the unknown field NAMES were lost; discovering them is the point:\n%s", got)
	}
}

// A value that looks like identity is replaced even in a field on the
// allowlist. The field name is evidence about the value, never proof.
func TestIdentityInAVocabularyFieldIsStillReplaced(t *testing.T) {
	const odd = `{"model": "A8:9C:6C:B2:27:FA", "type": "68cdb33400578403e401e390", "state": "CONNECTED"}`
	p := NewPseudonymiser()
	got := render(t, p.JSON("", decode(t, odd)))

	if strings.Contains(got, "A8:9C:6C:B2:27:FA") {
		t.Errorf("a MAC in a field called `model` was published:\n%s", got)
	}
	if strings.Contains(got, "68cdb33400578403e401e390") {
		t.Errorf("a device id in a field called `type` was published:\n%s", got)
	}
	if !strings.Contains(got, "CONNECTED") {
		t.Errorf("an ordinary vocabulary value was lost:\n%s", got)
	}
}

// A long value in a vocabulary field is data, whatever the field is called.
//
// The value has SPACES on purpose. The first version of this test used a run
// of one repeated character, which the token detector classified as a
// credential and replaced for that reason instead -- so the test passed with
// the length cap deleted. It certified a property it was not checking, which
// mutation testing is the only thing that catches.
func TestALongValueInAVocabularyFieldIsReplaced(t *testing.T) {
	// Two words, so the WORD rule cannot fire and the length cap is the only
	// thing that can catch this. Isolating the rules matters: a fixture both
	// rules catch passes with either one deleted.
	word := strings.Repeat("Vestibule", 4)
	long := word + " " + word

	if len(long) <= vocabularyCap {
		t.Fatalf("fixture is %d chars, inside the cap it is meant to test", len(long))
	}
	if n := len(strings.Fields(long)); n > vocabularyWords {
		t.Fatalf("fixture is %d words, so the word rule would catch it and the "+
			"length cap would go untested", n)
	}
	if identityShaped(long) {
		t.Fatal("fixture is identity-shaped, so this would pass for the wrong reason")
	}

	p := NewPseudonymiser()
	got := render(t, p.JSON("", map[string]any{"type": long}))
	if strings.Contains(got, long) {
		t.Errorf("a %d-character value survived in a vocabulary field:\n%s", len(long), got)
	}
}

// Prose in a vocabulary field is data. Length alone does not separate a model
// name from a sentence about somebody's building; word count does.
func TestProseInAVocabularyFieldIsReplaced(t *testing.T) {
	const prose = "Front Door forced open by Jane" // short, but a sentence
	if len(prose) > vocabularyCap {
		t.Fatal("fixture is caught by the length cap, so it tests nothing new")
	}
	p := NewPseudonymiser()
	got := render(t, p.JSON("", map[string]any{"status": prose}))
	if strings.Contains(got, prose) {
		t.Errorf("a sentence naming a door and a person survived:\n%s", got)
	}

	// And the thing the allowance exists for still works.
	if got := render(t, p.JSON("", map[string]any{"type": "UVC G6 PTZ"})); !strings.Contains(got, "UVC G6 PTZ") {
		t.Errorf("a model name was redacted; it is part of the payload:\n%s", got)
	}
}

// `code` can be a door PIN. `reason` and `result` carry prose. None of the
// three is worth the risk, so none is vocabulary.
func TestFieldsThatUsuallyHoldTermsButSometimesHoldSecretsAreNotVocabulary(t *testing.T) {
	p := NewPseudonymiser()
	got := render(t, p.JSON("", map[string]any{
		"code":   "4821",
		"reason": "Ada",
		"result": "Garage",
	}))
	for _, c := range []string{"4821", "Ada", "Garage"} {
		if strings.Contains(got, c) {
			t.Errorf("%q survived; the field it was in is not safe to publish:\n%s", c, got)
		}
	}
}

// Within one report the same value keeps one label, because "these two fields
// held the same device" is a real schema fact.
func TestOneValueKeepsOneLabelWithinAReport(t *testing.T) {
	p := NewPseudonymiser()
	a := p.Value("A8:9C:6C:B2:27:FA")
	b := p.Value("a89c6cb227fa") // the same MAC, other spelling
	if a != b {
		t.Errorf("one MAC got two labels (%s, %s); the report would describe "+
			"two devices where the console has one", a, b)
	}
	if c := p.Value("00:11:22:33:44:55"); c == a {
		t.Errorf("two different MACs collapsed to one label %s", c)
	}
}

// ACROSS reports they must NOT correlate. Two submissions from one site that
// shared labels would be linkable back to that site, which is the property
// this whole layer exists to deny.
func TestLabelsDoNotCorrelateAcrossReports(t *testing.T) {
	one := NewPseudonymiser()
	two := NewPseudonymiser()

	// The second report happens to see a different device first.
	one.Value("Nursery")
	two.Value("Garage")

	if one.Value("Nursery") == two.Value("Nursery") {
		t.Error("the same value produced the same label in two reports; two " +
			"submissions from one site would be linkable to each other")
	}
}

// A hash would be a fake protection here: the MAC space is small and camera
// names come from a small dictionary, so a hash of either is recoverable by
// brute force. Labels must carry no derived material at all.
func TestALabelIsNotDerivedFromTheValue(t *testing.T) {
	p := NewPseudonymiser()
	label := p.Value("Nursery")
	if !strings.HasPrefix(label, "<text-") {
		t.Fatalf("label = %q, want a bare counter", label)
	}
	// A counter is the same regardless of input, which is exactly the property
	// that makes it unguessable.
	q := NewPseudonymiser()
	if other := q.Value("a completely different string"); other != label {
		t.Errorf("labels differ by input (%q vs %q); something about the value "+
			"is leaking into the label", label, other)
	}
}

func TestNumbersAreClassifiedNotPublished(t *testing.T) {
	p := NewPseudonymiser()
	in := `{"start": 1758000000000, "seen": 1758000000, "port": 443, "score": 85,
	        "lat": 47.6062, "bytes": 99999999999999}`
	got := render(t, p.JSON("", decode(t, in)))

	for _, want := range []string{`"start":"<epoch_ms>"`, `"seen":"<epoch_s>"`,
		`"port":443`, `"score":85`, `"lat":"<float>"`, `"bytes":"<number>"`} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in:\n%s", want, got)
		}
	}
}

// A map KEYED by device id is a real shape on these consoles, and a redactor
// that walked only values would publish every id as a key.
func TestIdentifyingMapKeysAreReplaced(t *testing.T) {
	const keyed = `{"68cdb33400578403e401e390": {"state": "CONNECTED"}}`
	p := NewPseudonymiser()
	got := render(t, p.JSON("", decode(t, keyed)))
	if strings.Contains(got, "68cdb33400578403e401e390") {
		t.Errorf("a device id was published as a map key:\n%s", got)
	}
	if !strings.Contains(got, "CONNECTED") {
		t.Errorf("the nested value was lost:\n%s", got)
	}
}

func TestURLKeepsTheRouteAndNothingElse(t *testing.T) {
	p := NewPseudonymiser()
	got := p.URL("https://192.168.1.1/proxy/protect/integration/v1/cameras/68cdb33400578403e401e390/snapshot?token=9wYQ8vTkK2mNpLxR&hq=true")

	for _, bad := range []string{"192.168.1.1", "68cdb33400578403e401e390", "9wYQ8vTkK2mNpLxR"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived in %q", bad, got)
		}
	}
	// The route is the finding.
	for _, want := range []string{"/proxy/protect/integration/v1/cameras", "/snapshot", "hq", "token"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q was lost from %q; the route IS the discovery", want, got)
		}
	}
}

// Structure is the schema, so it must survive exactly.
func TestShapeIsPreserved(t *testing.T) {
	p := NewPseudonymiser()
	clean := p.JSON("", decode(t, protectFrame))

	m, ok := clean.(map[string]any)
	if !ok {
		t.Fatalf("top level became %T", clean)
	}
	item, ok := m["item"].(map[string]any)
	if !ok {
		t.Fatalf("item became %T; nesting was flattened", m["item"])
	}
	types, ok := item["smartDetectTypes"].([]any)
	if !ok || len(types) != 1 {
		t.Fatalf("smartDetectTypes became %T; array length is a schema fact", item["smartDetectTypes"])
	}
	if _, ok := item["metadata"].(map[string]any); !ok {
		t.Errorf("nested object collapsed to %T", item["metadata"])
	}
}

func TestEmptyAndNullSurvive(t *testing.T) {
	p := NewPseudonymiser()
	got := render(t, p.JSON("", decode(t, `{"a": null, "b": "", "c": true, "d": []}`)))
	want := `{"a":null,"b":"","c":true,"d":[]}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// Belt and braces against the report writer: whatever the pseudonymiser
// returns has to survive encoding, or a capture the operator cannot easily
// repeat is lost at the last step.
func TestRedactedOutputAlwaysEncodes(t *testing.T) {
	p := NewPseudonymiser()
	for _, in := range []string{
		protectFrame,
		`[1, 2, {"name": "x"}]`,
		`"bare string"`,
		`42`,
		`null`,
	} {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(p.JSON("", decode(t, in))); err != nil {
			t.Errorf("redacted %s does not encode: %v", in, err)
		}
	}
}
