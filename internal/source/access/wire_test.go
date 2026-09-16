package access

import (
	"encoding/json"
	"testing"
	"time"
)

func decodeEnvelope(t *testing.T, s string) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return e
}

// Some consoles send {"code":200} and others {"code":"SUCCESS"}. A strict
// string decode does not lose the code -- it fails the ENTIRE call against a
// console that is working perfectly.
func TestTheEnvelopeCodeMayBeAStringOrANumber(t *testing.T) {
	for _, body := range []string{
		`{"code":"SUCCESS","data":[]}`,
		`{"code":200,"data":[]}`,
		`{"data":[]}`,
	} {
		if ok, why := decodeEnvelope(t, body).ok(); !ok {
			t.Errorf("%s was rejected: %s", body, why)
		}
	}
}

// Access answers HTTP 200 with a failure code in the body. A client that
// trusts the status treats a refusal as an empty result -- which for the log
// poller is the difference between "no denials happened" and "we never asked".
func TestAFailureCodeIsAFailureEvenOnHTTP200(t *testing.T) {
	ok, why := decodeEnvelope(t, `{"code":"CODE_SYSTEM_ERROR","msg":"nope","data":null}`).ok()
	if ok {
		t.Fatal("CODE_SYSTEM_ERROR was read as success")
	}
	if why == "" {
		t.Error("the refusal carries no reason, so nothing can report why")
	}
}

// GET /doors decodes the whole site in one Unmarshal, so a strict decode does
// not drop one odd door -- it loses every door, and the product then reports a
// site with no doors as a site where nothing is wrong.
func TestTheDoorListSurvivesAnOddRecord(t *testing.T) {
	const body = `[
	  {"id":"d1","name":"DOOR8","full_name":"UDM-Pro-Max - 1F - DOOR8",
	   "door_lock_relay_status":"lock","door_position_status":"close"},
	  {"id":"d2","name":"Gate","door_lock_relay_status":"unlock",
	   "door_position_status":"open","door_lock_rule":{"type":"keep_unlock"}},
	  {"id":"d3","name":"Side","door_lock_rule":"keep_unlock",
	   "door_position_status":"none"}
	]`
	var doors []door
	if err := json.Unmarshal([]byte(body), &doors); err != nil {
		t.Fatalf("one door with a bare-string lock_rule killed the whole site: %v", err)
	}
	if len(doors) != 3 {
		t.Fatalf("got %d doors, want 3", len(doors))
	}
	if got := doors[0].displayName(); got != "UDM-Pro-Max - 1F - DOOR8" {
		t.Errorf("display name = %q, want full_name -- it is what the operator "+
			"sees in the Access app", got)
	}
	if got := doors[1].displayName(); got != "Gate" {
		t.Errorf("display name = %q, want the plain name when full_name is absent", got)
	}
}

// "close", not "closed". "none" means NO SENSOR FITTED, which is neither open
// nor shut and must never be read as shut.
func TestPositionValues(t *testing.T) {
	cases := map[string]PositionState{
		`"open"`:    PositionOpen,
		`"close"`:   PositionClosed,
		`"closed"`:  PositionClosed, // tolerated, though the console says "close"
		`"none"`:    PositionNone,
		`"unknown"`: PositionUnknown,
		`""`:        PositionUnknown,
		`null`:      PositionUnknown,
	}
	for raw, want := range cases {
		if got := parsePosition(json.RawMessage(raw)); got != want {
			t.Errorf("parsePosition(%s) = %q, want %q", raw, got, want)
		}
	}
	if PositionNone.derivable() {
		t.Error("a door with no sensor was treated as derivable; held-open and " +
			"forced-entry would be decided from nothing")
	}
	if PositionUnknown.derivable() {
		t.Error("an unreadable position was treated as derivable")
	}
}

// Absent or blank is UNKNOWN, not locked. Reporting a door as secured because
// a field was unreadable is reporting security on no evidence.
func TestRESTLockStateIsUnknownRatherThanSecure(t *testing.T) {
	cases := map[string]LockState{
		`"unlock"`:                    LockUnlocked,
		`"unlocked"`:                  LockUnlocked,
		`"lock"`:                      LockLocked,
		`"locked"`:                    LockLocked,
		`"something-nobody-has-seen"`: LockLocked,
		`""`:                          LockUnknown,
		`"   "`:                       LockUnknown,
		`null`:                        LockUnknown,
	}
	for raw, want := range cases {
		if got := parseRESTLock(json.RawMessage(raw)); got != want {
			t.Errorf("parseRESTLock(%s) = %q, want %q", raw, got, want)
		}
	}
}

// The socket has its OWN vocabulary. Routing its values through the REST value
// set alone reads every "unlock" as locked, because the REST rule is
// "anything unrecognised is locked".
func TestTheSocketLockVocabularyIsItsOwn(t *testing.T) {
	cases := map[string]LockState{
		`"unlock"`: LockUnlocked, `"unlocked"`: LockUnlocked,
		`"lock"`: LockLocked, `"locked"`: LockLocked,
		`""`: LockUnknown, `"weird"`: LockUnknown,
	}
	for raw, want := range cases {
		if got := parseSocketLock(json.RawMessage(raw)); got != want {
			t.Errorf("parseSocketLock(%s) = %q, want %q", raw, got, want)
		}
	}
}

// Shape A: the door is the subject.
func TestNotificationShapeA(t *testing.T) {
	const body = `{"event":"access.data.v2.location.update",
	 "data":{"id":"d1","name":"Front Door",
	         "state":{"lock":"unlocked",
	                  "remain_unlock":{"state":"unlocked","until":1780000000,"type":"schedule"}}}}`
	var n notification
	if err := json.Unmarshal([]byte(body), &n); err != nil {
		t.Fatal(err)
	}
	got := n.states()
	if len(got) != 1 {
		t.Fatalf("got %d states, want 1", len(got))
	}
	if got[0].DoorID != "d1" || got[0].Name != "Front Door" {
		t.Errorf("state = %+v, want the door id and name", got[0])
	}
	if got[0].Lock != LockUnlocked {
		t.Errorf("lock = %q, want unlocked", got[0].Lock)
	}
	if !got[0].Held || !got[0].Known {
		t.Errorf("remain_unlock not read as held: %+v", got[0])
	}
}

// Shape B: the DEVICE is the subject and carries a door per entry, with no
// name at all. Naming the door after the hub would label a door after the
// hardware that serves it.
func TestNotificationShapeB(t *testing.T) {
	const body = `{"event":"access.data.v2.device.update",
	 "data":{"location_states":[
	   {"location_id":"d1","lock":"lock",
	    "remain_unlock":{"state":"lock","until":0,"type":""}},
	   {"location_id":"d2","lock":"unlock"}]}}`
	var n notification
	if err := json.Unmarshal([]byte(body), &n); err != nil {
		t.Fatal(err)
	}
	got := n.states()
	if len(got) != 2 {
		t.Fatalf("got %d states, want 2", len(got))
	}
	if got[0].Name != "" {
		t.Errorf("shape B invented a door name %q", got[0].Name)
	}
	if got[0].Lock != LockLocked || got[1].Lock != LockUnlocked {
		t.Errorf("locks = %q, %q", got[0].Lock, got[1].Lock)
	}
}

// The value set of remain_unlock.state has never been captured from hardware.
// A guess here either raises a permanent unclearable incident or hides a door
// somebody left open, so an unrecognised value reports "not known".
func TestAnUnknownRemainUnlockStateIsNotGuessed(t *testing.T) {
	mk := func(state string) *remainUnlock {
		return &remainUnlock{State: json.RawMessage(`"` + state + `"`)}
	}
	for _, s := range []string{"unlock", "unlocked"} {
		if held, known := mk(s).held(); !held || !known {
			t.Errorf("state %q: held=%v known=%v, want held", s, held, known)
		}
	}
	for _, s := range []string{"lock", "locked", "none", "off", ""} {
		if held, known := mk(s).held(); held || !known {
			t.Errorf("state %q: held=%v known=%v, want not held", s, held, known)
		}
	}
	for _, s := range []string{"scheduled", "temporary", "whatever-comes-next"} {
		if _, known := mk(s).held(); known {
			t.Errorf("state %q was bucketed rather than reported as unknown", s)
		}
	}
	if _, known := (*remainUnlock)(nil).held(); !known {
		t.Error("an absent remain_unlock block should read as not held, not unknown")
	}
}

// target is an array on most rows and a single object on others.
func TestTheLogTargetIsPolymorphic(t *testing.T) {
	const asArray = `{"target":[{"id":"u1","type":"user"},{"id":"d1","type":"door","display_name":"Front"}]}`
	const asObject = `{"target":{"id":"d1","type":"door","display_name":"Front"}}`

	for _, body := range []string{asArray, asObject} {
		var src logSource
		if err := json.Unmarshal([]byte(body), &src); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		d, ok := src.door()
		if !ok || d.ID != "d1" {
			t.Errorf("%s: door = %+v, ok=%v", body, d, ok)
		}
	}
}

// The door is the SIXTH element on an unlock row and the second on a
// door-position row. Indexing attributes half of these events to whatever
// happens to sit in that slot.
func TestTheDoorTargetIsFoundByTypeNotByPosition(t *testing.T) {
	const body = `{"target":[
	  {"id":"u1","type":"user"},{"id":"p1","type":"policy"},
	  {"id":"g1","type":"user_group"},{"id":"r1","type":"reader"},
	  {"id":"c1","type":"credential"},{"id":"d9","type":"door","display_name":"Loading Bay"}]}`
	var src logSource
	if err := json.Unmarshal([]byte(body), &src); err != nil {
		t.Fatal(err)
	}
	d, ok := src.door()
	if !ok || d.ID != "d9" {
		t.Fatalf("door = %+v, ok=%v -- want the sixth element, found by type", d, ok)
	}
}

// @timestamp is RFC3339 and some firmwares omit it. event.published is UNIX
// MILLISECONDS -- inverted from the seconds the query takes, which is the
// console's inconsistency and not a transcription error.
func TestRowTimestampFallsBackToPublishedMilliseconds(t *testing.T) {
	want := time.Date(2026, 9, 16, 2, 40, 0, 0, time.UTC)

	var withTS logHit
	if err := json.Unmarshal([]byte(`{"_id":"a","@timestamp":"2026-09-16T02:40:00Z"}`), &withTS); err != nil {
		t.Fatal(err)
	}
	if got, ok := withTS.at(); !ok || !got.Equal(want) {
		t.Errorf("with @timestamp: at = %v (%v), want %v", got, ok, want)
	}

	var withoutTS logHit
	body := `{"_id":"b","_source":{"event":{"published":` +
		json.Number(itoaMillis(want)).String() + `}}}`
	if err := json.Unmarshal([]byte(body), &withoutTS); err != nil {
		t.Fatal(err)
	}
	got, ok := withoutTS.at()
	if !ok || !got.Equal(want) {
		t.Errorf("without @timestamp: at = %v (%v), want %v -- some firmwares "+
			"omit it entirely", got, ok, want)
	}

	var neither logHit
	if err := json.Unmarshal([]byte(`{"_id":"c"}`), &neither); err != nil {
		t.Fatal(err)
	}
	if _, ok := neither.at(); ok {
		t.Error("a row with no time at all claimed to have one; the caller must " +
			"stamp arrival and say so")
	}
}

func itoaMillis(t time.Time) string {
	b, _ := json.Marshal(t.UnixMilli())
	return string(b)
}

// Hubs have display names too, and they are frequently named after the door
// they serve -- so a name test attributes a hardware event to a person who was
// nowhere near the building.
func TestAnActorIsAPersonByTypeOrIDShapeNeverByName(t *testing.T) {
	person := logActor{ID: "0f8f1f4c-1f2b-4a5b-9c3d-1a2b3c4d5e6f", Type: "", DisplayName: "Ada"}
	if !person.isPerson() {
		t.Error("a 36-character UUID actor was not read as a person")
	}
	typed := logActor{ID: "x", Type: "user", DisplayName: "Front Door"}
	if !typed.isPerson() {
		t.Error("an actor typed `user` was not read as a person")
	}
	hub := logActor{ID: "a89c6cb227fa", Type: "UAH-Ent", DisplayName: "Front Door"}
	if hub.isPerson() {
		t.Error("a hub named after the door it serves was read as a person")
	}
	if got := (logActor{DisplayName: "N/A"}).who(); got == "N/A" {
		t.Error(`"N/A" was passed through; it is the console saying the credential ` +
			"did not resolve to anybody, which on a denial is the whole point")
	}
}
