package protect

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The bulk envelope is the highest-risk decode in the Protect path: a parser
// that reads item.id as a string drops every devicesBulkUpdate silently, with
// no error and no counter, and the product keeps looking healthy while it
// stops reporting the cameras it was bought to watch.
func TestBulkEnvelopeIDIsReadAsBothStringAndArray(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"single device update sends a string", `{"id":"abc123"}`, []string{"abc123"}},
		{
			"devicesBulkUpdate sends an array covering many devices",
			`{"id":["cam-1","cam-2","cam-3"]}`,
			[]string{"cam-1", "cam-2", "cam-3"},
		},
		{"devicesAdd with a single-element array is still an array", `{"id":["only-one"]}`, []string{"only-one"}},
		{"empty array yields nothing rather than an empty id", `{"id":[]}`, nil},
		{"absent id yields nothing", `{"modelKey":"camera"}`, nil},
		{"null id yields nothing", `{"id":null}`, nil},
		{"empty string id yields nothing", `{"id":""}`, nil},
		{
			"an unreadable element costs that element and not the batch",
			`{"id":["cam-1",{"nope":true},"cam-3"]}`,
			[]string{"cam-1", "cam-3"},
		},
		{"a numeric id is accepted rather than silently dropped", `{"id":42}`, []string{"42"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var it item
			if err := json.Unmarshal([]byte(tc.raw), &it); err != nil {
				t.Fatalf("decoding item: %v", err)
			}
			got := decodeIDs(it.ID)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("decodeIDs = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// Metadata scalars are WRAPPED. Reading metadata.alarmType as a plain string
// yields "" on every firmware that wraps, which turns a smoke alarm into an
// unclassified sensorAlarm and loses the critical severity with it.
func TestWrappedMetadataScalarsAreUnwrapped(t *testing.T) {
	const raw = `{
	  "metadata": {
	    "sensorType":              {"text":   "smoke"},
	    "sensorBatteryPercentage": {"number": 14},
	    "alarmType":               {"text":   "CO"},
	    "inputState":              {"text":   ""},
	    "quotedNumber":            {"number": "7"},
	    "bareString":              "unwrapped",
	    "bareNumber":              99
	  }
	}`

	var it item
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		t.Fatalf("decoding item: %v", err)
	}

	if v, ok := it.Metadata.Text("sensorType"); !ok || v != "smoke" {
		t.Errorf("sensorType = %q, %v; want \"smoke\", true", v, ok)
	}
	if v, ok := it.Metadata.Number("sensorBatteryPercentage"); !ok || v != 14 {
		t.Errorf("sensorBatteryPercentage = %v, %v; want 14, true", v, ok)
	}
	if v, ok := it.Metadata.Text("alarmType"); !ok || v != "CO" {
		t.Errorf("alarmType = %q, %v; want \"CO\", true", v, ok)
	}
	if v, ok := it.Metadata.Number("quotedNumber"); !ok || v != 7 {
		t.Errorf("quotedNumber = %v, %v; want 7, true", v, ok)
	}
	if v, ok := it.Metadata.Text("bareString"); !ok || v != "unwrapped" {
		t.Errorf("bareString = %q, %v; want \"unwrapped\", true", v, ok)
	}
	if v, ok := it.Metadata.Number("bareNumber"); !ok || v != 99 {
		t.Errorf("bareNumber = %v, %v; want 99, true", v, ok)
	}

	// Present-but-empty and absent must stay distinguishable. Collapsing them
	// is how an unknown state becomes a plausible default.
	if v, ok := it.Metadata.Text("inputState"); !ok || v != "" {
		t.Errorf("inputState = %q, %v; want \"\", true (present and empty)", v, ok)
	}
	if _, ok := it.Metadata.Text("neverSent"); ok {
		t.Error("absent metadata key reported as present")
	}
}

// A PIN in a struct field is all it takes for one to reach a crash dump, an
// audit row or a log line. Only its presence is allowed to survive.
func TestCredentialMetadataIsDroppedAtDecodeTime(t *testing.T) {
	const raw = `{"type":"nfcCardScanned","metadata":{"pin":{"text":"4417"},"cardId":{"text":"04A2B3"},"deviceName":{"text":"Side Door"}}}`

	var it item
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		t.Fatalf("decoding item: %v", err)
	}

	for _, key := range []string{"pin", "cardId"} {
		v, ok := it.Metadata.Text(key)
		if !ok {
			t.Errorf("%s: presence did not survive; the fact that one was used is worth keeping", key)
		}
		if v != presentSentinel {
			t.Errorf("%s = %q, want %q -- the value must not survive decode", key, v, presentSentinel)
		}
	}
	if v, _ := it.Metadata.Text("deviceName"); v != "Side Door" {
		t.Errorf("deviceName = %q; non-credential metadata must be preserved", v)
	}

	// And it must not survive into the audit copy either.
	f := frame{Type: "add", Item: json.RawMessage(raw)}
	got := rawOf(f)
	md := got["item"].(map[string]any)["metadata"].(map[string]any)
	if md["pin"] != presentSentinel {
		t.Errorf("raw audit copy kept the PIN: %#v", md["pin"])
	}
}

func TestTimestampsSurviveUnexpectedEncodings(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int64
	}{
		{"numeric milliseconds", `{"start":1760282368873}`, 1760282368873},
		{"quoted milliseconds", `{"start":"1760282368873"}`, 1760282368873},
		{"null start", `{"start":null}`, 0},
		{"garbage start costs the timestamp, not the event", `{"start":"not-a-time"}`, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var it item
			if err := json.Unmarshal([]byte(tc.raw), &it); err != nil {
				t.Fatalf("a bad timestamp must not fail the whole item: %v", err)
			}
			var got int64
			if it.Start != nil {
				got = int64(*it.Start)
			}
			if got != tc.want {
				t.Fatalf("start = %d, want %d", got, tc.want)
			}
		})
	}
}

// A strict decode does not lose one unexpected field, it loses the whole
// frame -- and on a socket with no resume cursor a lost frame is an event that
// can never be recovered.
func TestUnexpectedFieldsDoNotFailTheItem(t *testing.T) {
	const raw = `{"id":"e1","type":"ring","device":"cam-1","start":1,"somethingNew":{"deeply":{"nested":[1,2,3]}},"metadata":"not-an-object"}`
	var it item
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		t.Fatalf("decoding item: %v", err)
	}
	if it.Type != "ring" || it.Device != "cam-1" {
		t.Fatalf("usable fields lost: %+v", it)
	}
	if len(it.Metadata) != 0 {
		t.Fatalf("metadata in an unfamiliar shape should yield none, got %#v", it.Metadata)
	}
}
