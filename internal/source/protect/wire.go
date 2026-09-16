package protect

import (
	"encoding/json"
	"strconv"
	"strings"
)

// frame is the outer envelope both sockets speak: a flat JSON text frame
// discriminated on `type`, with the payload under `item`.
type frame struct {
	Type string          `json:"type"`
	Item json.RawMessage `json:"item"`
}

// item is one payload, decoded defensively.
//
// Every risky field is a pointer, a raw message or a tolerant type. A strict
// typed decode does not lose one unexpected field -- it fails the entire frame,
// and on a socket with no resume cursor a failed frame is an event that can
// never be recovered. So nothing here can fail on a surprise.
type item struct {
	// ID is raw because the devices channel sends it BOTH ways: a string on
	// ordinary frames and an ARRAY on bulk ones. See decodeIDs.
	ID json.RawMessage `json:"id"`

	ModelKey string `json:"modelKey"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	MAC      string `json:"mac"`

	// State is the camera/sensor connection enum: CONNECTED | CONNECTING |
	// DISCONNECTED. Camera disconnect is not an event type -- it is this field
	// flipping on the devices channel.
	State string `json:"state"`

	// Start and End are Unix MILLISECONDS, not seconds. Read as seconds they
	// land in 1970 and every alert points at the wrong footage.
	Start *flexMillis `json:"start"`
	End   *flexMillis `json:"end"`

	// Device is a Protect device id on this channel. The Alarm Manager webhook
	// carries a bare MAC for the same hardware; resolution to one identity
	// happens here rather than downstream.
	Device string `json:"device"`

	SmartDetectTypes []string `json:"smartDetectTypes"`
	Metadata         metadata `json:"metadata"`
}

// decodeIDs reads the id field in either of the two shapes Protect sends.
//
// THIS IS THE HIGHEST-RISK DECODE IN THE PROTECT PATH. devicesAdd,
// devicesBulkUpdate and devicesBulkRemove carry one payload covering many
// devices, with `id` as an array. A parser that reads it as a string drops
// every bulk message SILENTLY -- no error, no unrecognised counter, just a
// source that looks healthy and never reports the camera that went dark.
// Hence both shapes, and hence the test that sends both.
func decodeIDs(raw json.RawMessage) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}

	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}

	// An array element that is not a string is skipped rather than failing the
	// whole envelope: one unreadable id must not cost us the other forty.
	var many []json.RawMessage
	if err := json.Unmarshal(raw, &many); err == nil {
		out := make([]string, 0, len(many))
		for _, el := range many {
			if s, ok := scalarString(el); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	// A bare number is not documented, but costs nothing to accept and would
	// otherwise be an invisible drop.
	if s, ok := scalarString(raw); ok && s != "" {
		return []string{s}
	}
	return nil
}

func scalarString(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String(), true
	}
	return "", false
}

// flexMillis is a Unix-millisecond timestamp that tolerates being sent as a
// JSON string. Firmware has been observed changing scalar encodings between
// versions; a timestamp that arrives quoted must not cost us the event.
type flexMillis int64

func (f *flexMillis) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		return nil
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		// No information beats a guess: leave it zero and let the caller stamp
		// arrival time and say so.
		return nil
	}
	*f = flexMillis(int64(n))
	return nil
}

// metaValue is one metadata scalar.
//
// Protect WRAPS them: {"text": v} for enums and strings, {"number": v} for
// numerics. Reading metadata.sensorType as a plain string yields "" on every
// firmware that wraps, which turns a smoke alarm into an unclassified
// sensorAlarm. Both wrapped and bare forms are accepted so that an unwrapping
// firmware cannot silently blind us either.
type metaValue struct {
	Text      string
	Number    float64
	HasText   bool
	HasNumber bool
}

type metadata map[string]metaValue

// UnmarshalJSON never returns an error on purpose: a metadata scalar in an
// unfamiliar shape must degrade to "no information" for that one key, not fail
// the surrounding event.
func (m *metaValue) UnmarshalJSON(b []byte) error {
	var wrapper struct {
		Text   json.RawMessage `json:"text"`
		Number json.RawMessage `json:"number"`
	}
	if err := json.Unmarshal(b, &wrapper); err == nil {
		if len(wrapper.Text) > 0 {
			if s, ok := scalarString(wrapper.Text); ok {
				m.Text, m.HasText = s, true
			}
		}
		if len(wrapper.Number) > 0 {
			var f float64
			if err := json.Unmarshal(wrapper.Number, &f); err == nil {
				m.Number, m.HasNumber = f, true
			} else if s, ok := scalarString(wrapper.Number); ok {
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					m.Number, m.HasNumber = f, true
				}
			}
		}
		if m.HasText || m.HasNumber {
			return nil
		}
	}

	// Bare scalar fallback.
	var f float64
	if err := json.Unmarshal(b, &f); err == nil {
		m.Number, m.HasNumber = f, true
		m.Text, m.HasText = strconv.FormatFloat(f, 'f', -1, 64), true
		return nil
	}
	if s, ok := scalarString(b); ok {
		m.Text, m.HasText = s, true
	}
	return nil
}

// Text returns the wrapped string for a key, and whether it was present. The
// second return exists so callers can distinguish "absent" from "empty" --
// collapsing those is how an unknown alarm type becomes a plausible default.
func (m metadata) Text(key string) (string, bool) {
	v, ok := m[key]
	if !ok || !v.HasText {
		return "", false
	}
	return v.Text, true
}

func (m metadata) Number(key string) (float64, bool) {
	v, ok := m[key]
	if !ok || !v.HasNumber {
		return 0, false
	}
	return v.Number, true
}

// credentialMetadata names metadata keys whose VALUE is a credential.
//
// A PIN or a card number in a struct field is all it takes for one to reach a
// crash dump, a log line or the audit record. They are dropped at decode time
// and only their presence survives, because "an access attempt carried a PIN"
// is useful and "the PIN was 4417" is a liability.
var credentialMetadata = map[string]bool{
	"pin":        true,
	"code":       true,
	"password":   true,
	"token":      true,
	"cardId":     true,
	"nfcCardId":  true,
	"cardNumber": true,
}

// presentSentinel replaces a dropped credential value.
const presentSentinel = "present"

func (m *metadata) UnmarshalJSON(b []byte) error {
	raw := map[string]metaValue{}
	if err := json.Unmarshal(b, &raw); err != nil {
		// Metadata in an unfamiliar shape yields no metadata, never a failed
		// event: the event type alone is still worth alerting on.
		*m = metadata{}
		return nil
	}
	for k, v := range raw {
		if credentialMetadata[k] {
			raw[k] = metaValue{Text: presentSentinel, HasText: true}
		} else {
			raw[k] = v
		}
	}
	*m = raw
	return nil
}
