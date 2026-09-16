package access

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// envelope wraps every Access REST response.
//
// `code` is a RAW MESSAGE rather than a string because some consoles answer
// {"code":200} and others {"code":"SUCCESS"}. A strict string decode does not
// lose the code -- it fails the entire call, including the reads this source
// depends on, against a console that is working perfectly.
type envelope struct {
	Code json.RawMessage `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// ok reports whether the console considered the call a success.
//
// Checked SEPARATELY from the HTTP status, because Access answers HTTP 200
// with {"code":"CODE_SYSTEM_ERROR"} and a client that trusts the status code
// treats a refusal as an empty result. For the log poller that is the
// difference between "no denials happened" and "we never asked".
func (e envelope) ok() (bool, string) {
	code := strings.TrimSpace(scalarString(e.Code))
	if code == "" || strings.EqualFold(code, "SUCCESS") || code == "200" {
		return true, ""
	}
	if e.Msg != "" {
		return false, code + ": " + e.Msg
	}
	return false, code
}

// scalarString reads a JSON scalar as text regardless of which scalar it is.
func scalarString(raw json.RawMessage) string {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return strconv.FormatBool(b)
	}
	return ""
}

// door is one door record from GET /doors.
//
// Every risky field is tolerant. GET /doors decodes the whole site in one
// Unmarshal, so a strict decode does not drop one odd door -- it loses every
// door, and this source then reports a site with no doors as a site where
// nothing is wrong.
type door struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`

	// LockRelay is the raw relay status. See parseRESTLock.
	LockRelay json.RawMessage `json:"door_lock_relay_status"`

	// Position is door_position_status: "open", "close", "none", or absent.
	Position json.RawMessage `json:"door_position_status"`
}

// displayName prefers full_name, which is what the operator sees in the Access
// app -- "UDM-Pro-Max - 1F - DOOR8" rather than "DOOR8". An alert that names a
// door differently from the app is an alert somebody has to translate at 3am.
func (d door) displayName() string {
	if n := strings.TrimSpace(d.FullName); n != "" {
		return n
	}
	return strings.TrimSpace(d.Name)
}

// restUnlockValues are the door_lock_relay_status values that mean unlocked.
var restUnlockValues = []string{"unlock", "unlocked"}

// parseRESTLock reads the relay status.
//
// Absent or blank is UNKNOWN, not locked. Reporting a door as secured because
// a field was unreadable is reporting security on no evidence, and it is the
// direction of error that gets somebody hurt rather than merely annoyed.
func parseRESTLock(raw json.RawMessage) LockState {
	v := strings.ToLower(strings.TrimSpace(scalarString(raw)))
	if v == "" {
		return LockUnknown
	}
	for _, u := range restUnlockValues {
		if v == u {
			return LockUnlocked
		}
	}
	// Any other value present means the relay is energised in the locked
	// sense. The vocabulary here is not fully enumerated, so this is the
	// closed-world assumption, applied in the safe direction only because
	// UNKNOWN is handled above.
	return LockLocked
}

// parseSocketLock reads the notification socket's lock value.
//
// The socket has its OWN vocabulary -- "lock"/"unlock" -- distinct from the
// REST relay field. Routing socket values through the REST value set alone
// reads every "lock" as an unrecognised value and therefore as locked, which
// happens to be right, and reads every "unlock" as locked too, which is not.
func parseSocketLock(raw json.RawMessage) LockState {
	switch strings.ToLower(strings.TrimSpace(scalarString(raw))) {
	case "unlock", "unlocked":
		return LockUnlocked
	case "lock", "locked":
		return LockLocked
	case "":
		return LockUnknown
	}
	return LockUnknown
}

// parsePosition reads door_position_status.
//
// "close", not "closed". "none" means NO SENSOR FITTED and is kept distinct
// from unknown so Health can report how much of a site is actually observable.
func parsePosition(raw json.RawMessage) PositionState {
	switch strings.ToLower(strings.TrimSpace(scalarString(raw))) {
	case "open":
		return PositionOpen
	case "close", "closed":
		return PositionClosed
	case "none":
		return PositionNone
	}
	return PositionUnknown
}

// remainUnlock is Access's stay-unlocked mode.
type remainUnlock struct {
	State json.RawMessage `json:"state"`
	Until json.Number     `json:"until"`
	Type  string          `json:"type"`
}

// held reports whether a remain_unlock block means the door is being held open,
// and whether that could be determined at all.
//
// The value set of `state` has never been captured from hardware. So the two
// readings we have seen are honoured, the obvious negatives are honoured, and
// anything else returns known=false rather than being guessed into one bucket
// -- a guess here either raises a permanent unclearable incident or hides a
// door that has been left open.
func (r *remainUnlock) held() (held, known bool) {
	if r == nil {
		// An ABSENT block is the console not reporting the mode, which means
		// the door is not in it. Deliberately the opposite reading from
		// parseRESTLock, where an absent field is unknown rather than locked --
		// and the asymmetry is the point. There, the missing field IS the
		// door's security state and guessing it reports security on no
		// evidence. Here it is an optional sub-object that shape B omits on
		// ordinary frames, so reading absence as "unknown" would classify
		// almost every message as unrecognised and bury the real unknowns.
		return false, true
	}
	switch strings.ToLower(strings.TrimSpace(scalarString(r.State))) {
	case "unlock", "unlocked":
		return true, true
	case "", "lock", "locked", "none", "off":
		return false, true
	}
	return false, false
}

// notification is one frame from the notifications WebSocket.
//
// Two shapes have ever been captured, both from one hub model on one day, so
// this decodes both and counts anything else as unrecognised rather than
// treating the pair as the complete vocabulary (SOURCES.md section 2).
type notification struct {
	Event string `json:"event"`
	Data  struct {
		// Shape A: the door is the subject.
		ID    string `json:"id"`
		Name  string `json:"name"`
		State *struct {
			Lock         json.RawMessage `json:"lock"`
			RemainUnlock *remainUnlock   `json:"remain_unlock"`
		} `json:"state"`

		// Shape B: the DEVICE is the subject and carries a door per entry.
		// These entries have no name at all -- naming a door after the hub
		// that serves it would put the wrong label on an alert, so the name
		// comes from the door list instead.
		LocationStates []struct {
			LocationID   string          `json:"location_id"`
			Lock         json.RawMessage `json:"lock"`
			RemainUnlock *remainUnlock   `json:"remain_unlock"`
		} `json:"location_states"`
	} `json:"data"`
}

// lockReport is one door's state as a notification described it.
type lockReport struct {
	DoorID string
	Name   string
	Lock   LockState
	Held   bool
	Known  bool
}

// states flattens either notification shape into a list of door reports.
func (n notification) states() []lockReport {
	var out []lockReport
	if n.Data.ID != "" && n.Data.State != nil {
		held, known := n.Data.State.RemainUnlock.held()
		out = append(out, lockReport{
			DoorID: n.Data.ID, Name: strings.TrimSpace(n.Data.Name),
			Lock: parseSocketLock(n.Data.State.Lock), Held: held, Known: known,
		})
	}
	for _, ls := range n.Data.LocationStates {
		if ls.LocationID == "" {
			continue
		}
		held, known := ls.RemainUnlock.held()
		out = append(out, lockReport{
			DoorID: ls.LocationID,
			Lock:   parseSocketLock(ls.Lock), Held: held, Known: known,
		})
	}
	return out
}

// Log topics. Only door_openings and admin_activity carry a human actor;
// device_events is actored by the hub and cannot be attributed to a person.
const (
	topicDoorOpenings  = "door_openings"
	topicAdminActivity = "admin_activity"
	topicDeviceEvents  = "device_events"
	topicCritical      = "critical"
)

// logHit is one row of the system log.
//
// `_id` and `@timestamp` are SIBLINGS of `_source`, not fields inside it.
type logHit struct {
	ID        string    `json:"_id"`
	Timestamp string    `json:"@timestamp"`
	Source    logSource `json:"_source"`
}

type logSource struct {
	Actor logActor `json:"actor"`
	Event struct {
		Type           string      `json:"type"`
		LogKey         string      `json:"log_key"`
		DisplayMessage string      `json:"display_message"`
		Published      json.Number `json:"published"`
	} `json:"event"`

	// Target is POLYMORPHIC: an array on most rows and a single object on
	// others. Decoded raw and resolved by targets().
	Target json.RawMessage `json:"target"`

	Authentication struct {
		CredentialProvider string `json:"credential_provider"`
	} `json:"authentication"`
}

type logActor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
}

// isPerson reports whether an actor is a human rather than a hub.
//
// Decided on TYPE and ID SHAPE, never on the display name: hubs have display
// names too, and they are frequently named after the door they serve, so a
// name test attributes a hardware event to a person who was not there.
func (a logActor) isPerson() bool {
	if strings.EqualFold(a.Type, "user") {
		return true
	}
	return len(a.ID) == 36 && strings.Count(a.ID, "-") == 4
}

// who renders the actor for an alert, without claiming more than is known.
func (a logActor) who() string {
	n := strings.TrimSpace(a.DisplayName)
	if n == "" || n == "N/A" {
		// "N/A" is the console saying the credential did not resolve to
		// anybody -- which on a denial is the most important fact in the row,
		// so it is reported as itself rather than blanked.
		return "an unidentified credential"
	}
	return n
}

type logTarget struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
}

// targets decodes the polymorphic target field.
func (s logSource) targets() []logTarget {
	t := strings.TrimSpace(string(s.Target))
	if t == "" || t == "null" {
		return nil
	}
	var many []logTarget
	if err := json.Unmarshal(s.Target, &many); err == nil {
		return many
	}
	var one logTarget
	if err := json.Unmarshal(s.Target, &one); err == nil {
		return []logTarget{one}
	}
	return nil
}

// door finds the door among the targets BY TYPE, never by position.
//
// The door is the sixth element on an unlock row and the second on a
// door-position row. Indexing would attribute half of these events to whatever
// happened to sit in that slot -- a reader, a user, a policy.
func (s logSource) door() (logTarget, bool) {
	for _, t := range s.targets() {
		if strings.EqualFold(t.Type, "door") {
			return t, true
		}
	}
	return logTarget{}, false
}

// at returns when the row says it happened, and whether that was knowable.
//
// `@timestamp` is RFC3339 and some firmwares omit it entirely; `event.published`
// is UNIX MILLISECONDS -- inverted from the SECONDS the query takes, which is
// the console's inconsistency and not a transcription error. When neither is
// readable the caller stamps arrival and says so, because presenting an
// arrival time as an observation time sends somebody to the wrong footage.
func (h logHit) at() (time.Time, bool) {
	if s := strings.TrimSpace(h.Timestamp); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC(), true
		}
	}
	if ms, err := h.Source.Event.Published.Int64(); err == nil && ms > 0 {
		return time.UnixMilli(ms).UTC(), true
	}
	return time.Time{}, false
}
