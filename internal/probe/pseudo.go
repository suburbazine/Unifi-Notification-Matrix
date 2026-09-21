package probe

import (
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Pseudonymiser replaces identifying values with stable, meaningless labels.
//
// THIS IS THE PART THAT MAKES A SUBMISSION SAFE TO PUBLISH. A raw probe of a
// UniFi console is a map of somebody's building: camera names are room names,
// door names are door names, and the MACs, ids and addresses beside them
// identify the site and its hardware. What a schema contribution actually
// needs is shapes and vocabulary -- field names, types, enum values, which
// endpoints exist at which firmware -- and none of that requires a real name.
//
// Three decisions hold the whole thing up:
//
//  1. IT IS AN ALLOWLIST, NOT A DENYLIST. Every string is replaced unless
//     something specific says to keep it. A denylist ("redact fields called
//     name, mac, email...") fails on the field nobody anticipated -- and
//     finding fields nobody anticipated is the entire purpose of a probe. The
//     failure mode of an allowlist is a less informative report; the failure
//     mode of a denylist is a published address book.
//
//  2. PSEUDONYMS ARE COUNTERS, NOT HASHES. A hash of a MAC is not an
//     anonymisation: the MAC space is small and camera names come from a small
//     dictionary, so a hash of either is recoverable by brute force in
//     seconds. A counter discloses nothing, because there is nothing to grind.
//
//  3. THEY DO NOT SURVIVE THE REPORT. Counters restart for every report, so
//     two submissions from one site share no label and cannot be linked to
//     each other. Within a report the mapping is stable, which preserves the
//     genuinely useful fact that two fields held the same value.
type Pseudonymiser struct {
	mu   sync.Mutex
	seen map[string]string
	next map[string]int
}

// NewPseudonymiser returns a Pseudonymiser with fresh counters.
//
// Fresh is load-bearing -- see the type comment. Reusing one across reports
// would make labels correlatable between submissions, which is the property
// this exists to deny.
func NewPseudonymiser() *Pseudonymiser {
	return &Pseudonymiser{seen: map[string]string{}, next: map[string]int{}}
}

// vocabulary are the field names whose values ARE the thing being collected.
//
// An event type, a model key, a connection state: these are the vocabulary a
// capability report exists to record. They are chosen by Ubiquiti rather than
// by the operator, and they name no person, room or device. Everything absent
// from this list is replaced, including fields that look harmless today,
// because the next firmware revision invents one that is not.
//
// `name` is deliberately absent, and is the reason this list stays short.
var vocabulary = map[string]bool{
	"type": true, "eventtype": true, "event_type": true, "event": true,
	"subtype": true, "modelkey": true, "model": true, "model_name": true,
	"devicetype": true, "device_type": true, "kind": true, "class": true,
	"category": true, "state": true, "status": true, "action": true,
	"trigger": true, "alarmtype": true, "alarm_type": true,
	"severity": true, "level": true, "mode": true, "protocol": true,
	"unit": true, "method": true, "version": true, "firmwareversion": true,
	"firmware_version": true, "applicationversion": true,
	"apiversion": true, "api_version": true, "releasechannel": true,
	"schema": true,
	// The detection vocabulary arrives under four names on one camera record:
	// featureFlags.smartDetectTypes, featureFlags.smartDetectAudioTypes,
	// smartDetectSettings.objectTypes and smartDetectSettings.audioTypes. They
	// hold the same terms, and listing only the first made a report disagree
	// with itself -- "person" published under one name and replaced with a
	// counter under another. These terms are the enum the rule engine keys
	// on, which is most of what a schema contribution is for.
	"smartdetecttypes": true, "smart_detect_types": true,
	"smartdetectaudiotypes": true, "smart_detect_audio_types": true,
	"objecttypes": true, "object_types": true,
	"audiotypes": true, "audio_types": true,

	// UniFi Access speaks in whole-word field names rather than nested ones,
	// so the two enums its door logic turns on are single tokens and were
	// being replaced with counters: a report of 28 doors carried neither the
	// position vocabulary nor the lock vocabulary, which is most of what a
	// door schema is for.
	"door_position_status": true, "door_lock_relay_status": true,
	"position_status": true, "lock_relay_status": true,

	// And what a reader or hub says it can do. One site's report carried 89
	// distinct capability strings, every one of them a counter -- the single
	// richest piece of vocabulary any probe has produced, thrown away.
	"capabilities": true,

	// Two-segment entries, matched against parent.child. `text` on its own is
	// NOT here and must not be: Network's Alarm Manager spells its free-prose
	// message field `text` on some firmware, and that prose names doors and
	// rooms. Under alarmType it is the term that decides smoke from CO from
	// glass break, which is the difference between a critical incident and a
	// medium one. Same word, opposite handling, so the parent decides.
	"alarmtype.text": true, "alarmtype.name": true,
}

// vocabularyCap and vocabularyWords bound a kept value.
//
// A term chosen by Ubiquiti is short and is at most a few words:
// "smartDetectZone", "CONNECTED", "UVC G6 PTZ". Prose about a specific site --
// "Front Door forced open by Jane" -- is longer and wordier, and the word
// count is what separates them, because the length cap alone lets a short
// sentence through.
//
// `code`, `reason` and `result` were on the allowlist and were removed rather
// than bounded. `code` can be a door PIN, and the other two carry prose that
// names doors and people far more often than they carry an enum. A field whose
// values are usually safe is not a field whose values may be published.
const (
	vocabularyCap   = 64
	vocabularyWords = 4
)

var (
	// Two alternatives rather than a backreference on the separator: Go's
	// regexp is RE2, which has none. MustCompile panics at init, in a package
	// the daemon links -- so getting this wrong takes the SERVICE down at
	// startup, not merely the probe.
	macSeparated = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$|^(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$`)
	macBare      = regexp.MustCompile(`^[0-9A-Fa-f]{12}$`)
	uuidRe       = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	hexIDRe      = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	emailRe      = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	tokenRe      = regexp.MustCompile(`^[A-Za-z0-9+/=_.-]{32,}$`)
)

// category names the kind of thing a value is, so a report reads as
// "<mac-2> went offline" rather than as undifferentiated noise.
//
// It is a labelling aid and nothing more. Every category is replaced; none of
// them is a decision about whether to keep something.
func category(s string) string {
	switch {
	case macSeparated.MatchString(s), macBare.MatchString(s):
		return "mac"
	case uuidRe.MatchString(s):
		return "uuid"
	case net.ParseIP(s) != nil:
		return "ip"
	case emailRe.MatchString(s):
		return "email"
	case strings.Contains(s, "://"):
		return "url"
	case hexIDRe.MatchString(s):
		return "id"
	case tokenRe.MatchString(s):
		// Long opaque strings are credentials far more often than prose, and a
		// credential is the one class where a leak is immediately exploitable
		// rather than merely identifying.
		return "token"
	}
	return "text"
}

// identityShaped reports whether a value carries identity regardless of the
// field it arrived in.
//
// Applied to vocabulary fields too: a console that returns a serial number in
// a field called `model` must not have it published merely because the field
// name was on a list. A name is evidence about a value, never proof.
func identityShaped(s string) bool { return category(s) != "text" }

// normalise collapses spellings of one value so they share a single label.
//
// A MAC appears as "AA:BB:CC:DD:EE:FF" on one surface and "aabbccddeeff" on
// another; labelling those separately would report two devices where the
// console has one, which misdescribes the console in the direction of noise.
func normalise(s string) string {
	if macSeparated.MatchString(s) || macBare.MatchString(s) {
		r := strings.NewReplacer(":", "", "-", "")
		return "mac:" + strings.ToLower(r.Replace(s))
	}
	return s
}

// Value returns the label for a string, allocating one on first sight.
func (p *Pseudonymiser) Value(s string) string {
	if s == "" {
		return ""
	}
	key := normalise(s)

	p.mu.Lock()
	defer p.mu.Unlock()
	if got, ok := p.seen[key]; ok {
		return got
	}
	cat := category(s)
	p.next[cat]++
	label := "<" + cat + "-" + strconv.Itoa(p.next[cat]) + ">"
	p.seen[key] = label
	return label
}

// String applies the allowlist: a value survives only if its field name is
// vocabulary, it is short, and it is not itself identity-shaped.
func (p *Pseudonymiser) String(key, s string) string {
	if s == "" {
		return ""
	}
	if isVocabulary(key) && publishableTerm(s) {
		return s
	}
	return p.Value(s)
}

// publishableTerm reports whether a value is shaped like a vocabulary term
// rather than like data that happened to land in a vocabulary field.
func publishableTerm(s string) bool {
	if len(s) > vocabularyCap || identityShaped(s) {
		return false
	}
	return len(strings.Fields(s)) <= vocabularyWords
}

// isVocabulary reports whether a field is one whose values may be published.
//
// The full parent.child path is tried before the bare field name, so a term
// can be allowed in one parent and refused everywhere else.
func isVocabulary(path string) bool {
	lower := strings.ToLower(path)
	if vocabulary[lower] {
		return true
	}
	if i := strings.LastIndex(lower, "."); i >= 0 {
		return vocabulary[lower[i+1:]]
	}
	return false
}

// childPath is the parent.child key handed to a nested value.
//
// Only one level of parent is carried. A full path would make every rule
// depend on where a field sits in a document, and these payloads nest the same
// object at several depths.
func childPath(parent, key string) string {
	if parent == "" {
		return key
	}
	if i := strings.LastIndex(parent, "."); i >= 0 {
		parent = parent[i+1:]
	}
	return parent + "." + key
}

// maxSmallInt bounds the integers kept verbatim.
//
// Small non-negative integers are enum ordinals, counts, ports and indices --
// schema facts with no identity in them. Anything larger is a timestamp, a
// coordinate, a byte count or a numeric id, which are either identifying or
// worthless in a schema report. 4096 clears the port range; it is a judgement
// rather than a measurement, and it errs by keeping less than it safely could.
const maxSmallInt = 4096

// JSON walks a decoded document and returns one with the same shape and none
// of the identifying content.
//
// Structure, key names, nesting and array lengths survive exactly, because
// those ARE the schema. Leaves do not.
func (p *Pseudonymiser) JSON(key string, v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, sub := range t {
			// A map KEYED by device id is a real shape on these consoles, and
			// a redactor that walks only values publishes every id as a key.
			outKey := k
			if identityShaped(k) {
				outKey = p.Value(k)
			}
			out[outKey] = p.JSON(childPath(key, k), sub)
		}
		return out

	case []any:
		out := make([]any, len(t))
		for i, sub := range t {
			out[i] = p.JSON(key, sub)
		}
		return out

	case string:
		return p.String(key, t)

	case json.Number:
		return p.number(t.String())

	case float64:
		return p.float(t)

	case bool, nil:
		// Two values and no value respectively. Nothing to identify.
		return v
	}
	// An unmodelled type cannot be reasoned about, so it is described rather
	// than reproduced.
	return "<value>"
}

func (p *Pseudonymiser) float(f float64) any {
	if f != float64(int64(f)) {
		// Non-integers are coordinates, temperatures and rates. Kept as a type
		// and not a value, because a latitude is a building's address.
		return "<float>"
	}
	return p.number(strconv.FormatInt(int64(f), 10))
}

func (p *Pseudonymiser) number(s string) any {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if _, ferr := strconv.ParseFloat(s, 64); ferr == nil {
			// Non-integers are coordinates, temperatures and rates. Reported
			// as a type and not a value, because a latitude is an address.
			return "<float>"
		}
		return "<number>"
	}
	switch {
	case n >= 0 && n < maxSmallInt:
		return n
	case n >= 1_000_000_000 && n < 4_000_000_000:
		// Seconds since the epoch: roughly 2001 to 2096. Reported as a class,
		// because when something happened at a site is exactly the kind of
		// fact a published submission must not carry.
		return "<epoch_s>"
	case n >= 1_000_000_000_000 && n < 4_000_000_000_000:
		return "<epoch_ms>"
	}
	return "<number>"
}

// URL renders a URL with its identifying parts gone and its SHAPE intact,
// because which endpoint exists is the finding and the path is how it is
// named.
//
// Path segments that look like ids are labelled rather than dropped, so
// /cameras/<id-3>/snapshot still reads as a route.
func (p *Pseudonymiser) URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if s != "" && identityShaped(s) {
			segs[i] = p.Value(s)
		}
	}
	out := url.URL{Scheme: u.Scheme, Host: "<console>", Path: strings.Join(segs, "/")}
	s := out.String()
	if u.RawQuery != "" {
		// Query VALUES go wholesale rather than being labelled: Protect's
		// snapshot and stream URLs carry a token in the query that is all
		// anyone on the network needs to watch a camera, and the parameter
		// NAMES are the only part of a query worth reporting anyway.
		keys := make([]string, 0, 4)
		for k := range u.Query() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		s += "?" + strings.Join(keys, "&") + "="
	}
	return s
}
