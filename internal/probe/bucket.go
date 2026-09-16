package probe

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// samplesPerType is how many message bodies are kept for each distinct type.
//
// Three, not one: the second and third are what show which fields are
// optional. Not thirty: the Schema summary already covers every message, so
// extra samples add bytes a human must read without adding facts.
const samplesPerType = 3

// Buckets groups captured messages by type, counting every message but
// sampling each type separately.
//
// THIS IS THE DESIGN THAT DECIDES WHETHER A CAPTURE PROBE WORKS AT ALL. These
// sockets are dominated by repeated state-sync traffic, so a flat capture of
// the first N messages fills entirely with those and crowds out the rare class
// being probed for -- an earlier in-house capture hit a flat 50-message cap on
// exactly that spam, and the "only two Access message shapes exist" finding in
// SOURCES.md may be an artifact of it rather than a fact about the hardware.
// Counting every message while storing only the first samples of EACH type
// makes a one-in-a-thousand type impossible to miss.
type Buckets struct {
	p *Pseudonymiser

	total      int
	unreadable int
	dropped    int
	byType     map[string]*Bucket
}

// Bucket is everything retained about one message type.
type Bucket struct {
	// Count is every message of this type, whether or not it was sampled.
	// Kept separate from the samples so a type seen 4000 times and a type seen
	// once are distinguishable after both have contributed three samples.
	Count int `json:"count"`

	// Samples are redacted message bodies, structure intact.
	Samples []any `json:"samples,omitempty"`

	// Fields is the shape summary across ALL messages of this type, not only
	// the sampled ones.
	Fields *Schema `json:"schema"`
}

// NewBuckets returns an empty capture keyed through p.
func NewBuckets(p *Pseudonymiser) *Buckets {
	return &Buckets{p: p, byType: map[string]*Bucket{}}
}

// discriminators are the paths consulted to decide what a message IS, in the
// order they are tried, with every one that is present contributing.
//
// A COMPOSITE, not a single field, and that is not a refinement. Protect's
// envelope carries a frame verb ("add", "update") at the top level and the
// actual event type underneath at item.type; bucketing on the top level alone
// would collapse every event into two buckets and reproduce exactly the
// crowding-out this file exists to prevent. Access puts its type in a
// top-level `event`. One rule covers both without either product's parser.
var discriminators = [][]string{
	{"event"},
	{"type"},
	{"item", "type"},
	{"item", "modelKey"},
	{"data", "type"},
	{"data", "event_type"},
	{"alarm", "name"},
}

// discriminate builds the bucket key for a decoded message.
func discriminate(doc map[string]any) string {
	var buf bytes.Buffer
	for _, path := range discriminators {
		v, ok := lookup(doc, path)
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" || len(s) > vocabularyCap {
			continue
		}
		if identityShaped(s) {
			// A discriminator that is an id is not a type -- it is the device.
			// Bucketing on it produces one bucket per device, which is the
			// same failure as one bucket for everything, arrived at from the
			// opposite direction.
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('|')
		}
		buf.WriteString(strings.Join(path, "."))
		buf.WriteByte('=')
		buf.WriteString(s)
	}
	if buf.Len() == 0 {
		// Not a failure to report as an error: a message with no recognisable
		// type field is itself a finding, and it needs somewhere to go or it
		// is silently discarded.
		return "<no-type>"
	}
	return buf.String()
}

func lookup(doc map[string]any, path []string) (any, bool) {
	var cur any = doc
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// maxBucketTypes bounds how many distinct types are tracked, so a console that
// puts something unique in a discriminator field cannot exhaust memory during
// an unattended capture.
const maxBucketTypes = 512

// Observe folds one raw frame in.
//
// Redaction happens HERE, before anything is retained. There is no path in
// this package that stores a raw frame and redacts later, because a report
// written from a crash dump, a debugger or a future refactor would then carry
// real data. The raw bytes are readable only inside this function.
func (b *Buckets) Observe(raw []byte) {
	b.total++

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		// A frame that is not JSON is a finding -- a binary channel nobody
		// documented -- so it is counted. Its CONTENT is not kept: a thing we
		// cannot parse is a thing we cannot redact.
		b.unreadable++
		return
	}

	key := "<no-type>"
	if m, ok := doc.(map[string]any); ok {
		key = discriminate(m)
	} else {
		// A bare array or scalar at the top level is a shape worth recording.
		key = "<not-an-object>"
	}

	bkt, ok := b.byType[key]
	if !ok {
		if len(b.byType) >= maxBucketTypes {
			b.dropped++
			return
		}
		bkt = &Bucket{Fields: NewSchema()}
		b.byType[key] = bkt
	}
	bkt.Count++

	clean := b.p.JSON("", doc)
	bkt.Fields.Observe(clean)
	if len(bkt.Samples) < samplesPerType {
		bkt.Samples = append(bkt.Samples, clean)
	}
}

// Total is every message seen, including ones no sample was kept for.
func (b *Buckets) Total() int { return b.total }

// Unreadable is messages that would not decode as JSON.
func (b *Buckets) Unreadable() int { return b.unreadable }

// Dropped is messages discarded because the type cap was reached.
func (b *Buckets) Dropped() int { return b.dropped }

// Types returns the bucket keys, sorted, so two reports of the same console
// diff cleanly.
func (b *Buckets) Types() []string {
	out := make([]string, 0, len(b.byType))
	for k := range b.byType {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Bucket returns one type's capture.
func (b *Buckets) Bucket(key string) *Bucket { return b.byType[key] }

// All returns every bucket keyed by type.
func (b *Buckets) All() map[string]*Bucket { return b.byType }
