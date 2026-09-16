package probe

import (
	"encoding/json"
	"sort"
	"strconv"
)

// Schema is the accumulated shape of everything a probe saw at one surface.
//
// THIS, NOT THE SAMPLES, IS THE PAYLOAD OF A CAPABILITY REPORT. A maintainer
// deciding whether this product handles a firmware needs to know which fields
// exist, what types they hold, and which vocabulary terms appear -- and a
// summary answers that across every message, where a handful of samples
// answers it only for the handful.
//
// It also degrades well. When a field's values are pseudonymised the summary
// still reports that the field exists, what type it is, and HOW MANY distinct
// values were seen -- so an unrecognised field with four distinct values reads
// as "probably an enum worth asking about" even though none of the four can be
// published.
type Schema struct {
	// Fields is keyed by dotted path, with [] marking a step through an array:
	// "item.smartDetectTypes[]".
	Fields map[string]*Field `json:"fields"`
}

// Field is what was observed at one path.
type Field struct {
	// Types are the JSON types seen here, sorted. More than one is itself a
	// finding: a field that is a string on one firmware and an array on
	// another is the exact trap that silently drops messages.
	Types []string `json:"types"`

	// Count is how many times this path appeared across all records.
	Count int `json:"count"`

	// Distinct is how many different values were seen, counting pseudonyms.
	// Reported even when no value can be published, because cardinality
	// distinguishes an enum from free text without disclosing either.
	Distinct int `json:"distinct"`

	// Values are the values that survived pseudonymisation -- vocabulary terms
	// and small integers. Sorted, capped, and frequently empty.
	Values []string `json:"values,omitempty"`

	// Truncated marks a field whose distinct values outran the cap, so a
	// reader does not mistake a sample of the vocabulary for all of it.
	Truncated bool `json:"truncated,omitempty"`

	seen map[string]bool
	kept map[string]bool
}

// Caps. A report is read by a person and stored in a repository; an
// unrecognised payload with thousands of generated keys must not be able to
// turn either into something unusable.
const (
	maxValuesPerField = 24
	maxFields         = 2000
	maxDepth          = 12
)

// NewSchema returns an empty accumulator.
func NewSchema() *Schema { return &Schema{Fields: map[string]*Field{}} }

// Observe folds one ALREADY-PSEUDONYMISED document into the summary.
//
// Already-pseudonymised is a precondition, not a preference: this records
// distinct values, so handing it raw data would build a list of real camera
// names and put it in the report. Callers run Pseudonymiser.JSON first, and
// captureJSON is the only path that does both in the right order.
func (s *Schema) Observe(v any) { s.walk("", v, 0) }

func (s *Schema) walk(path string, v any, depth int) {
	if depth > maxDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		s.note(path, "object", "")
		for k, sub := range t {
			s.walk(join(path, k), sub, depth+1)
		}
	case []any:
		s.note(path, "array", "")
		for _, sub := range t {
			// Every element folds into ONE path. An array of forty cameras
			// describes one shape forty times, and reporting it as forty paths
			// would bury the schema in indices.
			s.walk(path+"[]", sub, depth+1)
		}
	case string:
		s.note(path, "string", t)
	case bool:
		s.note(path, "bool", boolString(t))
	case json.Number:
		s.note(path, "number", t.String())
	case float64:
		s.note(path, "number", strconv.FormatFloat(t, 'g', -1, 64))
	case int64:
		s.note(path, "number", strconv.FormatInt(t, 10))
	case nil:
		s.note(path, "null", "")
	default:
		s.note(path, "unknown", "")
	}
}

func (s *Schema) note(path, typ, value string) {
	if path == "" {
		path = "."
	}
	f, ok := s.Fields[path]
	if !ok {
		if len(s.Fields) >= maxFields {
			return
		}
		f = &Field{seen: map[string]bool{}, kept: map[string]bool{}}
		s.Fields[path] = f
	}
	f.Count++
	if !containsString(f.Types, typ) {
		f.Types = append(f.Types, typ)
		sort.Strings(f.Types)
	}
	if typ == "object" || typ == "array" || typ == "null" {
		return
	}
	if !f.seen[value] {
		f.seen[value] = true
		f.Distinct++
	}
	// A pseudonym is a label this package minted, so publishing it would say
	// only "there was a value here" -- which Distinct already says, more
	// honestly and without implying the label means something.
	if isPseudonym(value) {
		return
	}
	if f.kept[value] {
		return
	}
	if len(f.kept) >= maxValuesPerField {
		f.Truncated = true
		return
	}
	f.kept[value] = true
	f.Values = append(f.Values, value)
	sort.Strings(f.Values)
}

// isPseudonym reports whether a value is a label this package minted rather
// than something the console said.
func isPseudonym(v string) bool {
	return len(v) >= 2 && v[0] == '<' && v[len(v)-1] == '>'
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func containsString(in []string, s string) bool {
	for _, v := range in {
		if v == s {
			return true
		}
	}
	return false
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
