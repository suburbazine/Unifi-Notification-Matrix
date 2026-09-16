package probe

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SchemaVersion is the format of a submitted report.
//
// Carried in the file because submissions outlive the build that wrote them:
// a maintainer reading a contribution in a year needs to know which rules
// produced it, particularly which redaction rules.
const SchemaVersion = 1

// Meta is the first record of every report.
type Meta struct {
	Record        string `json:"record"`
	SchemaVersion int    `json:"schema_version"`
	ProbeVersion  string `json:"probe_version"`
	GeneratedAt   string `json:"generated_at"`

	// Versions is the firmware this report describes, per product. THE
	// PAYLOAD. A report that cannot say which console produced a shape is not
	// worth having, which is why these are the identifying facts kept on
	// purpose while everything else goes.
	Versions map[string]string `json:"versions"`

	// Redaction states what was applied, so a submission can be audited
	// without reading this source.
	Redaction string `json:"redaction"`
}

// Finding is a difference between what this build knows and what the console
// actually did.
type Finding struct {
	Record  string `json:"record"`
	Kind    string `json:"kind"`
	Product string `json:"product"`
	Detail  string `json:"detail"`
	Note    string `json:"note,omitempty"`
}

// Report is everything one probe run produced.
type Report struct {
	Meta      Meta
	Endpoints []EndpointResult
	Streams   []StreamResult
	Findings  []Finding
}

// Write emits the report as JSONL: one record per line.
//
// JSONL rather than one object, for the same reason the audit log is: a
// maintainer receiving contributions can grep, count and concatenate them with
// no tooling, and a submission truncated in transit still parses up to the
// break instead of becoming unreadable in its entirety.
func (r *Report) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	// HTML escaping off. It is on by default, and with it on, every pseudonym
	// renders as a pair of six-character unicode escapes instead of the angle
	// brackets they were written with -- which makes a file whose whole
	// purpose is to be read and grepped by a person hard to do either with.
	// Nothing here is ever interpolated into a page.
	enc.SetEscapeHTML(false)
	// Indentation is off deliberately: one record per line is the format's
	// whole value, and a pretty-printer would silently destroy it.
	if err := enc.Encode(r.Meta); err != nil {
		return err
	}
	for _, e := range r.Endpoints {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	for _, s := range r.Streams {
		if err := enc.Encode(s); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// Save writes the report to path, creating parent directories.
//
// 0600, and the reason is not the file's content -- which is redacted -- but
// the habit. A tool that writes probe output world-readable teaches operators
// that probe output is safe to leave lying around, and the next version of it
// might not be.
func (r *Report) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("probe: creating %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("probe: writing %s: %w", path, err)
	}
	defer f.Close()
	if err := r.Write(f); err != nil {
		return fmt.Errorf("probe: writing %s: %w", path, err)
	}
	return f.Sync()
}

// DefaultPath is where a report lands when the operator names no file.
func DefaultPath(dir string) string {
	return filepath.Join(dir, "probe-"+time.Now().UTC().Format("20060102T150405Z")+".jsonl")
}

// Summarise renders the human-readable digest printed after a run.
//
// Deliberately NOT the submission file. The operator is told to read the
// actual bytes before contributing anything, and a summary that looked
// complete enough to trust would quietly replace that step.
func (r *Report) Summarise(w io.Writer) {
	fmt.Fprintf(w, "console versions: ")
	if len(r.Meta.Versions) == 0 {
		fmt.Fprintln(w, "none identified")
	} else {
		keys := make([]string, 0, len(r.Meta.Versions))
		for k := range r.Meta.Versions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				fmt.Fprint(w, ", ")
			}
			fmt.Fprintf(w, "%s %s", k, r.Meta.Versions[k])
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "\nendpoints")
	for _, e := range r.Endpoints {
		switch {
		case e.Refused != "":
			fmt.Fprintf(w, "  skip  %-58s %s\n", e.Path, e.Refused)
		case e.Error != "":
			fmt.Fprintf(w, "  err   %-58s %s\n", e.Path, e.Error)
		default:
			mark := "     "
			if e.Status == 200 && !e.Known {
				// The discovery: a path this build does not use, answering.
				mark = "  NEW"
			}
			if e.Status == 404 && e.Known {
				// The regression: a path this build depends on, gone.
				mark = " GONE"
			}
			fmt.Fprintf(w, "%s %3d  %s\n", mark, e.Status, e.Path)
		}
	}

	fmt.Fprintln(w, "\nstreams")
	for _, s := range r.Streams {
		fmt.Fprintf(w, "  %s/%s: %s -- %d message(s), %d type(s)\n",
			s.Product, s.Name, s.Status, s.Messages, len(s.TypeNames))
		for _, t := range s.TypeNames {
			fmt.Fprintf(w, "      %-48s %d\n", t, s.Types[t].Count)
		}
	}

	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "\nfindings")
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  [%s] %s: %s\n", f.Kind, f.Product, f.Detail)
			if f.Note != "" {
				fmt.Fprintf(w, "        %s\n", f.Note)
			}
		}
	}
}
