package probe

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// answeredJSON says this endpoint answered as an API, rather than a web
// server answering on its behalf.
//
// A 200 IS NOT AN ANSWER. A console with no key issued serves its login page
// on the same paths, with the same 200, and only the body tells them apart --
// which is how four copies of a 1513-byte HTML page were once written up as
// four undocumented endpoints. The status line is the part an unauthenticated
// probe can least afford to believe.
func answeredJSON(e EndpointResult) bool {
	if e.Error != "" || e.Refused != "" || e.Status != 200 {
		return false
	}
	return strings.Contains(strings.ToLower(e.ContentType), "json")
}

// Authenticated reports whether anything in this run got past the front door.
//
// Everything else in a report is a claim about a console. From a run that was
// refused, every one of those claims is really a statement about this build's
// own catalogue, which the reader already has. So this is the question that
// decides whether the file is worth anything at all.
func (r *Report) Authenticated() bool {
	for _, e := range r.Endpoints {
		if answeredJSON(e) {
			return true
		}
	}
	return len(r.Meta.Versions) > 0
}

// FileSummary is what a written report can say about itself without being
// loaded in full.
type FileSummary struct {
	// Authenticated is the question that decides whether the file is worth
	// anything: did anything in the run get past the front door.
	Authenticated bool

	Findings int
	Versions map[string]string
}

// ScanFile reads a written report and summarises it.
//
// Read back from the file rather than carried out of the run that produced
// it: a report on disk outlives the process that wrote it, and the file is
// what would actually be published.
//
// Unparseable lines are skipped rather than fatal. A truncated submission
// should still be judged on the records that survived -- the same reason the
// format is JSONL.
func ScanFile(rd io.Reader) (FileSummary, error) {
	var out FileSummary
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var head struct {
			Record string `json:"record"`
		}
		if json.Unmarshal([]byte(line), &head) != nil {
			continue
		}
		switch head.Record {
		case "endpoint":
			var e EndpointResult
			if json.Unmarshal([]byte(line), &e) == nil && answeredJSON(e) {
				out.Authenticated = true
			}
		case "finding":
			out.Findings++
		case "meta":
			var m Meta
			if json.Unmarshal([]byte(line), &m) == nil && len(m.Versions) > 0 {
				out.Versions = m.Versions
				out.Authenticated = true
			}
		}
	}
	return out, sc.Err()
}

// ScanAuthenticated answers the one question submit asks.
func ScanAuthenticated(rd io.Reader) (bool, error) {
	sum, err := ScanFile(rd)
	return sum.Authenticated, err
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
	// FIRST, because it changes the meaning of every line under it. Without
	// it an operator reads a page of paths and statuses as a survey of their
	// firmware, when it is a list of what this build went looking for.
	if !r.Authenticated() {
		fmt.Fprintln(w, "THIS RUN WAS NOT AUTHENTICATED -- nothing below describes your console.")
		fmt.Fprintln(w, "Nothing came back as an API answer: requests were refused, or the")
		fmt.Fprintln(w, "console did not answer at all. What follows is what this build went")
		fmt.Fprintln(w, "looking for, not what your firmware has. Check the host, issue an API")
		fmt.Fprintln(w, "key for each product you want surveyed, and run it again.")
		fmt.Fprintln(w)
	}

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
			if answeredJSON(e) && !e.Known {
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
