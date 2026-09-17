package event

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite docs/CONDITIONS.md from the catalogue")

// docs/CONDITIONS.md IS GENERATED, and this test is what keeps it true.
//
// A hand-written reference for a vocabulary that lives in code drifts, and a
// reference that is quietly wrong is worse than none: an operator writes a
// rule against a condition that does not exist, it never matches, and nothing
// tells them. The config file's own header already made this exact mistake --
// it documented email recipients under a field name that does not exist.
//
// So the file is rendered from the catalogue and compared. To update it:
//
//	go test ./internal/event/ -run TestTheConditionReference -update
func TestTheConditionReferenceMatchesTheCatalogue(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "CONDITIONS.md")
	want := renderConditionDoc()

	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("wrote", path)
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v\n\nRegenerate it with:\n"+
			"  go test ./internal/event/ -run TestTheConditionReference -update", err)
	}
	if normalise(string(got)) != normalise(want) {
		t.Errorf("docs/CONDITIONS.md no longer matches the catalogue.\n" +
			"Regenerate it with:\n" +
			"  go test ./internal/event/ -run TestTheConditionReference -update")
	}
}

func normalise(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n")
}

// renderConditionDoc writes the operator-facing reference.
func renderConditionDoc() string {
	var b strings.Builder

	b.WriteString(`# Conditions: what this can tell you about

**Generated from the code.** Do not edit by hand -- run
` + "`go test ./internal/event/ -run TestTheConditionReference -update`" + `.

A *condition* is what happened, normalised. It is the thing a rule matches on,
and the interface offers this list in the Rules editor so nobody has to guess
at it or wait for an event to fire and read it out of the log.

## What this list is, and what it is not

**It is** every condition a rule can match. Rules match this build's
vocabulary, and this is all of it.

**It is not** everything your UniFi might send. Firmware emits event types this
build does not map; those are counted as unrecognised rather than becoming a
condition, and they are exactly what gets added in a later release. To ask your
own console what it actually exposes:

` + "```bash\nnotifymatrix probe\n```" + `

## How a rule uses one

A rule narrows by source, condition and entity, and any of the three may be
left empty to mean *anything*. The **entity** is a camera or door name from
your own site, so no list here can supply it -- the Rules editor suggests the
ones this daemon has actually seen events about.

A condition is also part of the stored dedup key, which is why it is a fixed
vocabulary rather than free text: the same real problem arriving by two routes
has to use the same string, or it becomes two incidents that both nag.

`)

	lastGroup := ""
	for _, c := range Catalogue() {
		if c.Group != lastGroup {
			b.WriteString("\n## " + c.Group + "\n\n")
			b.WriteString("| Condition | Means | Comes from |\n")
			b.WriteString("|---|---|---|\n")
			lastGroup = c.Group
		}
		from := "inbound webhook only"
		if len(c.Sources) > 0 {
			from = "`" + strings.Join(c.Sources, "`, `") + "`"
		}
		b.WriteString("| `" + c.Name + "` | " + c.Meaning + " | " + from + " |\n")
	}

	b.WriteString(`
---

## A note on "comes from"

This is where the condition is observed **in this build**, read off the mapping
tables rather than from intent. Several conditions that a UniFi console can
raise reach this product only as an *inbound webhook* -- you make an Alarm
Manager rule by hand and point it at a hook URL, because the Network
Integration API publishes no events at all. Those are marked *inbound webhook
only*, and a hook has to exist and be pointed at one before it can ever fire.
`)
	return b.String()
}
