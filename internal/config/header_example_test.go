package config

import (
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// A top-level YAML key, as opposed to a sentence in the prose that happens to
// end in a colon.
var topLevelKey = regexp.MustCompile(`^[a-z][a-z0-9_]*:$`)

// THE INSTRUCTIONS IN THE FILE HAVE TO BE INSTRUCTIONS THAT WORK.
//
// The header documented the email recipients as "to:". The field is
// "recipients:", and sigs.k8s.io/yaml is not strict, so following the
// product's own example dropped the key in silence and the daemon then
// refused to start with "channel email: has no recipients" -- pointing at
// the one line the operator had copied verbatim from the instructions.
//
// This parses the commented examples out of the header and unmarshals them
// STRICTLY, so any key that is not a real field fails here instead.
func TestTheExamplesInTheFileHeaderUseRealFieldNames(t *testing.T) {
	for _, block := range exampleBlocks(fileHeader) {
		var cfg Config
		if err := yaml.UnmarshalStrict([]byte(block), &cfg); err != nil {
			t.Errorf("an example in the file header is not valid configuration: %v\n%s", err, block)
		}
	}
}

// exampleBlocks pulls the commented YAML out of the header: a line like
// "# hooks:" or "# channels:" at the top level, plus the indented comment
// lines under it.
func exampleBlocks(header string) []string {
	var blocks []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, strings.Join(cur, "\n")+"\n")
			cur = nil
		}
	}
	for _, line := range strings.Split(header, "\n") {
		if !strings.HasPrefix(line, "#") {
			flush()
			continue
		}
		body := strings.TrimPrefix(line, "#")
		body = strings.TrimPrefix(body, " ")
		trimmed := strings.TrimSpace(body)

		switch {
		case len(cur) == 0:
			// Only a top-level key with no indentation starts a block.
			if !strings.HasPrefix(body, " ") && topLevelKey.MatchString(trimmed) {
				cur = append(cur, body)
			}
		case trimmed == "":
			// A blank comment line inside a block is spacing, not the end.
			cur = append(cur, "")
		case strings.HasPrefix(body, " "):
			cur = append(cur, body)
		default:
			flush()
		}
	}
	flush()
	return blocks
}

// If the extractor silently matched nothing, the test above would pass while
// checking nothing at all -- which is the failure mode that let a broken
// example ship in the first place.
func TestTheHeaderExampleExtractorFindsSomething(t *testing.T) {
	blocks := exampleBlocks(fileHeader)
	if len(blocks) < 2 {
		t.Fatalf("expected the hooks and channels examples, found %d blocks", len(blocks))
	}
	var joined string
	for _, b := range blocks {
		joined += b
	}
	for _, want := range []string{"recipients:", "topic:", "hooks:", "channels:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the extracted examples do not mention %q", want)
		}
	}
}
