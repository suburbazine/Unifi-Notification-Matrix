package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

var yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")

// THE YAML IN THE DOCUMENTATION HAS TO BE YAML.
//
// docs/SETUP.md carried a policy example whose stages put two mappings on one
// line -- "- after: 0s   channels: [ntfy, email]" -- which is not valid YAML at
// all, under prose telling the operator to write exactly that. The same shape
// had already bitten once in the config file's own header, where the email
// recipients field was documented under a name that does not exist.
//
// An operator copying an example out of the documentation and getting a daemon
// that will not start is the worst kind of bug, because the instructions are
// the one thing they had no reason to doubt.
func TestEveryYAMLExampleInTheDocsParses(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "docs", "SETUP.md"),
		filepath.Join(root, "docs", "ARCHITECTURE.md"),
		filepath.Join(root, "docs", "SOURCES.md"),
		filepath.Join(root, "docs", "DESIGN-RULES.md"),
		filepath.Join(root, "docs", "RELEASING.md"),
	}

	var checked int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range yamlBlock.FindAllStringSubmatch(string(b), -1) {
			block := m[1]
			if strings.TrimSpace(block) == "" {
				continue
			}
			checked++
			var into any
			if err := yaml.Unmarshal([]byte(block), &into); err != nil {
				t.Errorf("%s: a yaml example does not parse: %v\n%s",
					filepath.Base(f), err, block)
			}
		}
	}

	// A scanner that silently matches nothing passes for ever while checking
	// nothing, which is how the broken example shipped in the first place.
	if checked < 3 {
		t.Fatalf("only found %d yaml examples in the docs; this test is checking nothing", checked)
	}
	t.Logf("checked %d yaml examples", checked)
}
