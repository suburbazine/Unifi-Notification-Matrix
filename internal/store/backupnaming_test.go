package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ONE SHAPE FOR PRODUCT-MANAGED COPIES, ONE FOR OPERATOR-OWNED ONES, AND NO
// THIRD.
//
// docs/DESIGN-RULES.md §4 settles it: a copy the product will clean up ends
// ".previous"; a copy the operator owns is qualified by what it restores into
// and ends ".bak". The two are not interchangeable -- one is deleted by the
// product at the next successful start, the other survives until somebody
// decides they are happy -- so a name that does not say which is a name that
// gets the wrong lifetime.
//
// This is a test rather than a paragraph because a guard in a reviewer's
// memory is not a guard, which is the rule that section already applies to
// irreversible endpoints. It walks the tree so a third convention added
// anywhere breaks the build here, at the moment it is written, rather than
// being discovered in somebody's data directory.
//
// It exists because a third shape did briefly appear to exist. A file named
// config.yaml.before-ack-restore-20260917-050759 was found beside a production
// database and taken for a product convention; it had been created by hand and
// had never been in this codebase. The lesson that stuck was not about naming.
// It was that a convention nobody wrote down is one people will infer wrongly
// from whatever they happen to find.
func TestNoThirdBackupNamingConventionCreepsIn(t *testing.T) {
	// Suffixes and infixes that mean "this is a copy of something". Anything
	// matching has to be one of the two agreed shapes.
	suspicious := regexp.MustCompile(`\.(bak|previous|old|orig|backup|save|prev)\b|before-|\.copy\b`)

	// The two agreed shapes, and the literals that build them.
	allowed := map[string]bool{
		`".previous"`: true, // product-managed, internal/update
		`".bak"`:      true, // operator-owned, qualified by the caller
		`".v%d.bak"`:  true, // this package's qualifier
	}

	root := repoRoot(t)
	var offences []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable corner of the tree is not this test's business
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist", "node_modules", ".claude", "internal-notes":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(src), "\n") {
			code := stripComment(line)
			for _, lit := range stringLiterals(code) {
				if !suspicious.MatchString(lit) || allowed[lit] {
					continue
				}
				offences = append(offences, rel+":"+itoa(i+1)+"  "+lit)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(offences) > 0 {
		t.Errorf("a backup name that is neither shape agreed in "+
			"docs/DESIGN-RULES.md §4:\n  %s\n\n"+
			"A copy the product cleans up ends \".previous\". A copy the operator "+
			"owns is qualified by what it restores into and ends \".bak\". If this "+
			"is genuinely a third kind, change the rule and this test deliberately "+
			"rather than adding a shape nobody can reason about later.",
			strings.Join(offences, "\n  "))
	}
}

// repoRoot walks up until it finds go.mod, so the test does not care how deep
// the package sits.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

// stripComment drops a trailing line comment, so prose about backups does not
// read as code that names one. Crude on purpose: a "//" inside a string
// literal would truncate the line early, which can only cause this test to
// look at LESS and never at something that is not there.
func stripComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// stringLiterals pulls double-quoted literals out of a line, quotes included
// so the comparison against the allow-list is exact.
func stringLiterals(line string) []string {
	var out []string
	for {
		start := strings.Index(line, `"`)
		if start < 0 {
			return out
		}
		rest := line[start+1:]
		end := -1
		for i := 0; i < len(rest); i++ {
			if rest[i] == '\\' {
				i++
				continue
			}
			if rest[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 {
			return out
		}
		out = append(out, `"`+rest[:end]+`"`)
		line = rest[end+1:]
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
