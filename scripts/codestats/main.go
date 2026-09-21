// Command codestats counts what is in this repository and writes the ticker at
// the top of the README.
//
// RUN IT BY HAND, on a push worth re-counting:
//
//	go run ./scripts/codestats          # print the table, change nothing
//	go run ./scripts/codestats -write   # rewrite the README block
//
// Deliberately not a workflow that commits to main. A job that rewrites the
// README on every push produces a commit nobody made for a number nobody
// asked for, and the number is never interesting enough to be worth an
// unreviewed write to the default branch.
//
// WHAT IT REFUSES TO DO IS COUNT COMMENTS AS CODE. This repository is
// comment-heavy on purpose -- a lot of what is written down here is why
// something is the way it is, which is the part that does not survive in a
// diff -- so a single "lines of Go" figure would be flattering and would
// measure the wrong thing. Comments are counted and reported separately, and
// a line carrying both code and a trailing comment counts as code.
package main

import (
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// counts is one bucket of lines.
type counts struct {
	Files    int
	Code     int
	Comment  int
	Blank    int
	TestFunc int
}

func (c counts) Total() int { return c.Code + c.Comment + c.Blank }

func (c *counts) add(o counts) {
	c.Files += o.Files
	c.Code += o.Code
	c.Comment += o.Comment
	c.Blank += o.Blank
	c.TestFunc += o.TestFunc
}

func main() {
	write := flag.Bool("write", false, "rewrite the ticker block in README.md")
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	s, err := survey(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "codestats:", err)
		os.Exit(1)
	}
	fmt.Print(s.table())

	if !*write {
		return
	}
	path := filepath.Join(*root, "README.md")
	changed, err := rewrite(path, s.ticker())
	if err != nil {
		fmt.Fprintln(os.Stderr, "codestats:", err)
		os.Exit(1)
	}
	if changed {
		fmt.Println("\nREADME.md updated.")
		return
	}
	fmt.Println("\nREADME.md already said this.")
}

type stats struct {
	Go       counts // production Go
	GoTest   counts // _test.go
	UI       counts // the interface: js, css, html
	Docs     counts // markdown
	Packages int
}

// survey walks the repository. Everything that is not source is skipped by
// name rather than by guessing: .git, the gitignored working notes, and the
// scratch directories a build leaves behind.
func survey(root string) (stats, error) {
	var s stats
	pkgs := map[string]bool{}

	skipDir := map[string]bool{
		".git": true, ".github": false, "internal-notes": true,
		"node_modules": true, "dist": true, "vendor": true,
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (skipDir[name] || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(name))
		switch {
		case ext == ".go":
			c, err := countGo(path)
			if err != nil {
				return err
			}
			if strings.HasSuffix(name, "_test.go") {
				s.GoTest.add(c)
			} else {
				s.Go.add(c)
				pkgs[filepath.Dir(path)] = true
			}
		case ext == ".js" || ext == ".css" || ext == ".html":
			c, err := countPlain(path, ext)
			if err != nil {
				return err
			}
			s.UI.add(c)
		case ext == ".md":
			c, err := countPlain(path, ext)
			if err != nil {
				return err
			}
			s.Docs.add(c)
		}
		return nil
	})
	s.Packages = len(pkgs)
	return s, err
}

// countGo counts one Go file, using the real parser for the comments.
//
// A line-based guess at where comments are gets `"/*"` inside a string
// literal wrong, and this repository has several. The parser knows.
func countGo(path string) (counts, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return counts{}, err
	}
	lines := strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n")
	// A trailing newline produces a final empty element that is not a line.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		// A file that does not parse is still lines. Counted as code rather
		// than skipped, because silently dropping a file is how a number goes
		// quietly wrong.
		c := counts{Files: 1}
		for _, l := range lines {
			if strings.TrimSpace(l) == "" {
				c.Blank++
			} else {
				c.Code++
			}
		}
		return c, nil
	}

	// Which lines are comment and NOTHING else. A comment sharing its line
	// with code is code: the code is the reason the line exists.
	commentOnly := map[int]bool{}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			start := fset.Position(c.Pos())
			end := fset.Position(c.End())
			if strings.TrimSpace(lineAt(lines, start.Line)[:min(start.Column-1, len(lineAt(lines, start.Line)))]) != "" {
				// Something precedes it on that line, so that line is code.
				// Later lines of a block comment are still comment.
				for l := start.Line + 1; l <= end.Line; l++ {
					commentOnly[l] = true
				}
				continue
			}
			for l := start.Line; l <= end.Line; l++ {
				commentOnly[l] = true
			}
		}
	}

	c := counts{Files: 1}
	for i, l := range lines {
		n := i + 1
		switch {
		case strings.TrimSpace(l) == "":
			c.Blank++
		case commentOnly[n]:
			c.Comment++
		default:
			c.Code++
		}
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "func Test") || strings.HasPrefix(l, "func Fuzz") ||
			strings.HasPrefix(l, "func Benchmark") {
			c.TestFunc++
		}
	}
	return c, nil
}

func lineAt(lines []string, n int) string {
	if n-1 < 0 || n-1 >= len(lines) {
		return ""
	}
	return lines[n-1]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// countPlain counts a file whose comment syntax is not worth parsing.
//
// For CSS and JS a line starting with // or /* or * is taken as a comment,
// which is right often enough for a README figure and wrong only for
// continuation lines of a multi-line string. Markdown has no comments.
func countPlain(path, ext string) (counts, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return counts{}, err
	}
	c := counts{Files: 1}
	for _, l := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == "":
			c.Blank++
		case ext != ".md" && (strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") ||
			strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--")):
			c.Comment++
		default:
			c.Code++
		}
	}
	// The trailing newline again.
	if c.Blank > 0 {
		c.Blank--
	}
	return c, nil
}

func (s stats) table() string {
	var b strings.Builder
	row := func(name string, c counts) {
		fmt.Fprintf(&b, "%-16s %6d files %8d code %8d comment %8d blank\n",
			name, c.Files, c.Code, c.Comment, c.Blank)
	}
	row("Go", s.Go)
	row("Go tests", s.GoTest)
	row("interface", s.UI)
	row("docs", s.Docs)
	fmt.Fprintf(&b, "%-16s %6d packages %5d tests\n", "", s.Packages, s.GoTest.TestFunc)
	return b.String()
}

// ticker is the badge row. Static shields, because the numbers are counted
// here and not by a service that would have to be given the repository.
func (s stats) ticker() string {
	badge := func(label, value, colour string) string {
		return fmt.Sprintf(
			`  <img alt="%s: %s" src="https://img.shields.io/badge/%s-%s-%s">`,
			label, value, shieldEscape(label), shieldEscape(value), colour)
	}
	lines := []string{
		badge("Go", thousands(s.Go.Code)+" lines", "00ADD8"),
		badge("tests", thousands(s.GoTest.Code)+" lines", "2ea44f"),
		badge("test functions", fmt.Sprint(s.GoTest.TestFunc), "2ea44f"),
		badge("comments", fmt.Sprintf("%d%%", pct(s.Go.Comment, s.Go.Code+s.Go.Comment)), "8957e5"),
		badge("packages", fmt.Sprint(s.Packages), "555555"),
		badge("docs", thousands(s.Docs.Code)+" lines", "555555"),
	}
	return "<p align=\"center\">\n" + strings.Join(lines, "\n") + "\n</p>\n\n" +
		"<p align=\"center\">\n  <sub>\n" +
		"    Counted by <code>go run ./scripts/codestats -write</code>, by hand, and\n" +
		"    therefore true as of the last time somebody ran it. Comments are counted\n" +
		"    apart from code on purpose: a good deal of what is written down in this\n" +
		"    repository is <i>why</i>, which is the part a diff does not keep.\n" +
		"  </sub>\n</p>\n"
}

func pct(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a*100 + b/2) / b
}

func thousands(n int) string {
	s := fmt.Sprint(n)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// shieldEscape encodes a shields.io path segment: dashes double, spaces
// become underscores.
func shieldEscape(s string) string {
	// Percent FIRST: it is the escape character, so encoding it after
	// introducing %20 would turn that into %2520 and the badge would read
	// "33%2520".
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "-", "--")
	s = strings.ReplaceAll(s, "_", "__")
	return strings.ReplaceAll(s, " ", "%20")
}

const (
	startMark = "<!-- codestats:start -->"
	endMark   = "<!-- codestats:end -->"
)

// rewrite replaces the marked block, and refuses rather than guessing if the
// markers are not there.
func rewrite(path, block string) (bool, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	text := string(src)
	i := strings.Index(text, startMark)
	j := strings.Index(text, endMark)
	if i < 0 || j < 0 || j < i {
		return false, fmt.Errorf("%s has no %s ... %s block to write into", path, startMark, endMark)
	}
	next := text[:i+len(startMark)] + "\n" + block + text[j:]
	if next == text {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(next), 0o644)
}

var _ = sort.Strings // kept for a future breakdown by package
