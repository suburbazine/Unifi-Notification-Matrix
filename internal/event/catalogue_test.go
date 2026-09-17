package event

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// EVERY CONDITION MUST HAVE A MEANING WRITTEN DOWN.
//
// The catalogue is what the Rules editor offers and what the documentation is
// generated from, so a condition missing from it is a condition an operator
// cannot discover -- they are back to waiting for it to fire and reading the
// log, which is the problem the catalogue exists to end.
//
// Parsed out of the source rather than hand-listed, because a hand-listed
// expectation is a second thing to forget. Adding a Condition* constant and
// not describing it fails here.
func TestEveryConditionIsInTheCatalogue(t *testing.T) {
	declared := conditionConstants(t)
	if len(declared) < 30 {
		t.Fatalf("only found %d condition constants; the parser is not working "+
			"and this test is checking nothing", len(declared))
	}

	documented := map[string]bool{}
	for _, c := range Catalogue() {
		documented[c.Name] = true
	}

	for name, value := range declared {
		if !documented[value] {
			t.Errorf("%s (%q) has no entry in the catalogue, so it cannot be "+
				"offered in the Rules editor or appear in the documentation",
				name, value)
		}
	}
}

// ...and nothing in the catalogue may be invented. An entry for a condition no
// constant defines would be offered to an operator, accepted into a rule, and
// never match anything.
func TestTheCatalogueInventsNothing(t *testing.T) {
	declared := map[string]bool{}
	for _, v := range conditionConstants(t) {
		declared[v] = true
	}
	for _, c := range Catalogue() {
		if !declared[c.Name] {
			t.Errorf("the catalogue offers %q, which no Condition constant defines", c.Name)
		}
	}
}

// Every entry has to be usable: a name, a group, and a meaning that says
// something the name does not.
func TestEveryCatalogueEntryIsUsable(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Catalogue() {
		if seen[c.Name] {
			t.Errorf("%q appears twice", c.Name)
		}
		seen[c.Name] = true

		if strings.TrimSpace(c.Group) == "" {
			t.Errorf("%q has no group", c.Name)
		}
		m := strings.TrimSpace(c.Meaning)
		if len(m) < 20 {
			t.Errorf("%q has no real meaning: %q", c.Name, c.Meaning)
		}
		// "motion: motion was detected" is the failure mode: a meaning that is
		// the name again tells an operator nothing they did not have.
		bare := strings.ReplaceAll(c.Name, "-", " ")
		if strings.EqualFold(strings.TrimSuffix(m, "."), bare) {
			t.Errorf("%q restates its own name instead of explaining it: %q", c.Name, m)
		}
		for _, s := range c.Sources {
			switch s {
			case SurfaceProtect, SurfaceAccess, SurfaceNetwork, SurfaceInbound, SurfaceInternal:
			default:
				t.Errorf("%q names an unknown surface %q", c.Name, s)
			}
		}
	}
}

// Catalogue hands out a copy. A caller that mutates what it is given must not
// be able to rewrite the table for everybody else.
func TestCatalogueCannotBeRewrittenByItsCaller(t *testing.T) {
	got := Catalogue()
	if len(got) == 0 {
		t.Fatal("the catalogue is empty")
	}
	got[0].Name = "tampered"
	if Catalogue()[0].Name == "tampered" {
		t.Error("a caller rewrote the shared catalogue")
	}
}

// conditionConstants reads condition.go and returns constant name -> value for
// every Condition* string constant.
func conditionConstants(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "condition.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Condition") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				out[name.Name] = v
			}
		}
	}
	return out
}
