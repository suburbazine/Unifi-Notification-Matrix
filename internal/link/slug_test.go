package link

import (
	"errors"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// A SLUG IS NOT DECORATION.
//
// It becomes the event source, the first segment of every stored dedup key for
// ever, an audit field, and the path segment of DELETE /api/link/peers/{slug}.
// A slug with a slash in it is a peer that cannot be unpaired from the page at
// all; one with spaces or mixed case mints dedup keys that read as two
// different devices.
func TestASlugHasToBeUsableAsAnEventSource(t *testing.T) {
	for _, ok := range []string{"sentry", "door-matrix", "x", "a1", "a-b-c",
		strings.Repeat("a", MaxSlugChars)} {
		if !ValidSlug(ok) {
			t.Errorf("refused %q, which is a perfectly ordinary product name", ok)
		}
	}
	for _, bad := range []string{
		"", " ", "Sentry", "SENTRY", "door matrix", "door/matrix", "door.matrix",
		"-leading", "door_matrix", "sentry\n", "sentry\x00",
		strings.Repeat("a", MaxSlugChars+1),
	} {
		if ValidSlug(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A PEER MAY NOT CALL ITSELF ONE OF THIS PRODUCT'S OWN SOURCES.
//
// The capability machinery is named after the source a peer DISPLACES, so a
// peer calling itself "access" would be reasoning about displacing itself --
// and its dedup keys would be indistinguishable from the native source's, so
// an incident it raised and one this product raised would merge.
func TestAPeerCannotTakeTheNameOfOneOfOurOwnSources(t *testing.T) {
	for _, reserved := range []string{"protect", "access", "network", "inbound", "internal"} {
		if ValidSlug(reserved) {
			t.Errorf("a peer could pair as %q, which is one of this product's "+
				"own sources", reserved)
		}
	}
}

// AND THE MANIFEST VALIDATOR ENFORCES IT, which is what pairing runs.
func TestAManifestWithAnUnusableSlugIsRefused(t *testing.T) {
	m := Manifest{
		Capability: "access",
		Conditions: []ConditionSpec{{
			Name: "x-thing", Meaning: "something", Severity: incident.SeverityHigh,
		}},
	}
	for _, bad := range []string{"x/y", "X", "x y", "access", ""} {
		if err := m.Validate(bad); !errors.Is(err, ErrSlug) {
			t.Errorf("slug %q gave %v, want ErrSlug", bad, err)
		}
	}
	// A usable one still passes, or this is refusing everything.
	good := Manifest{
		Capability: "access",
		Conditions: []ConditionSpec{{
			Name: "sentry-thing", Meaning: "something", Severity: incident.SeverityHigh,
		}},
	}
	if err := good.Validate("sentry"); err != nil {
		t.Errorf("a valid manifest was refused: %v", err)
	}
}
