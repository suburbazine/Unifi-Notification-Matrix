package link

import (
	"errors"
	"fmt"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// MaxManifestConditions bounds what a peer may declare.
//
// Approving eleven conditions is review. Approving two hundred is
// rubber-stamping, and the operator's review is the entire security value of
// the manifest -- a list nobody reads is a vocabulary nobody agreed to.
const MaxManifestConditions = 32

// ConditionSpec is one condition a peer declares at pairing.
type ConditionSpec struct {
	// Name is what arrives in the envelope and becomes part of a stored dedup
	// key. It must begin with the peer's slug: dedup keys are already
	// namespaced by source, but the rules editor offers one vocabulary to a
	// human, and a peer declaring "motion" there would be indistinguishable
	// from this product's own.
	Name string `json:"name"`

	// Meaning is the operator-facing sentence. It is what they are approving,
	// so it is required: a condition with no meaning cannot be reviewed.
	Meaning string `json:"meaning"`

	// Severity is the peer's default for this condition. Rules may override it
	// and a per-peer cap may lower it.
	Severity incident.Severity `json:"severity"`

	// Momentary is a PROPOSAL, not a declaration.
	//
	// The flag decides whether an incident that cleared before its first rung
	// is still delivered, and getting it wrong on a high-volume condition
	// floods the operator. Only measurement settles that, which is why this
	// product classifies its own conditions rather than trusting a sender --
	// and a peer approved by an operator who has never seen the condition fire
	// cannot know either. So the peer proposes and the operator may override.
	Momentary bool `json:"momentary"`

	// DemotesClaim marks a condition that means "I am alive but cannot serve
	// the capability I claimed".
	//
	// LIVENESS IS NOT CAPABILITY. A peer whose outbound sockets are being
	// refused by the OS heartbeats perfectly over loopback while not watching
	// a single door. Suppressing our own ingest through that is worse than the
	// dead-peer case, because everything looks healthy. Raised demotes the
	// claim and our native source resumes; cleared restores it.
	DemotesClaim bool `json:"demotes_claim"`
}

// Manifest is the vocabulary a peer declared and an operator approved.
type Manifest struct {
	// Capability is what this peer claims to serve, named after the source it
	// displaces: "access". At most one peer may hold a capability.
	Capability string          `json:"capability"`
	Conditions []ConditionSpec `json:"conditions"`
}

// Override is the operator's decision about one condition.
//
// Kept apart from the manifest so it SURVIVES AN AMENDMENT. A peer that
// re-proposes momentary in its next release must not silently undo an operator
// who decided otherwise; the delta shows "peer proposes momentary, your
// override: state" and the override stands until they change it deliberately.
type Override struct {
	Momentary *bool `json:"momentary,omitempty"`
}

// Peer is a paired product and everything approved for it.
type Peer struct {
	// Slug names the product, becomes the event source, and is therefore the
	// first segment of every dedup key this peer produces. Never hardcoded:
	// this channel carries more than one product.
	Slug string `json:"slug"`

	Manifest  Manifest            `json:"manifest"`
	Overrides map[string]Override `json:"overrides,omitempty"`

	// MaxSeverity optionally caps what this peer may claim. Empty means
	// uncapped, which is the default: the cascade is the point.
	MaxSeverity incident.Severity `json:"max_severity,omitempty"`
}

var (
	ErrManifestEmpty    = errors.New("link: a manifest with no conditions declares nothing")
	ErrManifestTooLarge = errors.New("link: manifest is too large to review")
	ErrNoCapability     = errors.New("link: manifest declares no capability")
	ErrConditionPrefix  = errors.New("link: condition name must begin with the peer's slug")
	ErrConditionDup     = errors.New("link: condition declared twice")
	ErrNoMeaning        = errors.New("link: condition has no meaning for the operator to approve")
)

// Validate checks a manifest against what can be reviewed and honoured.
func (m Manifest) Validate(slug string) error {
	if strings.TrimSpace(m.Capability) == "" {
		return ErrNoCapability
	}
	if len(m.Conditions) == 0 {
		return ErrManifestEmpty
	}
	if len(m.Conditions) > MaxManifestConditions {
		return fmt.Errorf("%w: %d conditions, the limit is %d",
			ErrManifestTooLarge, len(m.Conditions), MaxManifestConditions)
	}
	prefix := strings.TrimSpace(slug) + "-"
	seen := map[string]bool{}
	for _, c := range m.Conditions {
		name := strings.TrimSpace(c.Name)
		switch {
		case !strings.HasPrefix(name, prefix):
			return fmt.Errorf("%w: %q should start %q", ErrConditionPrefix, name, prefix)
		case seen[name]:
			return fmt.Errorf("%w: %q", ErrConditionDup, name)
		case strings.TrimSpace(c.Meaning) == "":
			return fmt.Errorf("%w: %q", ErrNoMeaning, name)
		case !c.Severity.Valid():
			return fmt.Errorf("%w: %q proposes %q", ErrSeverity, name, c.Severity)
		}
		seen[name] = true
	}
	return nil
}

// Spec returns the approved entry for a condition.
func (p Peer) Spec(condition string) (ConditionSpec, bool) {
	for _, c := range p.Manifest.Conditions {
		if c.Name == condition {
			return c, true
		}
	}
	return ConditionSpec{}, false
}

// Allows reports whether this condition is in the approved manifest.
func (p Peer) Allows(condition string) bool {
	_, ok := p.Spec(condition)
	return ok
}

// IsMomentary reports the effective classification: the operator's override
// where they made one, otherwise the peer's proposal.
func (p Peer) IsMomentary(condition string) bool {
	spec, ok := p.Spec(condition)
	if !ok {
		return false
	}
	if o, has := p.Overrides[condition]; has && o.Momentary != nil {
		return *o.Momentary
	}
	return spec.Momentary
}

// DemotesClaim reports whether this condition, while raised, means the peer
// cannot serve the capability it claimed.
func (p Peer) DemotesClaim(condition string) bool {
	spec, ok := p.Spec(condition)
	return ok && spec.DemotesClaim
}
