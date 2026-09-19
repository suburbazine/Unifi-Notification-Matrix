package link

import (
	"strings"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// A PEER'S NEXT RELEASE SHOULD NOT MEAN HAND-EDITING YAML.
//
// The manifest is a closed vocabulary an operator approved, and that is the
// whole security value of it: a condition outside it is refused rather than
// bucketed, because a silent catch-all recreates the open vocabulary a closed
// one exists to prevent. See Envelope.Validate.
//
// But a peer ships a twelfth condition and every event carrying it is refused
// for ever. All the operator gets is a receipt saying the condition was not
// declared, and the only way forward is to open the configuration file by
// hand or to re-pair the product — which rotates a working credential to fix
// a spelling.
//
// So: the refusal stands, and the attempt is REMEMBERED. Nothing arrives
// until the operator says yes; what changes is that saying yes is a button.
// That keeps the property that matters — the vocabulary is still exactly what
// a human approved — and drops the one that was only ever an accident, that
// approving it required a text editor.
//
// In memory, bounded, and lost on restart, like the receipts. A proposal is a
// prompt to look, not a record; the peer re-sends within minutes and the
// prompt comes back.

// MaxProposalsPerPeer bounds what one peer can put in front of an operator.
//
// The same number as the manifest itself, for the same reason: reviewing
// thirty-two conditions is review, and reviewing two hundred is
// rubber-stamping. It also means an authenticated peer with a mapping bug
// cannot bury a real proposal under a thousand generated names.
const MaxProposalsPerPeer = MaxManifestConditions

// MaxConditionNameChars is the longest condition name worth remembering.
//
// A condition becomes part of a stored dedup key and of a line an operator
// reads at three in the morning. Nothing legitimate is near this.
const MaxConditionNameChars = 64

// Proposal is a condition a paired peer has sent that its approved manifest
// does not contain.
type Proposal struct {
	Slug      string
	Condition string

	// Severity and Title are the peer's own words from the refused envelope,
	// offered as a starting point. The operator edits both: the peer is
	// proposing, and a meaning nobody wrote is a meaning nobody reviewed.
	Severity incident.Severity
	Title    string

	First time.Time
	Last  time.Time

	// Count is how many times it has been tried, which is the difference
	// between a peer that fired once during its own testing and a door that
	// has been reporting something real and unheard for two days.
	Count int
}

// Proposals is the bounded record of conditions peers have offered.
type Proposals struct {
	mu       sync.Mutex
	byPeer   map[string]map[string]*Proposal
	full     map[string]int // slug -> distinct names refused because the list is full
	unusable map[string]int // slug -> names that could never be approved
}

// NewProposals builds an empty record.
func NewProposals() *Proposals {
	return &Proposals{
		byPeer:   map[string]map[string]*Proposal{},
		full:     map[string]int{},
		unusable: map[string]int{},
	}
}

// Note records that a paired peer sent a condition its manifest does not have.
//
// Called only AFTER authentication: an unauthenticated caller must not be able
// to put anything in front of an operator, and could otherwise fill this with
// invented conditions attributed to a peer the operator trusts.
func (p *Proposals) Note(slug, condition string, sev incident.Severity,
	title string, now time.Time) {

	slug = strings.TrimSpace(slug)
	condition = strings.TrimSpace(condition)
	if slug == "" || condition == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// A NAME THAT COULD NEVER BE APPROVED IS COUNTED, NOT LISTED.
	//
	// The manifest requires every condition to begin with the peer's slug, so
	// one that does not is a bug in the peer rather than a decision waiting
	// for the operator. Listing it would put a button next to something the
	// validator will refuse; counting it still tells them their peer is
	// sending something wrong.
	if len(condition) > MaxConditionNameChars ||
		!strings.HasPrefix(condition, slug+"-") {
		p.unusable[slug]++
		return
	}

	seen := p.byPeer[slug]
	if seen == nil {
		seen = map[string]*Proposal{}
		p.byPeer[slug] = seen
	}
	if existing, ok := seen[condition]; ok {
		existing.Last = now
		existing.Count++
		// The severity and title follow the LATEST attempt. A peer that
		// corrected them in its next release should not have the operator
		// reviewing the version it has stopped sending.
		if sev.Valid() {
			existing.Severity = sev
		}
		if strings.TrimSpace(title) != "" {
			existing.Title = title
		}
		return
	}
	if len(seen) >= MaxProposalsPerPeer {
		// Full. The oldest is NOT evicted: a list that rotates under an
		// operator reading it is worse than a list that says it is full, and
		// the first proposals are the ones most likely to be the real ones.
		p.full[slug]++
		return
	}
	seen[condition] = &Proposal{
		Slug: slug, Condition: condition, Severity: sev, Title: title,
		First: now, Last: now, Count: 1,
	}
}

// For returns one peer's proposals, most recently tried first.
func (p *Proposals) For(slug string) []Proposal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.forLocked(slug)
}

func (p *Proposals) forLocked(slug string) []Proposal {
	var out []Proposal
	for _, pr := range p.byPeer[slug] {
		out = append(out, *pr)
	}
	sortProposals(out)
	return out
}

// All returns every peer's proposals.
func (p *Proposals) All() []Proposal {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Proposal
	for slug := range p.byPeer {
		out = append(out, p.forLocked(slug)...)
	}
	sortProposals(out)
	return out
}

// Refused reports how many distinct names were NOT listed for this peer:
// those that could never be approved, and those that arrived after the list
// was full.
//
// Reported rather than silently dropped. A page that shows four proposals and
// does not mention the ninety it discarded is telling the operator their peer
// sends four things it does not declare.
func (p *Proposals) Refused(slug string) (unusable, overflowed int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unusable[slug], p.full[slug]
}

// Has reports whether this peer is currently being refused for this condition.
//
// The gate on the amendment route: an operator may approve what a peer ASKED
// for, not whatever a request body contains.
func (p *Proposals) Has(slug, condition string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := p.byPeer[strings.TrimSpace(slug)]
	if seen == nil {
		return false
	}
	_, ok := seen[strings.TrimSpace(condition)]
	return ok
}

// Forget drops one proposal, because the operator approved or dismissed it.
func (p *Proposals) Forget(slug, condition string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if seen := p.byPeer[slug]; seen != nil {
		delete(seen, condition)
		if len(seen) == 0 {
			delete(p.byPeer, slug)
		}
	}
	// The overflow count goes with it: it counted names turned away because
	// this list was full, and it no longer is.
	delete(p.full, slug)
}

// ForgetPeer drops everything for a peer that has been unpaired.
//
// A proposal is attributed to a product by slug, and leaving them behind would
// mean an unpaired peer still asking an operator for vocabulary -- and a
// DIFFERENT installation of that product later inheriting the first one's
// pending questions.
func (p *Proposals) ForgetPeer(slug string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.byPeer, slug)
	delete(p.full, slug)
	delete(p.unusable, slug)
}

func sortProposals(in []Proposal) {
	// Most recently tried first, then by name so the order is stable when two
	// arrived together. An unstable order under a list somebody is reading is
	// how the wrong button gets pressed.
	for i := 1; i < len(in); i++ {
		for j := i; j > 0; j-- {
			a, b := in[j-1], in[j]
			later := b.Last.After(a.Last) ||
				(b.Last.Equal(a.Last) && b.Condition < a.Condition)
			if !later {
				break
			}
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
}
