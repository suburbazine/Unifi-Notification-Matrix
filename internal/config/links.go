package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// BuildLinks turns configured peers into what the receiver needs.
//
// A peer with no credential is skipped rather than half-built: without a key
// nothing it sends can authenticate, so the entry would be a peer that appears
// paired in the file and can never arrive -- exactly the configured-but-inert
// shape this product refuses elsewhere.
func BuildLinks(c *Config) ([]link.Peer, []link.Credential) {
	peers := make([]link.Peer, 0, len(c.Links))
	creds := make([]link.Credential, 0, len(c.Links))
	for _, l := range c.Links {
		if l.LinkID == "" || l.Key.IsZero() || strings.TrimSpace(l.Slug) == "" {
			continue
		}
		conds := make([]link.ConditionSpec, 0, len(l.Conditions))
		for _, c := range l.Conditions {
			conds = append(conds, link.ConditionSpec{
				Name: c.Name, Meaning: c.Meaning, Severity: c.Severity,
				Momentary: c.Momentary, DemotesClaim: c.DemotesClaim,
			})
		}
		over := map[string]link.Override{}
		for name, o := range l.Overrides {
			over[name] = link.Override{Momentary: o.Momentary}
		}
		peers = append(peers, link.Peer{
			Slug:   l.Slug,
			LinkID: l.LinkID,
			Manifest: link.Manifest{
				Capability: l.Capability,
				Conditions: conds,
			},
			Overrides:   over,
			MaxSeverity: l.MaxSeverity,
		})
		creds = append(creds, link.Credential{LinkID: l.LinkID, Key: []byte(l.Key.Reveal())})
	}
	return peers, creds
}

// validateLinks refuses peer configurations that cannot work.
func (c Config) validateLinks() Problems {
	var p Problems

	if a := strings.TrimSpace(c.Web.LinkListen); a != "" {
		// Same check as the other two listeners: an address this machine does
		// not have is a service that will not start, not an exposure choice.
		if _, wantsRandom := WantsRandomAckPort(a); !wantsRandom {
			if _, _, err := net.SplitHostPort(a); err != nil {
				p = append(p, fmt.Sprintf("web.link_listen %q is not host:port "+
					"(or %q, to pick a port once and keep it)", a, AckListenAuto))
			} else if msg := listenHostProblem("web.link_listen", a); msg != "" {
				p = append(p, msg)
			}
		}
	}

	seenID := map[string]string{}
	claimed := map[string]string{}
	for i, l := range c.Links {
		where := l.Slug
		if where == "" {
			where = fmt.Sprintf("links[%d]", i)
		}
		if strings.TrimSpace(l.Slug) == "" {
			p = append(p, fmt.Sprintf("%s: a link needs a product slug; it becomes "+
				"the event source and the first part of every dedup key", where))
		}
		if strings.TrimSpace(l.LinkID) == "" {
			p = append(p, fmt.Sprintf("%s: a link needs a link_id", where))
			continue
		}
		if prev, dup := seenID[l.LinkID]; dup {
			p = append(p, fmt.Sprintf("%s: link_id %q is already used by %s; "+
				"two peers sharing a credential cannot be told apart", where, l.LinkID, prev))
		}
		seenID[l.LinkID] = where

		// ONE CLAIMANT PER CAPABILITY. Two peers both claiming to serve the
		// doors is the duplicate-source problem the claim exists to prevent,
		// and last-writer-wins would silently demote a working product.
		if cap := strings.TrimSpace(l.Capability); cap != "" {
			if prev, dup := claimed[cap]; dup {
				p = append(p, fmt.Sprintf("%s and %s both claim %q; a capability has "+
					"at most one claimant, so release one before granting the other",
					prev, where, cap))
			}
			claimed[cap] = where
		}

		if len(l.Conditions) > link.MaxManifestConditions {
			p = append(p, fmt.Sprintf("%s declares %d conditions; the limit is %d, "+
				"because a list nobody reads is a vocabulary nobody agreed to",
				where, len(l.Conditions), link.MaxManifestConditions))
		}
		prefix := l.Slug + "-"
		for _, cond := range l.Conditions {
			if !strings.HasPrefix(cond.Name, prefix) {
				p = append(p, fmt.Sprintf("%s: condition %q should start %q",
					where, cond.Name, prefix))
			}
			if cond.Severity != "" && !cond.Severity.Valid() {
				p = append(p, fmt.Sprintf("%s: condition %q proposes severity %q",
					where, cond.Name, cond.Severity))
			}
		}
	}
	return p
}

// linkWarnings reports peer setups that work but probably were not meant.
func (c Config) linkWarnings() []string {
	var w []string
	if len(c.Links) > 0 && strings.TrimSpace(c.Web.LinkListen) == "" {
		w = append(w, "a peer is paired but web.link_listen is not set, so the "+
			"link routes do not exist and nothing it sends can arrive")
	}
	for _, l := range c.Links {
		if l.Capability == "" {
			continue
		}
		// The failback has nothing to fall back to. Worth saying at the time,
		// because the shape reads as fully covered: the peer holds the
		// capability, and if it stops this product can only report that it
		// stopped.
		if l.Capability == "access" && !c.hasSource("access") {
			w = append(w, fmt.Sprintf("%s is the only source of door events: no "+
				"console is configured for access, so if it stops this product "+
				"will tell you it stopped but will not watch your doors in its "+
				"place. Add access to a console's sources if you want that",
				l.Slug))
		}
	}
	return w
}

// hasSource reports whether any console is configured for a source.
func (c Config) hasSource(name string) bool {
	for _, con := range c.Consoles {
		for _, s := range con.Sources {
			if strings.EqualFold(strings.TrimSpace(s), name) {
				return true
			}
		}
	}
	return false
}
