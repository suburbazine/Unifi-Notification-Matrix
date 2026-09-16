package escalate

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// ErrUnknownChannel means a policy stage names a channel that does not exist.
var ErrUnknownChannel = errors.New("policy names a channel that does not exist")

// ValidateAgainstChannels refuses a policy set naming a channel that is not
// registered.
//
// This is a refusal at startup, not a warning and not a skip, because the
// alternative is the worst kind of failure this product has. A stage naming
// "voice" with no voice channel registered would deliver nothing, report
// nothing, and look exactly like a stage that delivered successfully — so the
// operator who carefully configured a phone call for their top severity gets
// silence at 3am and no indication anything is wrong. An alarm product that
// silently drops a configured escalation rung has lied about what it will do.
//
// Refusing at startup is survivable: the daemon will not start, the operator
// sees why immediately, and fixes a config file. That is strictly better than
// discovering it during an incident.
func ValidateAgainstChannels(policies map[incident.Severity]Policy, available []string) error {
	have := make(map[string]bool, len(available))
	for _, c := range available {
		have[strings.TrimSpace(strings.ToLower(c))] = true
	}

	// Sorted so the same misconfiguration reports identically every run; map
	// iteration order would otherwise reshuffle the message and make it look
	// like a different fault each restart.
	sevs := make([]string, 0, len(policies))
	bySev := make(map[string]incident.Severity, len(policies))
	for sev := range policies {
		sevs = append(sevs, string(sev))
		bySev[string(sev)] = sev
	}
	sort.Strings(sevs)

	var problems []string
	for _, name := range sevs {
		p := policies[bySev[name]]
		for i, st := range p.Stages {
			for _, ch := range st.Channels {
				if !have[strings.TrimSpace(strings.ToLower(ch))] {
					problems = append(problems, fmt.Sprintf(
						"severity %q stage %d names channel %q", name, i, ch))
				}
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}

	known := append([]string(nil), available...)
	sort.Strings(known)
	if len(known) == 0 {
		known = []string{"(none configured)"}
	}
	return fmt.Errorf("%w:\n  %s\nconfigured channels: %s",
		ErrUnknownChannel, strings.Join(problems, "\n  "), strings.Join(known, ", "))
}

// ChannelsUsed returns every distinct channel named anywhere in the policy
// set, sorted. Used at startup to build only the channels that are actually
// reachable, and by diagnostics to show which are configured but never used —
// a channel nobody's policy names is a channel the operator believes is
// protecting them and which will never fire.
func ChannelsUsed(policies map[incident.Severity]Policy) []string {
	seen := map[string]bool{}
	for _, p := range policies {
		for _, st := range p.Stages {
			for _, ch := range st.Channels {
				c := strings.TrimSpace(strings.ToLower(ch))
				if c != "" {
					seen[c] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
