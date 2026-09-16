package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/source/access"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/source/network"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/source/protect"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/unifi"
)

// KnownSources are the source names a console entry may list.
var KnownSources = []string{protect.SourceName, access.SourceName, network.SourceName}

// BuildSources constructs a source for every enabled entry on every console.
//
// One construction failure does not fail the rest. A site whose Access key is
// wrong still wants its Protect cameras watched, and refusing to start
// anything would remove working coverage to punish a typo -- so the problems
// come back alongside the sources that did build, and the caller decides what
// to say about them.
func BuildSources(c *Config) ([]event.Source, []error) {
	var (
		out      []event.Source
		problems []error
	)
	for _, con := range c.Consoles {
		key, _ := con.ResolveAPIKey()
		// Per HOST, not per application. Protect, Access and Network are
		// served the same certificate by the same reverse proxy, so the pin is
		// one fact about the console rather than three about its applications.
		tls := &unifi.TLS{
			Fingerprint:        con.Fingerprint,
			InsecureSkipVerify: con.InsecureSkipVerify,
		}

		for _, name := range con.Sources {
			switch strings.ToLower(strings.TrimSpace(name)) {
			case protect.SourceName:
				s, err := protect.New(protect.Config{
					Host: con.Host, APIKey: key, TLS: tls,
				})
				if err != nil {
					problems = append(problems, fmt.Errorf("console %q: protect: %w", con.Name, err))
					continue
				}
				out = append(out, s)

			case access.SourceName:
				s, err := access.New(access.Config{
					Host: con.Host, APIKey: key, TLS: tls,
				})
				if err != nil {
					problems = append(problems, fmt.Errorf("console %q: access: %w", con.Name, err))
					continue
				}
				out = append(out, s)

			case network.SourceName:
				s, err := network.New(network.Config{
					Host: con.Host, APIKey: key, TLS: tls,
				})
				if err != nil {
					problems = append(problems, fmt.Errorf("console %q: network: %w", con.Name, err))
					continue
				}
				out = append(out, s)

			case "":
				// A blank entry in the list. Ignored rather than reported:
				// it is a YAML formatting artefact, not an operator intent.

			default:
				problems = append(problems, fmt.Errorf(
					"console %q lists source %q, which this build does not have (known: %s)",
					con.Name, name, strings.Join(KnownSources, ", ")))
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, problems
}
