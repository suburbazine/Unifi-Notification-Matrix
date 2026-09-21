package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
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
// keyFor is Console.KeyFor without the origin, for the switch below.
func keyFor(c Console, product string) secret.Secret {
	k, _ := c.KeyFor(product)
	return k
}

func BuildSourcesKeyed(c *Config) ([]KeyedSource, []error) {
	var (
		out      []KeyedSource
		problems []error
	)
	for _, con := range c.Consoles {
		// Per APPLICATION, because UniFi mints a key per application and a
		// key from one is answered 401 by the others. KeyFor falls back to
		// the console key, so a site with a single key is unaffected.
		//
		// The PIN below is the opposite case, and the comment is kept because
		// the two look alike and are not.
		//
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
					Host: con.Host, APIKey: keyFor(con, protect.SourceName), TLS: tls,
				})
				if err != nil {
					problems = append(problems, fmt.Errorf("console %q: protect: %w", con.Name, err))
					continue
				}
				out = append(out, KeyedSource{Key: sourceKey(con, protect.SourceName), Source: s})

			case access.SourceName:
				s, err := access.New(access.Config{
					Host: con.Host, APIKey: keyFor(con, access.SourceName), TLS: tls,
				})
				if err != nil {
					problems = append(problems, fmt.Errorf("console %q: access: %w", con.Name, err))
					continue
				}
				out = append(out, KeyedSource{Key: sourceKey(con, access.SourceName), Source: s})

			case network.SourceName:
				s, err := network.New(network.Config{
					Host: con.Host, APIKey: keyFor(con, network.SourceName), TLS: tls,
				})
				if err != nil {
					problems = append(problems, fmt.Errorf("console %q: network: %w", con.Name, err))
					continue
				}
				out = append(out, KeyedSource{Key: sourceKey(con, network.SourceName), Source: s})

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
	sort.SliceStable(out, func(i, j int) bool { return out[i].Source.Name() < out[j].Source.Name() })
	return out, problems
}

// KeyedSource is a built source alongside a fingerprint of everything that
// went into building it.
//
// THE NAME IS NOT AN IDENTITY. Every source returns a per-application constant
// -- "protect", "access", "network" -- so a Protect source built from a
// corrected API key has the same name as the broken one it replaces. A daemon
// reloading its configuration and matching by name would keep the broken one
// running and report it as healthy, which is the precise failure this product
// exists to refuse.
//
// The key covers the host, the application, the key that application is given,
// the pinned fingerprint and whether verification is skipped: change any of
// them and this is a different connection to make. It is a hash, so it can be
// compared, logged and kept in a map without the credential going with it.
type KeyedSource struct {
	Key    string
	Source event.Source
}

func sourceKey(con Console, app string) string {
	k, _ := con.KeyFor(app)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(con.Host)),
		app,
		k.Reveal(),
		strings.ToLower(strings.TrimSpace(con.Fingerprint)),
		strconv.FormatBool(con.InsecureSkipVerify),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// BuildSources is BuildSourcesKeyed for callers that only want the sources.
func BuildSources(c *Config) ([]event.Source, []error) {
	keyed, problems := BuildSourcesKeyed(c)
	out := make([]event.Source, 0, len(keyed))
	for _, k := range keyed {
		out = append(out, k.Source)
	}
	return out, problems
}
