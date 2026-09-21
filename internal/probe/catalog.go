package probe

import (
	"errors"
	"strings"
)

// ErrRefused means a request was blocked by this package's own rules rather
// than by the console.
var ErrRefused = errors.New("probe: refused")

// Endpoint is one read-only surface to ask a console about.
type Endpoint struct {
	// Product groups the finding: "protect", "access", "network", "unifi-os".
	Product string

	// Path is appended to the console base. GET only -- see Refuse.
	Path string

	// Auth says which credential this path expects.
	Auth AuthKind

	// Expect describes what a 200 here means, for the operator reading the
	// summary. It is documentation, not a check.
	Expect string

	// Known marks a path this build already relies on. It must track what the
	// sources in internal/source ACTUALLY request -- a path they poll and this
	// field calls unknown is reported as a discovery on every run, and, worse,
	// can never be reported as missing on the firmware that stops serving it.
	// A test asserts the two agree.
	//
	// Known marks a path this build already relies on. An unknown path that
	// answers is a discovery; a known path that stops answering is a
	// regression. The report distinguishes them because the two findings mean
	// opposite things.
	Known bool
}

// AuthKind is which credential a surface takes.
type AuthKind int

const (
	// AuthProtect sends X-API-KEY, spelled in the exact casing working clients
	// use -- see internal/source/protect.
	AuthProtect AuthKind = iota
	// AuthAccess sends X-API-KEY on the proxy path.
	AuthAccess
	// AuthNetwork sends X-API-Key.
	AuthNetwork
	// AuthNone is an unauthenticated path.
	AuthNone
)

// Catalogue is every path the probe may ask about.
//
// It contains paths this build does NOT use, deliberately. A capability probe
// that only asks about what is already handled can only ever confirm what is
// already known, and the entire reason this exists is that Protect's event
// vocabulary went from 16 types to 39 without anybody here noticing.
//
// Everything in it is a GET and everything in it is read-only. That is not a
// convention -- Refuse enforces it, and a test asserts the catalogue obeys it,
// because the entry that breaks the rule will be added by somebody in a hurry.
var Catalogue = []Endpoint{
	// UniFi Protect. Base /proxy/protect/integration/v1.
	{Product: "protect", Auth: AuthProtect, Known: true, Path: "/proxy/protect/integration/v1/meta/info", Expect: "applicationVersion -- the firmware this whole report is about"},
	{Product: "protect", Auth: AuthProtect, Known: true, Path: "/proxy/protect/integration/v1/cameras", Expect: "camera list, with featureFlags"},
	{Product: "protect", Auth: AuthProtect, Known: true, Path: "/proxy/protect/integration/v1/sensors", Expect: "sensor list"},
	{Product: "protect", Auth: AuthProtect, Known: true, Path: "/proxy/protect/integration/v1/nvrs", Expect: "console record; carries no state field"},
	{Product: "protect", Auth: AuthProtect, Path: "/proxy/protect/integration/v1/lights", Expect: "unknown to this build"},
	{Product: "protect", Auth: AuthProtect, Path: "/proxy/protect/integration/v1/chimes", Expect: "unknown to this build"},
	{Product: "protect", Auth: AuthProtect, Path: "/proxy/protect/integration/v1/viewers", Expect: "unknown to this build"},
	{Product: "protect", Auth: AuthProtect, Path: "/proxy/protect/integration/v1/liveviews", Expect: "unknown to this build"},
	{Product: "protect", Auth: AuthProtect, Path: "/proxy/protect/integration/v1/alarm-manager/webhook", Expect: "whether Alarm Manager is readable at all"},
	{Product: "protect", Auth: AuthProtect, Path: "/proxy/protect/integration/v1/files/animations", Expect: "unknown to this build"},

	// UniFi Access. The REST base says `integration` where the socket says
	// `api`; that asymmetry is real and is not a typo on either side.
	{Product: "access", Auth: AuthAccess, Known: true, Path: "/proxy/access/integration/v1/developer/doors", Expect: "door list -- the Access equivalent of /cameras"},
	{Product: "access", Auth: AuthAccess, Path: "/proxy/access/integration/v1/developer/devices", Expect: "hubs and readers"},
	{Product: "access", Auth: AuthAccess, Path: "/proxy/access/integration/v1/developer/door_groups", Expect: "unknown to this build"},
	{Product: "access", Auth: AuthAccess, Path: "/proxy/access/integration/v1/developer/system/info", Expect: "Access version, if this path exists"},

	// UniFi Network. Its Integration API arrived in Network 9.0 and covers no
	// events at all; the probe asks anyway, because "the spec contains zero
	// occurrences of event" is a fact about the spec, not about the console.
	{Product: "network", Auth: AuthNetwork, Known: true, Path: "/proxy/network/integration/v1/sites", Expect: "site list; ids feed the paths below"},
	{Product: "network", Auth: AuthNetwork, Known: true, Path: "/proxy/network/integration/v1/sites/{site}/devices", Expect: "device list for the first site"},
	{Product: "network", Auth: AuthNetwork, Path: "/proxy/network/integration/v1/info", Expect: "controller version, if this path exists"},

	// A CANDIDATE, asked because a design question turns on the answer.
	//
	// A wireless attack -- a deauth flood, a jammer -- shows first as clients
	// leaving an access point, and only later as anything a device list
	// notices. Whether this API exposes a per-device COUNT of them decides
	// whether that is buildable here at all.
	//
	// The client LIST is not asked for and must not be: /clients is refused
	// above as "the site's occupants and their personal devices", and adding
	// it here was caught by the test that holds the catalogue to those rules.
	// A count is a number about a radio; a list is a roster of the people in
	// the building, and no alarm is worth building the second one to get the
	// first.
	{Product: "network", Auth: AuthNetwork, Path: "/proxy/network/integration/v1/sites/{site}/devices/statistics",
		Expect: "whether per-device counters (client counts, radio state) are exposed, WITHOUT naming a client"},
}

// refusal is a path this probe will not request, and why.
type refusal struct {
	match string
	why   string
}

// refusals are checked against every URL before it is requested.
//
// Two different reasons live here and both matter:
//
//   - IRREVERSIBLE. disable-mic-permanently is exactly what it says and needs
//     a factory reset to undo. An earlier in-house probe refused it in prose
//     and by simply not writing the call; that is one careless edit away from
//     being wrong, so here it is a rule the request path checks.
//
//   - PEOPLE. Rosters, credentials, PINs and visitor records are lists of
//     humans. Pseudonymisation would reduce them to a count of rows, so
//     fetching them buys the schema nothing -- and a probe that pulls the
//     credential table into a process that writes files is a bad shape even
//     when the writing is safe.
var refusals = []refusal{
	{"disable-mic-permanently", "irreversible without a factory reset"},
	{"/credentials", "returns credentials themselves"},
	{"/users", "a roster of people; redaction would leave only a row count"},
	{"/user_groups", "a roster of people"},
	{"/visitors", "a roster of people"},
	{"/nfc_cards", "credential material"},
	{"/pin_codes", "credential material"},
	{"/clients", "the site's occupants and their personal devices"},
	{"/logout", "changes session state"},
	{"/factory-reset", "irreversible"},
	{"/reboot", "state-changing"},
	{"/restart", "state-changing"},
	{"/upgrade", "state-changing"},
	{"/firmware", "state-changing"},
	{"/backup", "downloads the console's entire database"},
}

// Refuse reports why a request must not be made, or "" if it may be.
//
// Both halves are enforced here rather than trusted to the catalogue: the
// method check makes every state-changing verb impossible regardless of what a
// caller passes, and the path check catches an entry added later. A probe is
// the one tool where "it only does what the table says" has to be a property
// of the code rather than a property of the table.
func Refuse(method, rawurl string) string {
	if !strings.EqualFold(method, "GET") {
		return "this probe issues GET only; " + strings.ToUpper(method) + " can change the console"
	}
	lower := strings.ToLower(rawurl)
	for _, r := range refusals {
		if strings.Contains(lower, r.match) {
			return r.match + ": " + r.why
		}
	}
	return ""
}

// NeedsSite reports whether an endpoint has to have a site id substituted in
// before it can be requested.
func (e Endpoint) NeedsSite() bool { return strings.Contains(e.Path, "{site}") }

// WithSite substitutes a resolved site id.
func (e Endpoint) WithSite(id string) Endpoint {
	e.Path = strings.ReplaceAll(e.Path, "{site}", id)
	return e
}
