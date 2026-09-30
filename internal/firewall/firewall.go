// Package firewall keeps Windows Firewall rules for the listeners that are
// MEANT to be reached from another machine: the ack-only listener and the
// peer link listener.
//
// Found on a real site: the acknowledgement link was right, the router
// forwarded the port, and every Acknowledge button still timed out, because
// Windows Firewall dropped the connection before this program saw it. The fix
// was a rule typed by hand into Defender. The Web settings are where that port
// is chosen, so that is where the rule is offered -- with the exact command,
// for anyone who would rather run it themselves or cannot let the service do
// it.
//
// NEVER web.listen. That is the status page and the settings sign-in, and the
// ack-only listener exists precisely so that nothing has to open it. A rule
// here is pinned to one port and to this program's own path, and lives in one
// named group so it can be found, checked and removed.
package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Group is the rule group everything this program creates belongs to.
const Group = "NotifyMatrix"

// Want is one listener and what it needs from the firewall.
type Want struct {
	// Name is the rule's unique id, stable across port changes so that
	// updating a rule replaces it rather than leaving the old port open.
	Name string `json:"name"`
	// Purpose is what the listener is for, in the operator's words.
	Purpose string `json:"purpose"`
	// Setting is the configuration key the port comes from.
	Setting string `json:"setting"`
	// Port is the TCP port to allow, or 0 when no rule is wanted.
	Port int `json:"port,omitempty"`
	// Skip says why no rule is wanted, when none is.
	Skip string `json:"skip,omitempty"`
}

const (
	ackRule  = "NotifyMatrix-ack"
	linkRule = "NotifyMatrix-link"
)

// Plan decides which listeners get a rule, from the SAVED addresses: the
// rule is ready for the listener the next start will open.
func Plan(ackListen, linkListen string) []Want {
	return []Want{
		plan(Want{Name: ackRule, Purpose: "acknowledgements", Setting: "web.ack_listen"}, ackListen),
		plan(Want{Name: linkRule, Purpose: "peer link", Setting: "web.link_listen"}, linkListen),
	}
}

const thisMachineOnly = "bound to this machine only, so nothing outside it can " +
	"connect and there is nothing to allow"

func plan(w Want, addr string) Want {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		w.Skip = "not set, so there is no listener to allow"
		return w
	}
	if strings.EqualFold(addr, "auto") {
		w.Skip = "\"auto\" -- the port is chosen and saved at the next start; come back after it"
		return w
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		w.Skip = "not an address this can read"
		return w
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		w.Skip = "not a port this can read"
		return w
	}
	if p == 0 {
		w.Skip = "port 0 -- chosen and saved at the next start; come back after it"
		return w
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		w.Skip = thisMachineOnly
		return w
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		w.Skip = thisMachineOnly
		return w
	}
	w.Port = p
	return w
}

// Found is a rule as the firewall reports it.
type Found struct {
	Name    string `json:"name"`
	Enabled string `json:"enabled"`
	Action  string `json:"action"`
	Port    string `json:"port"`
	Program string `json:"program"`
}

// Rule is one listener's state against the firewall.
type Rule struct {
	Want
	// Status is "allowed", "missing", "stale" or "not needed".
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Evaluate compares what is wanted with what is there.
func Evaluate(wants []Want, found []Found, program string) []Rule {
	byName := map[string]Found{}
	for _, f := range found {
		byName[f.Name] = f
	}
	out := make([]Rule, 0, len(wants))
	for _, w := range wants {
		f, have := byName[w.Name]
		r := Rule{Want: w}
		switch {
		case w.Port == 0 && have:
			// A rule left open for a listener that is no longer reachable
			// from outside, or no longer exists: an open port nobody meant.
			r.Status = "stale"
			r.Detail = "a rule for TCP " + f.Port + " is left from before, and " +
				w.Setting + " is " + w.Skip + "; applying removes it"
		case w.Port == 0:
			r.Status, r.Detail = "not needed", w.Skip
		case !have:
			r.Status = "missing"
			r.Detail = fmt.Sprintf("no rule allows TCP %d, so connections from other "+
				"machines are dropped before this program sees them", w.Port)
		case f.Port != strconv.Itoa(w.Port):
			r.Status = "stale"
			r.Detail = fmt.Sprintf("the rule allows TCP %s, but the listener is on %d", f.Port, w.Port)
		case !strings.EqualFold(f.Enabled, "True"):
			r.Status, r.Detail = "stale", "the rule exists but is switched off"
		case !strings.EqualFold(f.Action, "Allow"):
			r.Status, r.Detail = "stale", "the rule exists but is set to "+f.Action
		case program != "" && !strings.EqualFold(f.Program, program):
			r.Status = "stale"
			r.Detail = "the rule is for " + f.Program + ", not this copy of the program"
		default:
			r.Status = "allowed"
			r.Detail = fmt.Sprintf("TCP %d is allowed in", w.Port)
		}
		out = append(out, r)
	}
	return out
}

// Report is everything the Web settings need.
type Report struct {
	// Supported is false on anything but Windows; the page then says nothing.
	Supported bool `json:"supported"`
	// FirewallOn is false when every profile is switched off, in which case
	// nothing here matters and the page says so.
	FirewallOn bool   `json:"firewall_on"`
	Rules      []Rule `json:"rules"`
	// NeedsFix is true when any rule is missing or stale.
	NeedsFix bool `json:"needs_fix"`
	// Command is the exact PowerShell that applying runs, for an
	// administrator terminal.
	Command string `json:"command"`
}

// psQuote makes a PowerShell single-quoted string literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ApplyScript is the PowerShell that brings the rules in line with wants:
// every rule of ours is removed and the wanted ones created afresh, so a port
// that changed never leaves the old one open.
func ApplyScript(program string, wants []Want) string {
	var b strings.Builder
	for _, w := range wants {
		fmt.Fprintf(&b, "Remove-NetFirewallRule -Name %s -ErrorAction SilentlyContinue\n", psQuote(w.Name))
	}
	for _, w := range wants {
		if w.Port == 0 {
			continue
		}
		fmt.Fprintf(&b, "New-NetFirewallRule -Name %s -DisplayName %s -Group %s "+
			"-Direction Inbound -Action Allow -Protocol TCP -LocalPort %d "+
			"-Program %s -Profile Any | Out-Null\n",
			psQuote(w.Name),
			psQuote(fmt.Sprintf("NotifyMatrix %s (TCP %d)", w.Purpose, w.Port)),
			psQuote(Group), w.Port, psQuote(program))
	}
	return b.String()
}

// statusScript reads our rules and whether the firewall is on at all. It
// needs no administrator rights.
const statusScript = `$ErrorActionPreference = 'Stop'
$r = @(Get-NetFirewallRule -Group '` + Group + `' -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    name    = [string]$_.Name
    enabled = [string]$_.Enabled
    action  = [string]$_.Action
    port    = [string](@(($_ | Get-NetFirewallPortFilter).LocalPort) -join ',')
    program = [string]($_ | Get-NetFirewallApplicationFilter).Program
  }
})
$on = @(Get-NetFirewallProfile | Where-Object { $_.Enabled }).Count -gt 0
ConvertTo-Json -Compress -Depth 3 -InputObject @{ rules = $r; on = $on }
`

// Runner runs a PowerShell script and returns its combined output.
type Runner func(ctx context.Context, script string) ([]byte, error)

// Firewall reads and writes the rules for one program.
type Firewall struct {
	Supported bool
	Program   string
	Run       Runner
}

// Status reports the rules against the saved listener addresses.
func (f Firewall) Status(ctx context.Context, ackListen, linkListen string) (Report, error) {
	if !f.Supported {
		return Report{}, nil
	}
	wants := Plan(ackListen, linkListen)
	rep := Report{Supported: true, Command: ApplyScript(f.Program, wants)}
	out, err := f.Run(ctx, statusScript)
	if err != nil {
		return rep, fmt.Errorf("reading Windows Firewall rules: %w: %s", err, truncate(out))
	}
	var got struct {
		Rules []Found `json:"rules"`
		On    bool    `json:"on"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		return rep, fmt.Errorf("reading Windows Firewall rules: unexpected output %q", truncate(out))
	}
	rep.FirewallOn = got.On
	rep.Rules = Evaluate(wants, got.Rules, f.Program)
	for _, r := range rep.Rules {
		if r.Status == "missing" || r.Status == "stale" {
			rep.NeedsFix = true
		}
	}
	return rep, nil
}

// ErrNeedsAdmin is returned when the rules could not be changed for want of
// rights: the page then points at the command.
var ErrNeedsAdmin = errors.New("changing Windows Firewall needs administrator rights. " +
	"The installed service has them; a copy started from an ordinary terminal " +
	"does not. Run the command shown here in an administrator PowerShell instead")

// Apply brings the rules in line with the saved addresses, then reports.
func (f Firewall) Apply(ctx context.Context, ackListen, linkListen string) (Report, error) {
	if !f.Supported {
		return Report{}, errors.New("there is no Windows Firewall on this system")
	}
	script := "$ErrorActionPreference = 'Stop'\n" + ApplyScript(f.Program, Plan(ackListen, linkListen))
	if out, err := f.Run(ctx, script); err != nil {
		if deniedAccess(string(out) + " " + err.Error()) {
			return Report{}, ErrNeedsAdmin
		}
		return Report{}, fmt.Errorf("changing Windows Firewall: %w: %s", err, truncate(out))
	}
	return f.Status(ctx, ackListen, linkListen)
}

// RemoveAll removes every rule this program made, for uninstall.
func (f Firewall) RemoveAll(ctx context.Context) error {
	if !f.Supported {
		return nil
	}
	_, err := f.Run(ctx, "Remove-NetFirewallRule -Group "+psQuote(Group)+" -ErrorAction SilentlyContinue\n")
	return err
}

func deniedAccess(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "access is denied") || strings.Contains(s, "permissiondenied") ||
		strings.Contains(s, "0x80070005")
}

func truncate(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}
