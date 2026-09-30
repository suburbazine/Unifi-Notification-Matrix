package firewall

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// WHICH LISTENERS GET A RULE.
//
// Only the two meant to be reached from elsewhere, only when they are, and
// never for a port that is not decided yet.
func TestPlan(t *testing.T) {
	for _, tc := range []struct {
		name, ack, link   string
		wantAck, wantLink int
	}{
		{"the field case: ack on 50001, link on loopback", "0.0.0.0:50001", "127.0.0.1:63823", 50001, 0},
		{"both reachable", "0.0.0.0:50001", "0.0.0.0:50002", 50001, 50002},
		{"a LAN address is reachable", "192.168.1.50:50001", "", 50001, 0},
		{"IPv6 every interface", "[::]:50001", "", 50001, 0},
		{"localhost is this machine only", "localhost:50001", "", 0, 0},
		{"IPv6 loopback", "[::1]:50001", "", 0, 0},
		{"auto is not a port yet", "auto", "auto", 0, 0},
		{"port 0 is not a port yet", "0.0.0.0:0", "", 0, 0},
		{"not set", "", "", 0, 0},
		{"unreadable", "nonsense", "0.0.0.0:99999", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Plan(tc.ack, tc.link)
			if len(got) != 2 {
				t.Fatalf("planned %d listeners, want exactly the ack and link ones", len(got))
			}
			if got[0].Port != tc.wantAck || got[1].Port != tc.wantLink {
				t.Errorf("ports = %d/%d, want %d/%d (%+v)", got[0].Port, got[1].Port,
					tc.wantAck, tc.wantLink, got)
			}
			for _, w := range got {
				if w.Port == 0 && w.Skip == "" {
					t.Errorf("%s gets no rule and no reason why", w.Setting)
				}
			}
			// "auto" is not a mistake to correct: it becomes a port at the
			// next start, and the page has to say come back then, not that
			// the address cannot be read.
			if tc.ack == "auto" && !strings.Contains(got[0].Skip, "next start") {
				t.Errorf("for \"auto\" the page says %q", got[0].Skip)
			}
		})
	}
}

const prog = `C:\Program Files\NotifyMatrix\notifymatrix.exe`

// WHAT IS THERE AGAINST WHAT IS WANTED.
func TestEvaluate(t *testing.T) {
	want := Plan("0.0.0.0:50001", "127.0.0.1:63823")
	good := Found{Name: ackRule, Enabled: "True", Action: "Allow", Port: "50001", Program: prog}
	for _, tc := range []struct {
		name     string
		found    []Found
		ack      string // status for the ack rule
		link     string // status for the link rule
		contains string
	}{
		{"nothing there", nil, "missing", "not needed", "dropped"},
		{"right", []Found{good}, "allowed", "not needed", ""},
		{"program path differs only in case", []Found{func() Found {
			f := good
			f.Program = strings.ToUpper(prog)
			return f
		}()}, "allowed", "not needed", ""},
		{"old port", []Found{func() Found { f := good; f.Port = "50000"; return f }()},
			"stale", "not needed", "50000"},
		{"switched off", []Found{func() Found { f := good; f.Enabled = "False"; return f }()},
			"stale", "not needed", "switched off"},
		{"blocking", []Found{func() Found { f := good; f.Action = "Block"; return f }()},
			"stale", "not needed", "Block"},
		{"another copy", []Found{func() Found { f := good; f.Program = `D:\old\nm.exe`; return f }()},
			"stale", "not needed", `D:\old\nm.exe`},
		// The link listener moved back to loopback and its rule was left
		// behind: an open port nobody meant.
		{"left-over rule", []Found{good, {Name: linkRule, Enabled: "True", Action: "Allow",
			Port: "50002", Program: prog}}, "allowed", "stale", "50002"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(want, tc.found, prog)
			if got[0].Status != tc.ack || got[1].Status != tc.link {
				t.Fatalf("statuses = %s/%s, want %s/%s (%+v)", got[0].Status, got[1].Status,
					tc.ack, tc.link, got)
			}
			if tc.contains != "" && !strings.Contains(got[0].Detail+got[1].Detail, tc.contains) {
				t.Errorf("details %q / %q do not say %q", got[0].Detail, got[1].Detail, tc.contains)
			}
		})
	}
}

// THE COMMAND. It is shown to the operator to paste, and it is what the
// button runs -- one string, so the two cannot differ.
func TestApplyScript(t *testing.T) {
	odd := `C:\Users\O'Brien\nm.exe`
	s := ApplyScript(odd, Plan("0.0.0.0:50001", "127.0.0.1:63823"))

	// Every rule of ours is removed first, so a changed port never leaves
	// the old one open -- including the one no longer wanted.
	for _, name := range []string{ackRule, linkRule} {
		if !strings.Contains(s, "Remove-NetFirewallRule -Name '"+name+"'") {
			t.Errorf("the script does not clear %s first:\n%s", name, s)
		}
	}
	if strings.Count(s, "New-NetFirewallRule") != 1 {
		t.Errorf("want exactly one rule created, for the ack listener:\n%s", s)
	}
	for _, part := range []string{"-LocalPort 50001", "-Protocol TCP", "-Direction Inbound",
		"-Action Allow", "-Group 'NotifyMatrix'", "-Name 'NotifyMatrix-ack'"} {
		if !strings.Contains(s, part) {
			t.Errorf("the rule is missing %q:\n%s", part, s)
		}
	}
	// Pinned to the program, with a quote in its path doubled, never closed.
	if !strings.Contains(s, `-Program 'C:\Users\O''Brien\nm.exe'`) {
		t.Errorf("the program path is not quoted safely:\n%s", s)
	}
	if strings.Contains(s, "63823") {
		t.Errorf("a rule was made for a loopback listener:\n%s", s)
	}
}

func fakeRunner(out string, err error) (Runner, *[]string) {
	var seen []string
	return func(_ context.Context, script string) ([]byte, error) {
		seen = append(seen, script)
		return []byte(out), err
	}, &seen
}

// Read, parsed, and judged.
func TestStatusReadsTheFirewall(t *testing.T) {
	run, _ := fakeRunner(`{"on":true,"rules":[{"name":"NotifyMatrix-ack","enabled":"True",`+
		`"action":"Allow","port":"50000","program":"`+strings.ReplaceAll(prog, `\`, `\\`)+`"}]}`, nil)
	f := Firewall{Supported: true, Program: prog, Run: run}
	rep, err := f.Status(context.Background(), "0.0.0.0:50001", "")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.FirewallOn || !rep.NeedsFix || rep.Rules[0].Status != "stale" {
		t.Errorf("report %+v: a rule on the old port must read as needing a fix", rep)
	}
	if !strings.Contains(rep.Command, "-LocalPort 50001") {
		t.Errorf("the command does not fix it: %s", rep.Command)
	}
}

// Without the rights, the operator is sent to the command, not shown a
// PowerShell stack trace.
func TestApplyWithoutRightsPointsAtTheCommand(t *testing.T) {
	run, seen := fakeRunner("", errors.New("exit status 1: New-NetFirewallRule : Access is denied."))
	f := Firewall{Supported: true, Program: prog, Run: run}
	_, err := f.Apply(context.Background(), "0.0.0.0:50001", "")
	if !errors.Is(err, ErrNeedsAdmin) {
		t.Fatalf("err = %v, want ErrNeedsAdmin", err)
	}
	if len(*seen) != 1 || !strings.Contains((*seen)[0], ApplyScript(prog, Plan("0.0.0.0:50001", ""))) {
		t.Errorf("the button did not run the command it shows: %q", *seen)
	}
}

// Nothing is claimed, and nothing run, where there is no Windows Firewall.
func TestUnsupportedSaysNothing(t *testing.T) {
	run, seen := fakeRunner("", nil)
	rep, err := Firewall{Program: prog, Run: run}.Status(context.Background(), "0.0.0.0:50001", "")
	if err != nil || rep.Supported || len(*seen) != 0 {
		t.Errorf("unsupported: report %+v, err %v, ran %d scripts", rep, err, len(*seen))
	}
}

// THE REAL THING, read-only: the script this ships runs on Windows and its
// output parses. The first version's did not -- PowerShell's first-use
// progress record came out ahead of the JSON.
func TestTheStatusScriptRunsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Firewall only")
	}
	if testing.Short() {
		t.Skip("starts PowerShell")
	}
	rep, err := System(prog).Status(context.Background(), "0.0.0.0:50001", "")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Supported || len(rep.Rules) != 2 {
		t.Errorf("report %+v", rep)
	}
}
