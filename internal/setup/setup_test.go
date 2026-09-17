package setup

import (
	"strings"
	"testing"
	"time"
)

func workable() Input {
	return Input{
		ConfigPath:       "/etc/notifymatrix/config.yaml",
		Listen:           "0.0.0.0:8322",
		Consoles:         1,
		HasConsoleKey:    true,
		SourceNames:      []string{"protect", "access"},
		ChannelsEnabled:  []string{"ntfy", "email"},
		AckBaseURL:       "http://192.168.1.50:8322",
		PasswordSet:      true,
		ServiceInstalled: true, ServiceRunning: true, RecoversFromCrash: true,
	}
}

func step(t *testing.T, in Input, title string) Step {
	t.Helper()
	for _, s := range Steps(in) {
		if strings.Contains(s.Title, title) {
			return s
		}
	}
	t.Fatalf("no step matching %q", title)
	return Step{}
}

// THE PROPERTY A TEST FOUND THE HARD WAY.
//
// The hook URL carries its token. It is gated in the web handler by being read
// from one field -- so it must not also appear in the instruction prose, which
// that gate does not touch. An earlier version put it in both, and the public
// checklist endpoint published every token.
func TestHookURLsNeverAppearInTheInstructionText(t *testing.T) {
	in := workable()
	in.Hooks = []HookState{
		{Name: "wan", Product: "network", URL: "http://192.168.1.50:8322/hook/SECRET-TOKEN-VALUE"},
	}

	for _, s := range Steps(in) {
		for _, h := range s.How {
			if strings.Contains(h, "SECRET-TOKEN-VALUE") {
				t.Fatalf("a hook token appears in step %q instructions: %q", s.Title, h)
			}
		}
		if strings.Contains(s.State, "SECRET-TOKEN-VALUE") {
			t.Fatalf("a hook token appears in step %q state", s.Title)
		}
		if strings.Contains(s.Why, "SECRET-TOKEN-VALUE") {
			t.Fatalf("a hook token appears in step %q reason", s.Title)
		}
	}

	// And the operator is still told the URLs exist and where to find them.
	got := step(t, in, "Alarm Manager")
	if !strings.Contains(strings.Join(got.How, " "), "listed separately") {
		t.Errorf("the instructions never point at the URLs: %v", got.How)
	}
}

// The CLI DOES print them, because it runs on a machine already holding the
// config file.
func TestTheRenderedChecklistPrintsTheURLsAndWhetherAnythingArrived(t *testing.T) {
	in := workable()
	in.Hooks = []HookState{
		{Name: "wan", Product: "network", URL: "http://192.168.1.50:8322/hook/TOKEN-A"},
		{Name: "threat", Product: "network", URL: "http://192.168.1.50:8322/hook/TOKEN-B",
			Count: 3, LastAt: time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)},
	}

	var b strings.Builder
	Render(&b, in, true)
	out := b.String()

	for _, want := range []string{"TOKEN-A", "TOKEN-B", "nothing has ever arrived here", "3 alarm(s) received"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing from the rendered checklist", want)
		}
	}
}

// Configured is not the same as working. Alarm Manager rules cannot be created
// through any API, so a hook that looks right is no evidence that anybody made
// the rule.
func TestAHookWithNoTrafficIsUnverifiedNotDone(t *testing.T) {
	in := workable()
	in.Hooks = []HookState{{Name: "wan", URL: "http://x/hook/t"}}

	got := step(t, in, "Alarm Manager")
	if got.Status != Unverified {
		t.Errorf("status = %q, want unverified", got.Status)
	}
	if !strings.Contains(got.State, "nothing has ever arrived") {
		t.Errorf("state = %q", got.State)
	}

	in.Hooks[0].Count = 1
	if got := step(t, in, "Alarm Manager"); got.Status != Done {
		t.Errorf("after an alarm arrived, status = %q, want done", got.Status)
	}
}

// Partial evidence is its own answer: one rule working does not mean the other
// one does.
func TestOneWorkingHookDoesNotVouchForTheOthers(t *testing.T) {
	in := workable()
	in.Hooks = []HookState{
		{Name: "wan", Count: 4},
		{Name: "threat", Count: 0},
	}
	got := step(t, in, "Alarm Manager")
	if got.Status != Unverified {
		t.Errorf("status = %q, want unverified while one hook is untested", got.Status)
	}
	if !strings.Contains(got.State, "threat") {
		t.Errorf("state = %q, want it to name the untested hook", got.State)
	}
}

// The setting people most often get wrong, and the one whose failure only
// shows up at 3am on somebody's phone.
func TestALoopbackAckURLIsReportedAsWrong(t *testing.T) {
	for _, bad := range []string{"http://127.0.0.1:8322", "http://localhost:8322"} {
		in := workable()
		in.AckBaseURL = bad
		got := step(t, in, "acknowledgement")
		if got.Status != Todo {
			t.Errorf("%s: status = %q, want todo -- the link would open nothing "+
				"on the phone holding it", bad, got.Status)
		}
	}
	if got := step(t, workable(), "acknowledgement"); got.Status != Done {
		t.Errorf("a LAN address was rejected: %q", got.State)
	}
}

// A service that looks completely healthy and will not come back from a panic.
func TestAServiceThatWillNotRestartAfterACrashIsNotDone(t *testing.T) {
	in := workable()
	in.RecoversFromCrash = false
	got := step(t, in, "service")
	if got.Status != Todo {
		t.Errorf("status = %q, want todo", got.Status)
	}
	if !strings.Contains(got.State, "NOT restart") {
		t.Errorf("state = %q, want it to be unmissable", got.State)
	}
}

// Ready means "can raise and deliver an alarm", not "every box ticked".
// Telling somebody they are not ready when they are is how a checklist gets
// ignored.
func TestReadyMeansItCanActuallyDeliver(t *testing.T) {
	in := workable()
	if !Ready(in) {
		t.Fatal("a complete configuration was reported as not ready")
	}

	// Still ready without the optional extras.
	in.PasswordSet = false
	in.ServiceInstalled = false
	in.AckBaseURL = ""
	if !Ready(in) {
		t.Error("ready went false for things that do not stop an alarm being delivered")
	}

	for _, breakIt := range []func(*Input){
		func(i *Input) { i.Consoles = 0 },
		func(i *Input) { i.HasConsoleKey = false },
		func(i *Input) { i.SourceNames = nil },
		func(i *Input) { i.ChannelsEnabled = nil },
	} {
		bad := workable()
		breakIt(&bad)
		if Ready(bad) {
			t.Errorf("reported ready with a missing essential: %+v", bad)
		}
	}
}

// A source that is running and broken is more urgent than one that was never
// configured, and must not be hidden behind a green tick.
func TestAFailedSourceOverridesAConfiguredLookingStep(t *testing.T) {
	in := workable()
	in.SourcesLive = []SourceState{{Name: "access", Fatal: "console refused the credential"}}

	got := step(t, in, "watch")
	if got.Status != Todo {
		t.Errorf("status = %q, want todo", got.Status)
	}
	if !strings.Contains(got.State, "refused") {
		t.Errorf("state = %q, want the actual failure", got.State)
	}
}

// One channel works, and the operator should know what they are choosing.
func TestASingleChannelIsFlaggedWithoutBeingCalledBroken(t *testing.T) {
	in := workable()
	in.ChannelsEnabled = []string{"ntfy"}
	got := step(t, in, "told")
	if got.Status != Optional {
		t.Errorf("status = %q, want optional", got.Status)
	}

	in.ChannelsEnabled = nil
	if got := step(t, in, "told"); got.Status != Todo {
		t.Errorf("with no channel, status = %q, want todo", got.Status)
	}
}

// Every step has to say what goes wrong if it is skipped. "Do this" without
// "or else" is an instruction people postpone.
func TestEveryStepExplainsItselfAndSaysHow(t *testing.T) {
	for _, s := range Steps(Input{}) {
		if strings.TrimSpace(s.Why) == "" {
			t.Errorf("step %q has no reason", s.Title)
		}
		if len(s.How) == 0 {
			t.Errorf("step %q says nothing about how to do it", s.Title)
		}
		if strings.TrimSpace(s.State) == "" {
			t.Errorf("step %q does not say what is true now", s.Title)
		}
	}
}

// The unconfigured case is the one a new user meets, and it must not be empty
// or reassuring.
func TestAFreshInstallIsReportedAsNotReady(t *testing.T) {
	var b strings.Builder
	Render(&b, Input{ConfigPath: "/x/config.yaml"}, false)
	out := b.String()

	if !strings.Contains(out, "NOT READY") {
		t.Error("a fresh install did not say it cannot deliver an alarm")
	}
	if !strings.Contains(out, "/x/config.yaml") {
		t.Error("the checklist never names the file to edit")
	}
	if n := len(Remaining(Input{})); n < 5 {
		t.Errorf("remaining = %d on a fresh install", n)
	}
}

// The terminal is 80 columns wide more often than not.
func TestRenderedLinesStayReadableInATerminal(t *testing.T) {
	in := workable()
	in.Hooks = []HookState{{Name: "wan", URL: strings.Repeat("x", 60)}}

	var b strings.Builder
	Render(&b, in, true)
	for _, line := range strings.Split(b.String(), "\n") {
		// URLs are exempt: breaking one makes it unpasteable, which is worse
		// than a wrapped line.
		if strings.Contains(line, "xxxx") {
			continue
		}
		if len(line) > 90 {
			t.Errorf("a %d-character line will wrap badly:\n%s", len(line), line)
		}
	}
}

// THE OFF-SITE CASE, and the state that makes it dangerous.
//
// A public acknowledgement address with nothing scoping the listener means a
// port forward would publish the status page -- cameras, doors, open alarms --
// and the settings sign-in alongside the acknowledgement routes, because a NAT
// rule cannot restrict by path.
func TestAPublicAckURLWithNothingScopedIsReportedAsUnfinished(t *testing.T) {
	in := workable()
	in.AckBaseURL = "https://alarms.example.com"
	in.PublicAckURL = true
	in.AckScoped = false

	got := step(t, in, "acknowledgement")
	if got.Status != Todo {
		t.Fatalf("status = %q, want todo", got.Status)
	}
	for _, want := range []string{"public", "ack_listen", "status page"} {
		if !strings.Contains(got.State, want) {
			t.Errorf("state = %q, want it to mention %q", got.State, want)
		}
	}
}

// Scoped and over TLS is finished, and says what is scoping it.
func TestAScopedPublicAckURLIsDone(t *testing.T) {
	in := workable()
	in.AckBaseURL = "https://alarms.example.com"
	in.PublicAckURL = true
	in.AckScoped = true
	in.AckListen = "0.0.0.0:49898"

	got := step(t, in, "acknowledgement")
	if got.Status != Done {
		t.Fatalf("status = %q, want done: %s", got.Status, got.State)
	}
	if !strings.Contains(got.State, "49898") {
		t.Errorf("state = %q, want it to name the scoped listener", got.State)
	}
}

// Scoped but plain http still leaks the token in transit.
func TestAScopedButUnencryptedPublicAckURLIsFlagged(t *testing.T) {
	in := workable()
	in.AckBaseURL = "http://alarms.example.com"
	in.PublicAckURL = true
	in.AckScoped = true

	got := step(t, in, "acknowledgement")
	if got.Status == Done {
		t.Fatal("a public token in the clear was reported as finished")
	}
	if !strings.Contains(got.State, "token") {
		t.Errorf("state = %q, want it to say what is exposed", got.State)
	}
}

// The instructions have to lead with the option that is both safer and easier,
// or people take the harder one and get it wrong.
func TestTheOffSiteInstructionsLeadWithTheVPN(t *testing.T) {
	got := step(t, workable(), "acknowledgement")
	// The off-site discussion is reference material under the step, not
	// part of How: it is seven paragraphs an operator on a LAN never needs.
	if len(got.Reference) == 0 {
		t.Fatalf("the acknowledgement step has no reference topic; the off-site "+
			"instructions have gone:\n%s", strings.Join(got.How, "\n"))
	}
	joined := strings.Join(got.Reference[0].Lines, "\n")

	vpn := strings.Index(joined, "VPN")
	forward := strings.Index(joined, "FORWARD A PORT")
	if vpn < 0 || forward < 0 {
		t.Fatalf("the off-site options are not both described:\n%s", joined)
	}
	if vpn > forward {
		t.Error("the port-forward option is described before the VPN one")
	}
	for _, want := range []string{"CANNOT", "status page", "TCP only", "TLS", "mobile data"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the instructions never mention %q", want)
		}
	}
}

// The setup token is printed to the daemon's STDOUT. A Windows service has no
// stdout, so once installed the token is minted into a void and no restart
// will ever show it. The checklist's only instruction was "enter the token the
// daemon printed" -- which, for the majority of installs, is an instruction to
// go and find something that was never displayed.
func TestThePasswordStepDoesNotSendAServiceInstallLookingForATokenItCannotSee(t *testing.T) {
	in := Input{Listen: "127.0.0.1:8322", PasswordSet: false, ServiceInstalled: true}
	s := passwordStep(in)

	how := strings.Join(s.How, " ")
	if !strings.Contains(how, "set-password") {
		t.Errorf("an installed service is not told about set-password, which is its only route:\n  %s", how)
	}
	if strings.Contains(how, "setup token") {
		t.Errorf("an installed service is still told to use the setup token, which it can never see:\n  %s", how)
	}
	if !strings.Contains(s.State, "not reachable") {
		t.Errorf("the state does not say why the usual route is unavailable: %q", s.State)
	}
	// Setting it while the daemon holds the old config in memory does nothing
	// until it restarts, and saying so is the difference between "it worked"
	// and "I set it and still cannot log in".
	if !strings.Contains(how, "restart") {
		t.Errorf("nothing says the service has to be restarted:\n  %s", how)
	}
}

// Before it is a service, the token route is the right one and still works --
// this must not have been traded away for the fix above.
func TestThePasswordStepStillOffersTheTokenBeforeInstall(t *testing.T) {
	in := Input{Listen: "127.0.0.1:8322", PasswordSet: false, ServiceInstalled: false}
	s := passwordStep(in)

	how := strings.Join(s.How, " ")
	if !strings.Contains(how, "setup token") {
		t.Errorf("the console route disappeared:\n  %s", how)
	}
	if !strings.Contains(how, "set-password") {
		t.Errorf("the alternative is not mentioned at all:\n  %s", how)
	}
	if s.Status != Todo {
		t.Errorf("status = %v, want Todo", s.Status)
	}
}

// Every instruction this checklist printed read "notifymatrix install".
// Nobody who downloads a release has a program called that: they have
// notifymatrix-windows-amd64.exe -- "notifymatrix-windows-amd64 (1).exe" after
// a second download -- sitting in Downloads and not on PATH. So every command
// here failed with "not recognized", and the checklist never mentioned the one
// problem standing between them and all of it.
func TestCommandsNameTheFileTheOperatorActuallyHas(t *testing.T) {
	for _, tc := range []struct{ name, exe, want string }{
		{"packaged install", "", "notifymatrix install"},
		{"plain name needs nothing", "notifymatrix", "notifymatrix install"},
		{"a downloaded asset", "notifymatrix-windows-amd64.exe", "notifymatrix-windows-amd64.exe install"},
		{"a second download", "notifymatrix-windows-amd64 (1).exe", `& ".\notifymatrix-windows-amd64 (1).exe" install`},
		{"a space alone is enough", "notify matrix.exe", `& ".\notify matrix.exe" install`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Input{Exe: tc.exe}).Command("install"); got != tc.want {
				t.Errorf("Command(install) with Exe=%q\n  got  %s\n  want %s", tc.exe, got, tc.want)
			}
		})
	}
}

// The name reaches the steps, not just the helper. A correct renderer nothing
// calls fixes nothing.
func TestTheRenderedStepsUseTheRealName(t *testing.T) {
	in := Input{Exe: "notifymatrix-windows-amd64 (1).exe", Listen: "127.0.0.1:8322"}
	var found bool
	for _, s := range Steps(in) {
		for _, h := range s.How {
			if strings.Contains(h, "notifymatrix-windows-amd64 (1).exe") {
				found = true
			}
			// "Run: notifymatrix install" must not survive anywhere.
			if strings.Contains(h, "Run: notifymatrix ") {
				t.Errorf("step %q still tells them to run a program they do not have:\n  %s", s.Title, h)
			}
		}
	}
	if !found {
		t.Error("no step mentions the executable the operator actually has")
	}
}

// Reported from a live install: the process was plainly running and the
// interface "was not". web.listen had been pinned to one address, so
// 127.0.0.1 -- which every message, document and habit prints -- stopped
// working. Nothing anywhere said that would happen.
func TestPinningTheListenerToOneAddressSaysLoopbackWillStopWorking(t *testing.T) {
	in := Input{
		Listen:     "192.168.20.115:50001",
		AckBaseURL: "http://192.168.20.115:50001",
	}
	s := ackStep(in)
	if !strings.Contains(s.State, "127.0.0.1") {
		t.Errorf("a pinned listener does not warn that loopback stops working:\n  %s", s.State)
	}
	// It still WORKS, so it must not be reported as unfinished.
	if s.Status == Todo {
		t.Errorf("a working configuration was marked as todo: %s", s.State)
	}
}

// The other half of the same report: an ack address is meaningless if nothing
// accepts connections there. Each setting looks right alone.
func TestAnAckAddressWithALoopbackListenerIsReportedAsUnfinished(t *testing.T) {
	in := Input{
		Listen:     "127.0.0.1:8322",
		AckBaseURL: "https://alerts.example.com",
	}
	s := ackStep(in)
	if s.Status != Todo {
		t.Fatalf("an unreachable ack address was not flagged: %v / %s", s.Status, s.State)
	}
	if !strings.Contains(s.State, "0.0.0.0") {
		t.Errorf("the state does not say what to set instead:\n  %s", s.State)
	}
}

// An https address aimed at the port this program serves in plain HTTP. The
// address is right, the port is right, the scheme is the one everybody knows
// they should use, and nothing connects.
func TestAnHTTPSAckURLAimedAtThePlainListenerIsFlagged(t *testing.T) {
	in := Input{
		Listen:     "0.0.0.0:50001",
		AckBaseURL: "https://notifymatrix.example.com:50001",
	}
	s := ackStep(in)
	if s.Status != Todo {
		t.Fatalf("an https URL aimed at the plain listener was accepted: %v / %s",
			s.Status, s.State)
	}
	if !strings.Contains(s.State, "plain HTTP") {
		t.Errorf("the state does not say why it cannot work:\n  %s", s.State)
	}
}

// Behind a reverse proxy on a DIFFERENT port, https is correct and must not be
// nagged -- that is the configuration the instructions recommend.
func TestAnHTTPSAckURLOnAnotherPortIsFine(t *testing.T) {
	in := Input{
		Listen:     "0.0.0.0:50001",
		AckListen:  "0.0.0.0:51234",
		AckScoped:  true,
		AckBaseURL: "https://alerts.example.com",
	}
	if s := ackStep(in); s.Status == Todo {
		t.Errorf("a proxied setup was flagged: %s", s.State)
	}
}

// The instructions must name BOTH settings. Telling somebody the ack address
// and not the listener is how the reported failure happened.
func TestTheInstructionsNameTheListenerAsWellAsTheAddress(t *testing.T) {
	how := strings.Join(ackStep(Input{Listen: "127.0.0.1:8322"}).How, "\n")
	for _, want := range []string{"web.listen", "web.ack_base_url", "0.0.0.0", "plain HTTP"} {
		if !strings.Contains(how, want) {
			t.Errorf("the instructions never mention %q:\n%s", want, how)
		}
	}
}

// A warning in the checklist leads with capitals. That was only a habit until
// the interface started drawing warnings as callouts; now it is the rule, and
// a line that should be a callout and is not gets found here rather than by
// an operator reading it at the same weight as the step beside it.
func TestWarningsAreTheLinesThatLeadWithCapitals(t *testing.T) {
	for _, tc := range []struct {
		line string
		want LineKind
	}{
		{"IF YOU MUST FORWARD A PORT, scope it.", Warning},
		{"ADD THE HEADER TOO. Both are listed below.", Warning},
		{"TWO settings have to agree", Warning},
		{"BEST: a VPN. WireGuard or Tailscale, on the phone.", Aside},
		{"A guessable topic on the public ntfy.sh server", Action},
		{"Run: notifymatrix install", Action},
		{"In the UniFi console, open the application", Action},
		{"ntfy is the quickest", Action},
		{"", Action},
	} {
		if got := KindOf(tc.line); got != tc.want {
			t.Errorf("KindOf(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}

	// And the steps actually contain some, or the convention is decorative.
	var warnings int
	for _, s := range Steps(Input{}) {
		for _, h := range s.How {
			if KindOf(h) == Warning {
				warnings++
			}
		}
	}
	if warnings == 0 {
		t.Error("no step carries a warning line; the callouts have gone")
	}
}

// Every step has a stable key, and the hooks step's is the one the renderers
// put the credentials under. Matching on the title text is how a rewording
// would move them somewhere else without anybody noticing.
func TestEveryStepHasAStableKey(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Steps(Input{}) {
		if s.Key == "" {
			t.Errorf("step %q has no key", s.Title)
		}
		if seen[s.Key] {
			t.Errorf("key %q is used twice", s.Key)
		}
		seen[s.Key] = true
	}
	if step(t, Input{}, hooksTitle).Key != "hooks" {
		t.Error("the hooks step is not keyed \"hooks\", so the credentials will be printed under the wrong step")
	}
}
