package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// workable is the smallest config that should actually be accepted.
func workable() Config {
	c := Default()
	c.Consoles = []Console{{
		Name:        "main",
		Host:        "10.0.0.1",
		APIKey:      secret.Secret("console-key"),
		Fingerprint: "aa:bb:cc",
		Sources:     []string{"protect"},
	}}
	c.Channels.Ntfy = &Ntfy{Enabled: true, ServerURL: "https://ntfy.sh", Topic: "alarms"}
	c.Web.AckBaseURL = "https://nm.example.com"
	c.applyDefaults()
	return c
}

func TestAWorkableConfigValidates(t *testing.T) {
	if err := workable().Validate(); err != nil {
		t.Fatalf("a minimal working config was rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

const canary = "unifi-api-key-do-not-log-me"

func TestRoundTripEncryptsSecretsAndKeepsEverythingElseReadable(t *testing.T) {
	dir := t.TempDir()
	secret.SetKeyFile(filepath.Join(dir, "secret.key"))

	c := workable()
	c.Consoles[0].APIKey = secret.Secret(canary)
	if err := Save(dir, &c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("the API key is in the file in the clear:\n%s", raw)
	}
	// Everything that is NOT a secret must stay legible: the file is the
	// source of truth and an operator has to be able to read it.
	for _, want := range []string{"10.0.0.1", "main", "alarms", "protect"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the file does not contain %q; it should be readable:\n%s", want, raw)
		}
	}
	// And it must record how the secrets were protected, and by which host.
	if !strings.Contains(string(raw), "host_fingerprint") {
		t.Error("no host fingerprint recorded; a config moved between machines " +
			"could not then be told apart from a corrupt one")
	}

	back, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := back.Consoles[0].APIKey.Reveal(); got != canary {
		t.Errorf("round trip lost the key: %q", got)
	}
	if back.Consoles[0].Host != "10.0.0.1" {
		t.Errorf("round trip lost the host: %q", back.Consoles[0].Host)
	}
}

func TestSaveRefusesToPersistAnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	secret.SetKeyFile(filepath.Join(dir, "secret.key"))

	c := workable()
	c.Consoles[0].Host = "" // now invalid

	if err := Save(dir, &c); err == nil {
		t.Fatal("an invalid config was written; the daemon reloads from this " +
			"file, so writing something it will refuse to load turns a bad " +
			"form submission into a service that cannot start")
	}
	if _, err := os.Stat(Path(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a file was left behind by the refused write")
	}
}

func TestSaveLeavesNoTemporaryFilesBehind(t *testing.T) {
	dir := t.TempDir()
	secret.SetKeyFile(filepath.Join(dir, "secret.key"))
	c := workable()
	if err := Save(dir, &c); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestLoadReportsAMissingConfigAsMissingNotBroken(t *testing.T) {
	_, err := Load(t.TempDir())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load on an empty directory = %v, want ErrNotFound -- a fresh "+
			"install is not a fault", err)
	}
}

func TestLoadOrCreateWritesAUsableDefault(t *testing.T) {
	dir := t.TempDir()
	secret.SetKeyFile(filepath.Join(dir, "secret.key"))

	c, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	// A fresh install must not invent a destination for alerts.
	if len(c.Consoles) != 0 || c.anyChannelEnabled() {
		t.Error("the default config arrived with consoles or channels already set")
	}
	if _, err := Load(dir); err != nil {
		t.Errorf("the config it wrote cannot be loaded back: %v", err)
	}
}

// A downgraded binary must refuse rather than read what it recognises and
// silently drop a console or a channel -- that is how a site stops being
// monitored without anyone being told.
func TestANewerSchemaIsRefusedClearly(t *testing.T) {
	dir := t.TempDir()
	body := `version: 99
web:
  listen: 127.0.0.1:8322
`
	if err := os.WriteFile(Path(dir), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("Load = %v, want ErrNewerSchema", err)
	}
	if !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("the error does not say what to do about it: %v", err)
	}
}

// The failure this is really for: a config copied from another machine cannot
// decrypt, and without special handling the operator is told their YAML is
// malformed. They then hunt for a syntax error in a perfectly well-formed file.
func TestAForeignConfigIsReportedAsForeignNotAsCorrupt(t *testing.T) {
	dir := t.TempDir()
	secret.SetKeyFile(filepath.Join(dir, "secret.key"))

	// Craft the file directly rather than moving a real one between machines.
	// The platform decides the mechanism -- DPAPI on Windows, a key file or
	// systemd-creds on Linux -- so the portable way to produce "a secret this
	// host cannot open" is a well-formed blob under this host's own prefix
	// that is not actually one of its blobs.
	w, err := secret.SelectWriter()
	if err != nil {
		t.Skipf("no secret mechanism available here: %v", err)
	}
	body := fmt.Sprintf(`version: 1
consoles:
  - name: main
    host: 10.0.0.1
    api_key: "%sbm90LWEtcmVhbC1ibG9i"
    sources: [protect]
web:
  listen: 127.0.0.1:8322
secrets:
  host_fingerprint: 0000aaaa1111bbbb
`, w.Prefix())
	if err := os.WriteFile(Path(dir), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir)
	if err == nil {
		t.Fatal("a config with undecryptable secrets loaded successfully")
	}
	if !errors.Is(err, ErrForeignConfig) {
		t.Fatalf("Load = %v, want ErrForeignConfig -- otherwise the operator is "+
			"told their YAML is malformed and goes hunting for a syntax error "+
			"in a perfectly well-formed file", err)
	}
	for _, want := range []string{"different machine", "re-entering"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not say what happened or what to do "+
				"(%q missing): %v", want, err)
		}
	}
	// It should also name both fingerprints, so "which machine was this?" is
	// answerable without guessing.
	if fp := HostFingerprint(); fp != "" && !strings.Contains(err.Error(), fp) {
		t.Errorf("the message does not name this host's fingerprint: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// The setting people get wrong. It works perfectly on the machine running the
// daemon and is useless in the 3am notification it is embedded in.
func TestAckBaseURLPointingAtLoopbackIsRefused(t *testing.T) {
	for _, bad := range []string{
		"http://localhost:8322", "http://127.0.0.1:8322", "http://[::1]:8322",
	} {
		c := workable()
		c.Web.AckBaseURL = bad
		err := c.Validate()
		if err == nil {
			t.Fatalf("%s was accepted as an ack base URL", bad)
		}
		if !strings.Contains(err.Error(), "phone") {
			t.Errorf("%s: the message does not explain why it is wrong: %v", bad, err)
		}
	}
}

func TestAnEnabledChannelWithNoAckURLIsRefused(t *testing.T) {
	c := workable()
	c.Web.AckBaseURL = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("a config with alerting channels and no ack URL was accepted; " +
			"nothing could stop an alert repeating except the web UI")
	}
}

// Validation must report EVERY problem. Fixing a config one restart at a time
// means a sequence of windows where nothing is watching.
func TestValidationReportsEveryProblemNotJustTheFirst(t *testing.T) {
	c := Default()
	c.Consoles = []Console{{Name: "", Host: "", Sources: nil}}
	c.Channels.Email = &Email{Enabled: true} // no host, from, or recipients

	err := c.Validate()
	if err == nil {
		t.Fatal("a thoroughly broken config validated")
	}
	var p Problems
	if !errors.As(err, &p) {
		t.Fatalf("error is %T, want Problems", err)
	}
	if len(p) < 4 {
		t.Errorf("reported only %d problems:\n%v", len(p), err)
	}
	if !errors.Is(err, ErrInvalid) {
		t.Error("validation failure does not match ErrInvalid")
	}
}

func TestDuplicateConsoleNamesAreRefused(t *testing.T) {
	c := workable()
	c.Consoles = append(c.Consoles, c.Consoles[0])
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate console names were accepted: %v", err)
	}
}

func TestUnknownSourceIsRefused(t *testing.T) {
	c := workable()
	c.Consoles[0].Sources = []string{"protect", "telepathy"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "telepathy") {
		t.Fatalf("an unknown source was accepted: %v", err)
	}
}

// A policy naming a channel that is not configured would deliver nothing and
// look exactly like one that worked.
func TestAPolicyNamingAnUnconfiguredChannelIsRefused(t *testing.T) {
	c := workable() // ntfy only
	c.Policies = map[string]Policy{
		"critical": {
			Stages:      []Stage{{After: "0s", Channels: []string{"ntfy", "email"}}},
			RepeatEvery: "5m",
			GiveUpAfter: "never",
		},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "email") {
		t.Fatalf("a policy naming the disabled email channel was accepted: %v", err)
	}
}

func TestCriticalCannotBeConfiguredIntoSilence(t *testing.T) {
	for name, pol := range map[string]Policy{
		"quiet hours": {
			Stages:      []Stage{{After: "0s", Channels: []string{"ntfy"}}},
			RepeatEvery: "5m", GiveUpAfter: "never", RespectQuietHours: true,
		},
		"gives up": {
			Stages:      []Stage{{After: "0s", Channels: []string{"ntfy"}}},
			RepeatEvery: "5m", GiveUpAfter: "4h",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := workable()
			c.Policies = map[string]Policy{"critical": pol}
			if err := c.Validate(); err == nil {
				t.Fatal("a critical policy that can go silent was accepted")
			}
		})
	}
}

func TestBadDurationsAreReportedHelpfully(t *testing.T) {
	c := workable()
	c.Policies = map[string]Policy{
		"high": {Stages: []Stage{{After: "soon", Channels: []string{"ntfy"}}}},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "30s") {
		t.Fatalf("a bad duration was not explained with an example: %v", err)
	}
}

// A WARNING, not a refusal -- and the distinction is the whole point.
//
// This must be said: nothing authenticates the console. But it must not stop
// the daemon, because a UniFi console with a self-signed certificate and no
// pin learned yet is the ordinary state of affairs on day one. Refusing to
// start locks the operator out before they can reach the step that fixes it,
// and an unpinned daemon that is watching beats a pinned one that is not
// running.
func TestInsecureWithNoPinIsWarnedAboutButStillStarts(t *testing.T) {
	c := workable()
	c.Consoles[0].Fingerprint = ""
	c.Consoles[0].InsecureSkipVerify = true

	if err := c.Validate(); err != nil {
		t.Fatalf("a console with no pin was refused outright: %v", err)
	}
	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "nothing authenticates") {
		t.Fatalf("verification off with no pin was accepted silently: %v", c.Warnings())
	}
}

// Likewise: said out loud, but it does not take away the Protect and Access
// coverage on the same console.
func TestAnUnimplementedSourceWarnsWithoutRefusingTheConsole(t *testing.T) {
	c := workable()
	c.Consoles[0].Sources = []string{"protect", "network"}

	if err := c.Validate(); err != nil {
		t.Fatalf("one unimplemented source refused the whole config: %v", err)
	}
	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "network") {
		t.Errorf("an unimplemented source was accepted silently, which reads as "+
			"a WAN that is being watched: %v", c.Warnings())
	}

	// But a name that is not a source at all is still a refusal: it is a typo,
	// and a typo silently watching nothing is the failure this guards.
	c.Consoles[0].Sources = []string{"protekt"}
	if err := c.Validate(); err == nil {
		t.Error("a misspelled source name was accepted")
	}
}

// ---------------------------------------------------------------------------
// Credential precedence
// ---------------------------------------------------------------------------

// An administrator who provisioned a credential has stated an intent, and a
// key the UI happened to write must not silently override it.
func TestAServiceCredentialBeatsTheConfigFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "unifi-key"), []byte("from-systemd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	con := Console{APIKey: secret.Secret("from-the-file"), APIKeyCredential: "unifi-key"}
	got, from := con.ResolveAPIKey()
	if got.Reveal() != "from-systemd" {
		t.Errorf("key = %q, want the service credential", got.Reveal())
	}
	// Diagnostics must be able to say where it came from, or "I changed the
	// key in the UI and nothing happened" is baffling.
	if !strings.Contains(from, "service credential") {
		t.Errorf("source = %q, want it to name the service credential", from)
	}
}

func TestAMissingServiceCredentialFallsBackToTheFile(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	con := Console{APIKey: secret.Secret("from-the-file"), APIKeyCredential: "absent"}
	got, from := con.ResolveAPIKey()
	if got.Reveal() != "from-the-file" {
		t.Errorf("key = %q, want the config file value", got.Reveal())
	}
	if !strings.Contains(from, "config file") {
		t.Errorf("source = %q", from)
	}
}

// ---------------------------------------------------------------------------
// Host fingerprint
// ---------------------------------------------------------------------------

func TestHostFingerprintIsStableAndNotTheRawMachineID(t *testing.T) {
	a := HostFingerprint()
	if a == "" {
		t.Skip("no stable machine identifier on this host")
	}
	if a != HostFingerprint() {
		t.Error("the fingerprint changed between two calls")
	}
	if id := machineID(); id != "" && strings.Contains(a, id) {
		t.Error("the fingerprint contains the raw machine id; a config file " +
			"may be pasted into a support ticket")
	}
}

// "Cannot tell" must never be reported as "foreign": a false mismatch sends an
// operator re-entering credentials that were fine.
func TestAnUnknownFingerprintIsNotAMismatch(t *testing.T) {
	if !(SecretsMeta{}).MatchesThisHost() {
		t.Error("a config with no recorded fingerprint was treated as foreign")
	}
	if (SecretsMeta{HostFingerprint: "definitely-not-this-host"}).MatchesThisHost() {
		t.Error("a foreign fingerprint matched")
	}
	if !(SecretsMeta{HostFingerprint: HostFingerprint()}).MatchesThisHost() {
		t.Error("this host's own fingerprint did not match")
	}
}

// A fresh install must start. Filtering the default ladders against zero
// enabled channels produced an empty policy set, and the scheduler refuses to
// start without one -- so the very first run failed with
// "scheduler needs at least one policy".
func TestAFreshInstallStillHasPolicies(t *testing.T) {
	c := Default()
	if len(c.EnabledChannelNames()) != 0 {
		t.Fatal("test precondition: the default config should enable nothing")
	}
	policies, err := c.BuildPolicies(c.EnabledChannelNames())
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) == 0 {
		t.Fatal("a config with no channels produced no policies, so the daemon " +
			"would refuse to start on first run")
	}
	if _, ok := policies["critical"]; !ok {
		t.Error("critical has no policy on a fresh install")
	}
}

// With channels enabled, the defaults are filtered to what exists -- a site
// running ntfy only should not be refused because our default ladder also
// mentions email.
func TestDefaultsAreFilteredToTheEnabledChannels(t *testing.T) {
	c := workable() // ntfy only
	policies, err := c.BuildPolicies(c.EnabledChannelNames())
	if err != nil {
		t.Fatal(err)
	}
	crit, ok := policies["critical"]
	if !ok {
		t.Fatal("critical was filtered away entirely")
	}
	for i, st := range crit.Stages {
		for _, ch := range st.Channels {
			if ch != "ntfy" {
				t.Errorf("stage %d still names %q, which is not enabled", i, ch)
			}
		}
	}
}

// The file is the source of truth and an operator reads it, so every block
// must use the same snake_case vocabulary. QuietHours originally serialised
// with Go field names because it carried no json tags.
func TestTheWrittenFileUsesConsistentFieldNames(t *testing.T) {
	dir := t.TempDir()
	secret.SetKeyFile(filepath.Join(dir, "secret.key"))

	c := workable()
	c.QuietHours = escalate.QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: "UTC"}
	if err := Save(dir, &c); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"quiet_hours", "enabled", "start", "end", "zone"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the file does not use %q:\n%s", want, raw)
		}
	}
	for _, bad := range []string{"Enabled:", "Start:", "Zone:"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the file exposes the Go field name %q:\n%s", bad, raw)
		}
	}
}

// An operator bootstrapping by hand pastes a key straight into the file. That
// is accepted -- otherwise the only way in is a UI that may not be running --
// but a credential that sat readable on disk has been exposed, and the product
// must say so rather than quietly encrypting it and moving on.
func TestAHandEnteredPlaintextKeyIsAcceptedAndReported(t *testing.T) {
	dir := t.TempDir()
	secret.SetKeyFile(filepath.Join(dir, "secret.key"))

	body := `version: 1
consoles:
  - name: main
    host: 10.0.0.1
    api_key: pasted-by-hand
    sources: [protect]
channels:
  ntfy:
    enabled: true
    topic: alarms
web:
  listen: 127.0.0.1:8322
  ack_base_url: https://nm.example.com
`
	if err := os.WriteFile(Path(dir), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("a hand-entered key was refused: %v", err)
	}
	if got := cfg.Consoles[0].APIKey.Reveal(); got != "pasted-by-hand" {
		t.Errorf("key = %q, want the pasted value", got)
	}
	if len(cfg.PlaintextFields) == 0 {
		t.Fatal("the unprotected credential was not reported")
	}
	warn := PlaintextWarning(cfg.PlaintextFields, Path(dir))
	for _, want := range []string{"NOT encrypted", "api_key", "exposed"} {
		if !strings.Contains(warn, want) {
			t.Errorf("the warning does not mention %q:\n%s", want, warn)
		}
	}
	// And it must never echo the credential itself.
	if strings.Contains(warn, "pasted-by-hand") {
		t.Errorf("the warning leaks the credential:\n%s", warn)
	}

	// Saving encrypts it, and a reload then reports nothing.
	if err := Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	again, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.PlaintextFields) != 0 {
		t.Errorf("still reported as plaintext after a save: %v", again.PlaintextFields)
	}
	if again.Consoles[0].APIKey.Reveal() != "pasted-by-hand" {
		t.Error("re-encryption lost the value")
	}
}
