package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ack"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/demo"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// demoCmd serves the real interface over fabricated data.
//
// Everything a viewer sees goes through the same rendering, the same store and
// the same API as a live daemon: a demo that reimplemented the screens would
// be a screenshot of something that does not exist, which is worse than no
// demo. What is fabricated is the data underneath, and only that.
//
// No console is contacted, no channel is constructed, no service is touched,
// and the delivery function refuses.
func demoCmd(dataDir string, explicitDir bool) int {
	// A default of its own, so the overwhelmingly common invocation -- just
	// `notifymatrix demo` -- cannot land on the real data directory even by
	// accident.
	if !explicitDir {
		dataDir = filepath.Join(os.TempDir(), "notifymatrix-demo")
		_ = os.RemoveAll(dataDir)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := demo.Refuse(dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	db, err := store.Open(filepath.Join(dataDir, "incidents.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	now := time.Now()
	if err := demo.Seed(ctx, db, now); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	auditLog, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer auditLog.Close()

	cfg := demoConfig()
	ui, err := web.New(web.Deps{
		Store:   db,
		Audit:   auditLog,
		Version: version + " (demo)",
		Demo:    demo.Banner,
		Config:  func() *config.Config { return cfg },
		SaveConfig: func(next *config.Config) error {
			// Editable, because the settings screens are half of what somebody
			// is here to look at. Held in memory only: a demo that wrote a
			// config would leave one behind for the real daemon to find.
			cfg = next
			return nil
		},
		Health:          func() web.Health { return demo.Health(time.Now()) },
		PasswordHash:    func() string { return "" },
		SetPasswordHash: func(string) error { return nil },
		Checklist:       func() setup.Input { return demoChecklist(cfg) },
		TestChannel: func(context.Context, string) (string, error) {
			return "", fmt.Errorf("nothing is sent in demo mode")
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	const addr = "127.0.0.1:8330"
	srv := &http.Server{
		Addr:              addr,
		Handler:           ui.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf(`
%s

Open http://%s/ to look around. Everything on screen is made up:
no console is contacted, no channel exists, and nothing is delivered.

Data directory: %s
Stop it with Ctrl-C.

`, demo.Banner, addr, dataDir)

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Println("demo stopped")
	return 0
}

// demoConfig is a site that is fully set up, so the settings screens show
// something rather than a set of empty boxes.
func demoConfig() *config.Config {
	c := config.Default()
	c.Consoles = []config.Console{{
		Name:        "Main site",
		Host:        "unifi.example.internal",
		APIKey:      "demo-not-a-real-key",
		Fingerprint: "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90",
		Sources:     []string{"protect", "access", "network"},
	}}
	c.Channels.Ntfy = &config.Ntfy{
		Enabled: true, ServerURL: "https://ntfy.sh", Topic: "demo-topic-not-a-real-one",
		Token: "demo-not-a-real-token",
	}
	c.Channels.Pushover = &config.Pushover{
		Enabled: true, Token: "demo-not-a-real-token", User: "demo-not-a-real-user",
	}
	c.Channels.Email = &config.Email{
		Enabled: true, Host: "smtp.example.com", Port: 587,
		Username: "alerts@example.com", Password: "demo-not-a-real-password",
		From: "alerts@example.com", Recipients: []string{"oncall@example.com"},
		TLS: "starttls",
	}
	c.Hooks = []config.Hook{
		{
			Name: "wan-down", Product: "network", Condition: "wan-down",
			Severity: "critical", Entity: "WAN1",
			Token: "demo-not-a-real-token", Bearer: "demo-not-a-real-bearer",
		},
		{
			Name: "threat", Product: "network", Condition: "threat-detected",
			Token: "demo-not-a-real-token-2", Bearer: "demo-not-a-real-bearer-2",
		},
	}
	c.Web.Listen = "127.0.0.1:8330"
	c.Web.AckBaseURL = "https://alerts.example.com"
	// A REAL KEY, even here.
	//
	// The hook tokens above are fixtures rendered onto a page to show what a
	// credential looks like; this one SIGNS acknowledgement links. A fixed key
	// in published source means every ack token a demo installation mints is
	// forgeable by anybody who has read the repository -- harmless while the
	// demo stays on loopback, and wrong the first time somebody forwards a
	// port to show a colleague. Generated rather than written down, because
	// the cost of doing it properly is two lines.
	if k, err := ack.NewSecret(); err == nil {
		c.Web.AckKey = k
	}
	c.QuietHours.Enabled = true
	c.QuietHours.Start, c.QuietHours.End, c.QuietHours.Zone = "23:00", "07:00", "Europe/London"
	return &c
}

// demoChecklist shows a site part-way through setup, because a checklist with
// every line ticked does not show what the checklist is FOR.
func demoChecklist(c *config.Config) setup.Input {
	in := setup.Input{
		DataDir:    "C:\\ProgramData\\NotifyMatrix",
		ConfigPath: "C:\\ProgramData\\NotifyMatrix\\config.yaml",
		Listen:     c.Web.Listen,
		AckBaseURL: c.Web.AckBaseURL,
		Consoles:   len(c.Consoles), HasConsoleKey: true,
		SourceNames:       []string{"protect", "access", "network"},
		ChannelsEnabled:   c.EnabledChannelNames(),
		PasswordSet:       true,
		ServiceInstalled:  true,
		ServiceRunning:    true,
		RecoversFromCrash: true,
		SourcesLive: []setup.SourceState{
			{Name: "protect", Events: 1842},
			{Name: "access", Events: 311},
			{Name: "network", Events: 27},
		},
		Hooks: []setup.HookState{
			{
				Name: "wan-down", Product: "network",
				// Not a real URL, and not a real token: a screenshot of this
				// screen would otherwise publish a live endpoint.
				URL:    "http://192.168.1.50:8322/hook/<the token, shown only to you>",
				Header: "Bearer <the bearer, shown only to you>",
				Count:  3, LastAt: time.Now().Add(-9 * time.Minute),
			},
			{
				Name: "threat", Product: "network",
				URL:    "http://192.168.1.50:8322/hook/<the token, shown only to you>",
				Header: "Bearer <the bearer, shown only to you>",
				// The state that matters most on this screen: the rule exists,
				// the network path works, and the header is wrong.
				Rejected:   2,
				LastReject: "the Authorization header did not match",
			},
		},
	}
	return in
}

var _ incident.Store = (*store.SQLite)(nil)
