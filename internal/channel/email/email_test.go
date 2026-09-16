package email

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"strings"
	"testing"
	"time"

	gomail "github.com/wneessen/go-mail"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// part is one decoded leaf of the MIME tree, with its transfer encoding undone
// so that a long ack URL broken across quoted-printable soft line breaks still
// compares equal to itself.
type part struct {
	mediaType   string
	disposition string
	contentID   string
	filename    string
	body        string
	// path is the chain of container media types above this leaf, which is
	// what part-ordering assertions are actually about.
	path []string
}

func newTestChannel(t *testing.T, cfg Config) *Channel {
	t.Helper()
	if cfg.Host == "" {
		cfg.Host = "smtp.example.net"
	}
	if cfg.From == "" {
		cfg.From = "matrix@example.net"
	}
	if len(cfg.To) == 0 {
		cfg.To = []string{"oncall@example.net"}
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func sampleAlert() channel.Alert {
	at := time.Date(2026, 9, 15, 3, 14, 7, 0, time.UTC)
	return channel.Alert{
		IncidentID: "inc-42",
		Severity:   incident.SeverityCritical,
		Title:      "Door forced open",
		Body:       "Front entrance was forced.\nDoor position reports open.",
		Entity:     "Front Door",
		AckURL:     "https://alerts.example.net/ack/inc-42/6f1c9e2b7a4d8e3f0c5b1a9d",
		OpenedAt:   at.Add(-12 * time.Minute),
		At:         at,
	}
}

// render writes the message the way go-mail would put it on the wire, then
// parses it back. Everything worth asserting about this channel is a property
// of those bytes.
func render(t *testing.T, m *gomail.Msg) (*mail.Message, []part) {
	t.Helper()
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadMessage: %v\n---\n%s", err, buf.String())
	}
	parts := walk(t, msg.Header.Get("Content-Type"),
		msg.Header.Get("Content-Transfer-Encoding"),
		msg.Header.Get("Content-Disposition"),
		msg.Header.Get("Content-ID"), msg.Body, nil)
	return msg, parts
}

func walk(t *testing.T, contentType, transferEnc, disposition, contentID string,
	body io.Reader, path []string,
) []part {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("parsing content-type %q: %v", contentType, err)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		var out []part
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("reading %s: %v", mediaType, err)
			}
			out = append(out, walk(t, p.Header.Get("Content-Type"),
				p.Header.Get("Content-Transfer-Encoding"),
				p.Header.Get("Content-Disposition"),
				p.Header.Get("Content-ID"), p, append(append([]string{}, path...), mediaType))...)
		}
		return out
	}

	raw, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("reading leaf %s: %v", mediaType, err)
	}
	var decoded []byte
	switch strings.ToLower(strings.TrimSpace(transferEnc)) {
	case "quoted-printable":
		decoded, err = io.ReadAll(quotedprintable.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("quoted-printable decode of %s: %v", mediaType, err)
		}
	case "base64":
		decoded, err = base64.StdEncoding.DecodeString(
			strings.Join(strings.Fields(string(raw)), ""))
		if err != nil {
			t.Fatalf("base64 decode of %s: %v", mediaType, err)
		}
	default:
		decoded = raw
	}

	filename := ""
	dispType := ""
	if disposition != "" {
		dt, dparams, derr := mime.ParseMediaType(disposition)
		if derr == nil {
			dispType = dt
			filename = dparams["filename"]
		}
	}
	return []part{{
		mediaType:   mediaType,
		disposition: dispType,
		contentID:   contentID,
		filename:    filename,
		body:        string(decoded),
		path:        path,
	}}
}

func findPart(parts []part, mediaType string) (part, bool) {
	for _, p := range parts {
		if p.mediaType == mediaType {
			return p, true
		}
	}
	return part{}, false
}

func mediaTypes(parts []part) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, p.mediaType)
	}
	return out
}

func TestPlainTextIsTheBasePartAndHTMLTheAlternative(t *testing.T) {
	// The failure this guards: an HTML-stripping gateway delivers the FIRST
	// part of a multipart/alternative and drops the rest. If HTML were the
	// base part, the on-call engineer gets an empty security alert and nobody
	// on the sending side can tell.
	c := newTestChannel(t, Config{})
	m, err := c.buildMessage(sampleAlert())
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	_, parts := render(t, m)

	var alt []part
	for _, p := range parts {
		if len(p.path) > 0 && p.path[len(p.path)-1] == "multipart/alternative" {
			alt = append(alt, p)
		}
	}
	if len(alt) != 2 {
		t.Fatalf("alternative has %d parts (%v), want text/plain then text/html",
			len(alt), mediaTypes(parts))
	}
	if alt[0].mediaType != "text/plain" {
		t.Errorf("first alternative part is %s; plain text must be the base part",
			alt[0].mediaType)
	}
	if alt[1].mediaType != "text/html" {
		t.Errorf("second alternative part is %s, want text/html", alt[1].mediaType)
	}
}

func TestAckLinkAppearsInBothParts(t *testing.T) {
	// An ack reachable only from the HTML part is unreachable from a
	// text-only client, a pager gateway, or a stripped message -- and an
	// incident nobody can acknowledge nags forever.
	c := newTestChannel(t, Config{})
	a := sampleAlert()
	m, err := c.buildMessage(a)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	_, parts := render(t, m)

	for _, mt := range []string{"text/plain", "text/html"} {
		p, ok := findPart(parts, mt)
		if !ok {
			t.Fatalf("no %s part; got %v", mt, mediaTypes(parts))
		}
		if !strings.Contains(p.body, a.AckURL) {
			t.Errorf("%s part does not carry the ack URL:\n%s", mt, p.body)
		}
	}
}

func TestInlineLogoResolvesByContentID(t *testing.T) {
	c := newTestChannel(t, Config{Logo: &InlineImage{
		Filename:    "logo.png",
		ContentID:   "notifymatrix-logo",
		ContentType: "image/png",
		Data:        []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
	}})
	m, err := c.buildMessage(sampleAlert())
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	_, parts := render(t, m)

	logo, ok := findPart(parts, "image/png")
	if !ok {
		t.Fatalf("no image/png part; got %v", mediaTypes(parts))
	}
	if logo.contentID != "<notifymatrix-logo>" {
		t.Errorf("Content-ID = %q, want %q -- cid: references resolve against the "+
			"bracketed form", logo.contentID, "<notifymatrix-logo>")
	}
	// Inline, not attachment: a paperclip on a security alert is the thing
	// every operator is trained to distrust.
	if logo.disposition != "inline" {
		t.Errorf("Content-Disposition = %q, want inline", logo.disposition)
	}
	// It must sit inside the related container that wraps the alternative, or
	// the HTML part cannot see it.
	joined := strings.Join(logo.path, ">")
	if !strings.Contains(joined, "multipart/related") {
		t.Errorf("logo path = %q, want it inside multipart/related", joined)
	}
	htmlPart, ok := findPart(parts, "text/html")
	if !ok {
		t.Fatal("no html part")
	}
	if !strings.Contains(htmlPart.body, "cid:notifymatrix-logo") {
		t.Errorf("html part does not reference the logo:\n%s", htmlPart.body)
	}
}

func TestNoLogoMeansNoRelatedContainerAndNoStrayParts(t *testing.T) {
	c := newTestChannel(t, Config{})
	m, err := c.buildMessage(sampleAlert())
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	_, parts := render(t, m)
	if got := mediaTypes(parts); len(got) != 2 {
		t.Errorf("parts = %v, want exactly text/plain and text/html", got)
	}
}

func TestSnapshotAttachesAsJPEG(t *testing.T) {
	c := newTestChannel(t, Config{})
	a := sampleAlert()
	a.Snapshot = []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F'}
	m, err := c.buildMessage(a)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	_, parts := render(t, m)

	snap, ok := findPart(parts, "image/jpeg")
	if !ok {
		t.Fatalf("no image/jpeg part; got %v", mediaTypes(parts))
	}
	if snap.disposition != "attachment" {
		t.Errorf("disposition = %q, want attachment", snap.disposition)
	}
	if snap.filename != snapshotFilename {
		t.Errorf("filename = %q, want %q", snap.filename, snapshotFilename)
	}
	if snap.body != string(a.Snapshot) {
		t.Errorf("snapshot bytes did not survive the transfer encoding")
	}
}

func TestArrivalTimeIsWordedReceivedInBothParts(t *testing.T) {
	tests := []struct {
		name            string
		atIsArrivalTime bool
		want            string
		notWant         string
	}{
		{
			name:            "source supplied no time",
			atIsArrivalTime: true,
			want:            "Received",
			notWant:         "Observed at",
		},
		{
			name:            "source supplied a real observation time",
			atIsArrivalTime: false,
			want:            "Observed at",
			notWant:         "Received",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestChannel(t, Config{})
			a := sampleAlert()
			a.AtIsArrivalTime = tt.atIsArrivalTime
			m, err := c.buildMessage(a)
			if err != nil {
				t.Fatalf("buildMessage: %v", err)
			}
			_, parts := render(t, m)
			for _, mt := range []string{"text/plain", "text/html"} {
				p, ok := findPart(parts, mt)
				if !ok {
					t.Fatalf("no %s part", mt)
				}
				if !strings.Contains(p.body, tt.want) {
					t.Errorf("%s part missing %q:\n%s", mt, tt.want, p.body)
				}
				if strings.Contains(p.body, tt.notWant) {
					t.Errorf("%s part says %q; an arrival time presented as an "+
						"observation time sends someone scrubbing to a moment that "+
						"means nothing", mt, tt.notWant)
				}
			}
		})
	}
}

func TestSubjectCarriesSeverityAndReminder(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*channel.Alert)
		want string
	}{
		{
			name: "first delivery",
			mut:  func(*channel.Alert) {},
			want: "[CRITICAL] Door forced open",
		},
		{
			name: "re-alert is marked",
			mut:  func(a *channel.Alert) { a.Repeat = 3 },
			want: "[CRITICAL] Door forced open (reminder 3)",
		},
		{
			name: "newlines in the title never reach the header",
			mut:  func(a *channel.Alert) { a.Title = "Door\r\nforced open" },
			want: "[CRITICAL] Door forced open",
		},
		{
			name: "empty title falls back to the entity",
			mut:  func(a *channel.Alert) { a.Title = "" },
			want: "[CRITICAL] Front Door",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sampleAlert()
			tt.mut(&a)
			if got := subjectFor(a); got != tt.want {
				t.Errorf("subject = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSubjectHeaderSurvivesNonASCII(t *testing.T) {
	c := newTestChannel(t, Config{})
	a := sampleAlert()
	a.Title = "Tür gewaltsam geöffnet"
	m, err := c.buildMessage(a)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	msg, _ := render(t, m)
	dec := new(mime.WordDecoder)
	got, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("decoding subject: %v", err)
	}
	if !strings.Contains(got, "Tür gewaltsam geöffnet") {
		t.Errorf("subject = %q", got)
	}
}

func TestHTMLIsEscaped(t *testing.T) {
	// Entity names and titles come from whatever the operator typed into the
	// UniFi console. An unescaped one silently breaks the layout of the part
	// that most people read.
	c := newTestChannel(t, Config{})
	a := sampleAlert()
	a.Entity = `Front <img src=x onerror="alert(1)"> Door`
	m, err := c.buildMessage(a)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	_, parts := render(t, m)
	htmlPart, ok := findPart(parts, "text/html")
	if !ok {
		t.Fatal("no html part")
	}
	if strings.Contains(htmlPart.body, "<img src=x") {
		t.Errorf("entity name reached the HTML unescaped:\n%s", htmlPart.body)
	}
	if !strings.Contains(htmlPart.body, "&lt;img src=x") {
		t.Errorf("escaped entity name missing:\n%s", htmlPart.body)
	}
}

func TestRepeatIsVisibleInBothParts(t *testing.T) {
	c := newTestChannel(t, Config{})
	a := sampleAlert()
	a.Repeat = 3
	a.Stage = 2
	m, err := c.buildMessage(a)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	_, parts := render(t, m)
	for _, mt := range []string{"text/plain", "text/html"} {
		p, ok := findPart(parts, mt)
		if !ok {
			t.Fatalf("no %s part", mt)
		}
		if !strings.Contains(strings.ToLower(p.body), "reminder 3") {
			t.Errorf("%s part does not mark the re-alert:\n%s", mt, p.body)
		}
	}
}

func TestNotThreadedWithPreviousDeliveries(t *testing.T) {
	// Deliberate: a threaded reminder lands inside an already-read
	// conversation and shows as nothing new.
	c := newTestChannel(t, Config{})
	a := sampleAlert()
	a.Repeat = 7
	m, err := c.buildMessage(a)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	msg, _ := render(t, m)
	if v := msg.Header.Get("In-Reply-To"); v != "" {
		t.Errorf("In-Reply-To = %q, want none", v)
	}
	if v := msg.Header.Get("References"); v != "" {
		t.Errorf("References = %q, want none", v)
	}
	if msg.Header.Get("Message-ID") == "" {
		t.Error("no Message-ID; relays and dedupers need one")
	}
}

func TestMessageIDDoesNotDiscloseTheHostname(t *testing.T) {
	// go-mail's default Message-ID is <random@os.Hostname()>. That ships the
	// name of the machine on the operator's LAN out through whatever relay
	// they configured, in every alert, and nothing else in the message
	// discloses it. The From domain is already public here.
	host, err := os.Hostname()
	if err != nil {
		t.Skipf("no hostname: %v", err)
	}
	c := newTestChannel(t, Config{From: "matrix@example.net"})
	m, err := c.buildMessage(sampleAlert())
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	msg, _ := render(t, m)
	id := msg.Header.Get("Message-ID")
	if id == "" {
		t.Fatal("no Message-ID; relays and dedupers need one")
	}
	if host != "" && strings.Contains(id, host) {
		t.Errorf("Message-ID %q carries this machine's hostname", id)
	}
	if !strings.HasSuffix(id, "@example.net>") {
		t.Errorf("Message-ID = %q, want it scoped to the sender's own domain", id)
	}

	// Two messages must not collide: dedupers key on this.
	m2, err := c.buildMessage(sampleAlert())
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	msg2, _ := render(t, m2)
	if msg2.Header.Get("Message-ID") == id {
		t.Error("two messages share a Message-ID")
	}
}

func TestAddressDomain(t *testing.T) {
	// What the Message-ID is scoped to. An address this cannot read falls back
	// to go-mail's generator rather than leaving the header off, because a
	// message with no Message-ID is one relays and dedupers cannot key on.
	tests := []struct {
		in   string
		want string
	}{
		{in: "matrix@example.net", want: "example.net"},
		{in: "  matrix@example.net  ", want: "example.net"},
		{in: "UniFi Matrix <matrix@sub.example.net>", want: "sub.example.net"},
		{in: "not-an-address", want: ""},
		{in: "", want: ""},
	}
	for _, tt := range tests {
		if got := addressDomain(tt.in); got != tt.want {
			t.Errorf("addressDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAutoSubmittedHeaderIsSet(t *testing.T) {
	c := newTestChannel(t, Config{})
	m, err := c.buildMessage(sampleAlert())
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	msg, _ := render(t, m)
	if got := msg.Header.Get("Auto-Submitted"); got != "auto-generated" {
		t.Errorf("Auto-Submitted = %q; an out-of-office answering an alarm is a loop", got)
	}
}

func TestSendHandsExactlyOneMessageToTheTransport(t *testing.T) {
	c := newTestChannel(t, Config{})
	var sent []*gomail.Msg
	c.send = func(_ context.Context, m *gomail.Msg) error {
		sent = append(sent, m)
		return nil
	}
	if err := c.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("transport saw %d messages, want 1", len(sent))
	}
	rcpts, err := sent[0].GetRecipients()
	if err != nil {
		t.Fatalf("GetRecipients: %v", err)
	}
	if len(rcpts) != 1 || !strings.Contains(rcpts[0], "oncall@example.net") {
		t.Errorf("recipients = %v", rcpts)
	}
}

func TestSendPropagatesTransportError(t *testing.T) {
	c := newTestChannel(t, Config{})
	want := fmt.Errorf("connection refused")
	c.send = func(context.Context, *gomail.Msg) error { return want }
	if err := c.Send(context.Background(), sampleAlert()); err == nil {
		t.Fatal("want an error; a failed delivery must not look like a success -- " +
			"the scheduler uses it to decide the incident has not been alerted")
	}
}

func TestTestMessageIsWellFormed(t *testing.T) {
	c := newTestChannel(t, Config{})
	m, err := c.buildTestMessage()
	if err != nil {
		t.Fatalf("buildTestMessage: %v", err)
	}
	msg, parts := render(t, m)
	if msg.Header.Get("Subject") == "" {
		t.Error("test message has no subject")
	}
	plain, ok := findPart(parts, "text/plain")
	if !ok {
		t.Fatalf("test message has no plain part; got %v", mediaTypes(parts))
	}
	if !strings.Contains(plain.body, "test message") {
		t.Errorf("plain part = %q", plain.body)
	}
	if _, ok := findPart(parts, "text/html"); !ok {
		t.Error("test message has no html alternative")
	}
}

func TestTLSModeResolution(t *testing.T) {
	tests := []struct {
		name string
		port int
		set  TLSMode
		want TLSMode
	}{
		{name: "auto on 465 is implicit TLS", port: 465, set: TLSAuto, want: TLSImplicit},
		{name: "auto on 587 is STARTTLS", port: 587, set: TLSAuto, want: TLSSTARTTLS},
		{name: "auto on 25 is STARTTLS, never opportunistic", port: 25, set: TLSAuto, want: TLSSTARTTLS},
		{name: "auto on 2525 is STARTTLS", port: 2525, set: TLSAuto, want: TLSSTARTTLS},
		{name: "explicit implicit on 587 is honoured", port: 587, set: TLSImplicit, want: TLSImplicit},
		{name: "explicit none is honoured", port: 25, set: TLSNone, want: TLSNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestChannel(t, Config{Port: tt.port, TLS: tt.set})
			if got := c.tlsMode(); got != tt.want {
				t.Errorf("tlsMode = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientBuildsForEveryTLSModeAndAuthCombination(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "implicit tls with auth", cfg: Config{
			Port: 465, Username: "u", Password: secret.Secret("p")}},
		{name: "starttls with auth", cfg: Config{
			Port: 587, Username: "u", Password: secret.Secret("p")}},
		{name: "starttls without auth", cfg: Config{Port: 587}},
		{name: "no tls without auth", cfg: Config{Port: 25, TLS: TLSNone}},
		{name: "custom helo", cfg: Config{Port: 587, HELO: "nvr.lan"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestChannel(t, tt.cfg)
			if _, err := c.client(); err != nil {
				t.Errorf("client: %v", err)
			}
		})
	}
}

func TestNewValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "no host", cfg: Config{From: "a@b.c", To: []string{"d@e.f"}}},
		{name: "no from", cfg: Config{Host: "h", To: []string{"d@e.f"}}},
		{name: "no recipients", cfg: Config{Host: "h", From: "a@b.c"}},
		{name: "blank recipients only", cfg: Config{Host: "h", From: "a@b.c", To: []string{"", "  "}}},
		{name: "impossible port", cfg: Config{Host: "h", From: "a@b.c", To: []string{"d@e.f"}, Port: 70000}},
		{name: "logo with no data", cfg: Config{
			Host: "h", From: "a@b.c", To: []string{"d@e.f"}, Logo: &InlineImage{ContentID: "x"}}},
		// An address the message builder cannot use fails EVERY delivery. It
		// has to be refused at configuration time, not discovered at 3am on an
		// incident record.
		{name: "unusable from address", cfg: Config{
			Host: "h", From: "not-an-address", To: []string{"d@e.f"}}},
		{name: "unusable recipient", cfg: Config{
			Host: "h", From: "a@b.c", To: []string{"d@e.f", "nope"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Errorf("New(%+v) = nil error, want a refusal", tt.cfg)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	c, err := New(Config{
		Host: "smtp.example.net",
		From: "a@b.c",
		To:   []string{"d@e.f"},
		Logo: &InlineImage{Data: []byte{1}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.cfg.Port != 587 {
		t.Errorf("port = %d, want 587", c.cfg.Port)
	}
	if c.cfg.Timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", c.cfg.Timeout, DefaultTimeout)
	}
	if c.cfg.Logo.ContentID != DefaultLogoContentID {
		t.Errorf("logo content-id = %q", c.cfg.Logo.ContentID)
	}
	if c.cfg.Logo.ContentType != "image/png" || c.cfg.Logo.Filename != "logo.png" {
		t.Errorf("logo defaults = %+v", *c.cfg.Logo)
	}
}

func TestPasswordNeverReachesAFormatVerb(t *testing.T) {
	// secret.Secret's String() is what makes this safe; the test exists so a
	// future change from Secret to string is caught here rather than in a log.
	cfg := Config{
		Host:     "smtp.example.net",
		From:     "a@b.c",
		To:       []string{"d@e.f"},
		Username: "u",
		Password: secret.Secret("hunter2"),
	}
	if s := fmt.Sprintf("%v", cfg); strings.Contains(s, "hunter2") {
		t.Errorf("config formatted its password: %s", s)
	}
}

func TestMultipleRecipients(t *testing.T) {
	c := newTestChannel(t, Config{To: []string{"a@example.net", "b@example.net"}})
	m, err := c.buildMessage(sampleAlert())
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	rcpts, err := m.GetRecipients()
	if err != nil {
		t.Fatalf("GetRecipients: %v", err)
	}
	if len(rcpts) != 2 {
		t.Errorf("recipients = %v, want 2", rcpts)
	}
}

func TestName(t *testing.T) {
	c := newTestChannel(t, Config{})
	if c.Name() != "email" {
		t.Errorf("Name = %q", c.Name())
	}
}

// Compile-time proof that this satisfies the interface the scheduler uses.
var _ channel.Channel = (*Channel)(nil)
