package email

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	netmail "net/mail"
	"strings"

	mail "github.com/wneessen/go-mail"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// snapshotFilename is the attached JPEG's name.
const snapshotFilename = "snapshot.jpg"

// timeLayout is deliberately absolute and carries the zone.
//
// An alert email is read hours later, from a different timezone, next to a
// video timeline. "03:14" alone is not enough to scrub to.
const timeLayout = "2006-01-02 15:04:05 MST"

// buildMessage turns an alert into an SMTP message.
//
// THE PART ORDER IS THE POINT OF THIS FUNCTION.
//
// Plain text is set as the BASE part and HTML is added as an alternative on
// top of it. That ordering is what multipart/alternative means -- least
// faithful representation first, richest last -- and every consumer that
// matters here depends on it:
//
//   - HTML-stripping security gateways deliver the text part and drop the
//     rest. If HTML were the base, they deliver nothing readable.
//   - Text-only alert pipelines (a pager gateway, an SMS bridge, a ticketing
//     mailbox, a terminal mail client on the NVR itself) take the first part.
//   - A client that renders HTML picks the last part regardless, so nothing is
//     lost by being correct here.
//
// A security alert that arrives as an empty message because a gateway
// stripped the only part carrying the content is a total failure of this
// channel, and it is invisible from the sending side. Hence the ordering is
// structural rather than a formatting preference.
func (c *Channel) buildMessage(a channel.Alert) (*mail.Msg, error) {
	m := mail.NewMsg(mail.WithCharset(mail.CharsetUTF8))

	if err := c.addresses(m); err != nil {
		return nil, err
	}
	m.Subject(subjectFor(a))
	m.SetDate()
	c.setMessageID(m)

	if a.Severity == incident.SeverityCritical || a.Severity == incident.SeverityHigh {
		m.SetImportance(mail.ImportanceHigh)
	}
	if a.IncidentID != "" {
		m.SetGenHeader("X-Incident-ID", a.IncidentID)
	}
	if a.Severity != "" {
		m.SetGenHeader("X-Incident-Severity", string(a.Severity))
	}

	// Auto-Submitted stops a recipient's out-of-office from answering the
	// alert, and stops the relay treating a nagging incident as a loop.
	m.SetGenHeader("Auto-Submitted", "auto-generated")

	// Deliberately NOT threaded. Giving re-alerts an In-Reply-To pointing at
	// the first delivery is the obvious thing to do and it is wrong here:
	// clients collapse a thread, so "reminder 7" lands inside an already-read
	// conversation and shows as nothing new. A nag that looks read is a nag
	// that did not happen.

	// Plain text FIRST, as the base part. See the function comment.
	m.SetBodyString(mail.TypeTextPlain, plainBody(a))
	m.AddAlternativeString(mail.TypeTextHTML, htmlBody(a, c.cfg.Logo))

	if err := c.embedLogo(m); err != nil {
		return nil, err
	}
	if len(a.Snapshot) > 0 {
		if err := m.AttachReader(snapshotFilename, bytes.NewReader(a.Snapshot),
			mail.WithFileContentType("image/jpeg")); err != nil {
			return nil, fmt.Errorf("email: attaching snapshot: %w", err)
		}
	}
	return m, nil
}

func (c *Channel) buildTestMessage() (*mail.Msg, error) {
	m := mail.NewMsg(mail.WithCharset(mail.CharsetUTF8))
	if err := c.addresses(m); err != nil {
		return nil, err
	}
	m.Subject("UniFi Notification Matrix: delivery test")
	m.SetDate()
	c.setMessageID(m)
	m.SetGenHeader("Auto-Submitted", "auto-generated")

	plain := "This is a test message from UniFi Notification Matrix.\r\n\r\n" +
		"If it arrived, the SMTP host, transport security, authentication and\r\n" +
		"routing for this channel are all working. No incident is open.\r\n"
	m.SetBodyString(mail.TypeTextPlain, plain)
	m.AddAlternativeString(mail.TypeTextHTML, testHTML(c.cfg.Logo))
	if err := c.embedLogo(m); err != nil {
		return nil, err
	}
	return m, nil
}

// setMessageID stamps a Message-ID whose right-hand side is the sender's own
// domain rather than this machine's hostname.
//
// go-mail's SetMessageID uses os.Hostname(), which puts the NVR's internal
// hostname into every alert that leaves through a third-party relay -- a piece
// of the operator's infrastructure that the alert has no reason to disclose,
// and that nothing else in this message carries. A bare LAN hostname is not a
// domain either, and a Message-ID whose right-hand side is not one is a thing
// receiving filters score against. The From domain is already in every
// message, so using it discloses nothing new.
//
// Falls back to go-mail's own generator rather than sending no Message-ID:
// relays and dedupers need one.
func (c *Channel) setMessageID(m *mail.Msg) {
	domain := addressDomain(c.cfg.From)
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil || domain == "" {
		m.SetMessageID()
		return
	}
	m.SetMessageIDWithValue(hex.EncodeToString(token[:]) + "@" + domain)
}

// addressDomain returns the domain part of an address, or "" if it has none.
func addressDomain(addr string) string {
	parsed, err := netmail.ParseAddress(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	at := strings.LastIndex(parsed.Address, "@")
	if at < 0 || at == len(parsed.Address)-1 {
		return ""
	}
	return parsed.Address[at+1:]
}

func (c *Channel) addresses(m *mail.Msg) error {
	var err error
	if c.cfg.FromName != "" {
		err = m.FromFormat(c.cfg.FromName, c.cfg.From)
	} else {
		err = m.From(c.cfg.From)
	}
	if err != nil {
		return fmt.Errorf("email: from address %q: %w", c.cfg.From, err)
	}
	if err := m.To(c.cfg.To...); err != nil {
		return fmt.Errorf("email: recipients: %w", err)
	}
	return nil
}

// embedLogo attaches the logo INTO the message as an embed rather than as an
// attachment.
//
// The difference is not cosmetic. An embed is written with Content-Disposition
// inline and a Content-ID, inside the related part that wraps the alternative,
// so "cid:..." in the HTML resolves in place. Attached instead, the same bytes
// arrive as a paperclip on a security alert -- which looks exactly like the
// thing every operator is trained to distrust.
func (c *Channel) embedLogo(m *mail.Msg) error {
	if c.cfg.Logo == nil {
		return nil
	}
	l := c.cfg.Logo
	// go-mail writes the Content-ID header verbatim, and RFC 2392 says
	// "cid:foo" refers to Content-ID "<foo>", so the brackets are added here
	// rather than asked of the caller.
	err := m.EmbedReader(l.Filename, bytes.NewReader(l.Data),
		mail.WithFileContentID("<"+l.ContentID+">"),
		mail.WithFileContentType(mail.ContentType(l.ContentType)))
	if err != nil {
		return fmt.Errorf("email: embedding logo: %w", err)
	}
	return nil
}

// --- subject --------------------------------------------------------------

func subjectFor(a channel.Alert) string {
	var b strings.Builder
	if a.Severity != "" {
		fmt.Fprintf(&b, "[%s] ", strings.ToUpper(string(a.Severity)))
	}
	title := strings.TrimSpace(a.Title)
	if title == "" {
		title = strings.TrimSpace(a.Entity)
	}
	if title == "" {
		title = "UniFi alert"
	}
	b.WriteString(collapseWhitespace(title))

	// The reminder count belongs in the subject because the subject is all a
	// phone's notification shelf shows. An identical subject on the seventh
	// nag reads as a duplicate and gets archived unread.
	if a.IsRepeat() {
		fmt.Fprintf(&b, " (reminder %d)", a.Repeat)
	}
	return b.String()
}

// collapseWhitespace keeps a newline out of a header, where it would either be
// folded into nonsense or rejected outright.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// --- plain text -----------------------------------------------------------

func plainBody(a channel.Alert) string {
	var b strings.Builder
	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
		b.WriteString("\r\n")
	}

	if a.Severity != "" {
		w("%s: %s", strings.ToUpper(string(a.Severity)), collapseWhitespace(titleOf(a)))
	} else {
		w("%s", collapseWhitespace(titleOf(a)))
	}
	if a.IsRepeat() {
		w("Reminder %d, escalation stage %d.", a.Repeat, a.Stage)
	}
	w("")

	if body := strings.TrimSpace(a.Body); body != "" {
		for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
			w("%s", line)
		}
		w("")
	}

	if entity := strings.TrimSpace(a.Entity); entity != "" {
		w("Device:      %s", entity)
	}
	if line := observedLine(a); line != "" {
		w("%s", line)
	}
	if !a.OpenedAt.IsZero() {
		w("Open since:  %s", a.OpenedAt.Format(timeLayout))
	}
	if a.IncidentID != "" {
		w("Incident:    %s", a.IncidentID)
	}

	// The ack link is in BOTH parts, never only in the HTML. The reader most
	// likely to be on a text-only client at 3am is the on-call one.
	if ack := strings.TrimSpace(a.AckURL); ack != "" {
		w("")
		w("Acknowledge this alert -- one tap, no login. It stops the")
		w("escalation for this incident and nothing else:")
		w("")
		w("  %s", ack)
	}
	if len(a.Snapshot) > 0 {
		w("")
		w("A snapshot is attached as %s.", snapshotFilename)
	}
	return b.String()
}

func titleOf(a channel.Alert) string {
	if t := strings.TrimSpace(a.Title); t != "" {
		return t
	}
	if e := strings.TrimSpace(a.Entity); e != "" {
		return e
	}
	return "UniFi alert"
}

// observedLine words the timestamp according to what it actually is.
//
// When the source supplied no time of its own we stamped it on arrival, and
// the alert must say so. Network's Alarm Manager webhook carries no controller
// timestamp at all; presenting our arrival time as an observation time sends
// somebody scrubbing footage to a moment that means nothing, and they blame
// the camera rather than the label.
func observedLine(a channel.Alert) string {
	if a.At.IsZero() {
		return ""
	}
	if a.AtIsArrivalTime {
		return "Received:    " + a.At.Format(timeLayout) +
			"  (the source supplied no time of its own)"
	}
	return "Observed at: " + a.At.Format(timeLayout)
}

// --- HTML -----------------------------------------------------------------

// Colours are inline because every mail client strips <style> blocks, and
// deliberately readable in a dark client too: no white-on-white panels.
func severityColour(sev incident.Severity) string {
	switch sev {
	case incident.SeverityCritical:
		return "#b3261e"
	case incident.SeverityHigh:
		return "#c25e00"
	case incident.SeverityMedium:
		return "#8a6d00"
	case incident.SeverityLow:
		return "#3a6ea5"
	default:
		return "#4a4a4a"
	}
}

func htmlBody(a channel.Alert, logo *InlineImage) string {
	esc := html.EscapeString
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html><html><body style="margin:0;padding:0;` +
		`background:#f4f4f5;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;">`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">` +
		`<tr><td align="center" style="padding:24px 12px;">` +
		`<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" ` +
		`style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;` +
		`border:1px solid #e4e4e7;">`)

	if logo != nil {
		fmt.Fprintf(&b, `<tr><td style="padding:20px 24px 0 24px;">`+
			`<img src="cid:%s" alt="" height="32" style="height:32px;border:0;display:block;">`+
			`</td></tr>`, esc(logo.ContentID))
	}

	fmt.Fprintf(&b, `<tr><td style="padding:20px 24px 4px 24px;">`+
		`<span style="display:inline-block;padding:3px 10px;border-radius:12px;`+
		`background:%s;color:#ffffff;font-size:12px;font-weight:700;letter-spacing:.06em;">%s</span>`,
		severityColour(a.Severity), esc(strings.ToUpper(string(a.Severity))))
	if a.IsRepeat() {
		fmt.Fprintf(&b, `<span style="margin-left:8px;font-size:12px;color:#6b7280;">`+
			`reminder %d &middot; stage %d</span>`, a.Repeat, a.Stage)
	}
	b.WriteString(`</td></tr>`)

	fmt.Fprintf(&b, `<tr><td style="padding:4px 24px 0 24px;font-size:20px;`+
		`line-height:1.3;font-weight:700;color:#111827;">%s</td></tr>`, esc(titleOf(a)))

	if body := strings.TrimSpace(a.Body); body != "" {
		fmt.Fprintf(&b, `<tr><td style="padding:12px 24px 0 24px;font-size:15px;`+
			`line-height:1.5;color:#374151;white-space:pre-wrap;">%s</td></tr>`, esc(body))
	}

	b.WriteString(`<tr><td style="padding:16px 24px 0 24px;">` +
		`<table role="presentation" cellpadding="0" cellspacing="0" border="0" ` +
		`style="font-size:13px;color:#4b5563;">`)
	row := func(label, value string) {
		fmt.Fprintf(&b, `<tr><td style="padding:2px 12px 2px 0;color:#6b7280;">%s</td>`+
			`<td style="padding:2px 0;">%s</td></tr>`, esc(label), esc(value))
	}
	if entity := strings.TrimSpace(a.Entity); entity != "" {
		row("Device", entity)
	}
	if !a.At.IsZero() {
		if a.AtIsArrivalTime {
			// Same rule as the plain part: "received", never "at".
			row("Received", a.At.Format(timeLayout)+"  (the source supplied no time of its own)")
		} else {
			row("Observed at", a.At.Format(timeLayout))
		}
	}
	if !a.OpenedAt.IsZero() {
		row("Open since", a.OpenedAt.Format(timeLayout))
	}
	if a.IncidentID != "" {
		row("Incident", a.IncidentID)
	}
	b.WriteString(`</table></td></tr>`)

	// The ack link appears in this part AND in the plain-text part, as a
	// button and as the bare URL beneath it -- clients that suppress the
	// styled anchor still leave something selectable.
	if ack := strings.TrimSpace(a.AckURL); ack != "" {
		fmt.Fprintf(&b, `<tr><td style="padding:20px 24px 4px 24px;">`+
			`<a href="%s" style="display:inline-block;padding:11px 22px;border-radius:6px;`+
			`background:#111827;color:#ffffff;font-size:15px;font-weight:600;`+
			`text-decoration:none;">Acknowledge</a></td></tr>`, esc(ack))
		fmt.Fprintf(&b, `<tr><td style="padding:8px 24px 0 24px;font-size:12px;`+
			`line-height:1.4;color:#6b7280;">Stops the escalation for this incident and `+
			`nothing else. If the button does not work:<br>`+
			`<a href="%s" style="color:#3a6ea5;word-break:break-all;">%s</a></td></tr>`,
			esc(ack), esc(ack))
	}

	if len(a.Snapshot) > 0 {
		fmt.Fprintf(&b, `<tr><td style="padding:16px 24px 0 24px;font-size:12px;`+
			`color:#6b7280;">A snapshot is attached as %s.</td></tr>`, esc(snapshotFilename))
	}

	b.WriteString(`<tr><td style="padding:20px 24px 22px 24px;font-size:11px;` +
		`color:#9ca3af;border-top:1px solid #f1f1f3;">UniFi Notification Matrix</td></tr>`)
	b.WriteString(`</table></td></tr></table></body></html>`)
	return b.String()
}

func testHTML(logo *InlineImage) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,` +
		`Helvetica,Arial,sans-serif;color:#111827;">`)
	if logo != nil {
		fmt.Fprintf(&b, `<p><img src="cid:%s" alt="" height="32" style="height:32px;border:0;"></p>`,
			html.EscapeString(logo.ContentID))
	}
	b.WriteString(`<p><strong>This is a test message from UniFi Notification Matrix.</strong></p>` +
		`<p>If it arrived, the SMTP host, transport security, authentication and routing ` +
		`for this channel are all working. No incident is open.</p></body></html>`)
	return b.String()
}
