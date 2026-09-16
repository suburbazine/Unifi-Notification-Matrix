// Package email delivers alerts by SMTP.
//
// Built on github.com/wneessen/go-mail rather than the standard library.
// net/smtp is frozen, cannot do implicit TLS on port 465 at all, and has no
// MIME support whatsoever -- which matters here because the part structure of
// an alert email is load-bearing rather than cosmetic. See buildMessage.
package email

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/channel"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// TLSMode selects how the connection is protected.
type TLSMode int

const (
	// TLSAuto picks implicit TLS on 465 and mandatory STARTTLS everywhere
	// else. It never picks "opportunistic": a mode that silently delivers in
	// the clear when STARTTLS is missing is indistinguishable from a working
	// one until somebody is reading the mail.
	TLSAuto TLSMode = iota

	// TLSSTARTTLS upgrades a plaintext connection and fails if it cannot.
	TLSSTARTTLS

	// TLSImplicit wraps the connection in TLS from the first byte (port 465).
	TLSImplicit

	// TLSNone sends in the clear. Exists for a relay on the same host or a
	// trusted LAN segment, and requires the operator to say so explicitly --
	// it is never reached by default.
	TLSNone
)

func (m TLSMode) String() string {
	switch m {
	case TLSAuto:
		return "auto"
	case TLSSTARTTLS:
		return "starttls"
	case TLSImplicit:
		return "implicit"
	case TLSNone:
		return "none"
	default:
		return "unknown"
	}
}

// InlineImage is an image referenced from the HTML part by content-id.
type InlineImage struct {
	// Filename is what a client shows if it displays the part at all.
	Filename string

	// ContentID is the bare id, without angle brackets. The HTML refers to it
	// as "cid:<ContentID>" and the part header carries "<ContentID>".
	ContentID string

	ContentType string
	Data        []byte
}

// DefaultLogoContentID is used when an InlineImage does not name one.
const DefaultLogoContentID = "notifymatrix-logo"

// Config is everything this channel needs. Plain data.
type Config struct {
	Host string
	Port int // 0 means 587

	From     string
	FromName string
	To       []string

	// Username empty means no authentication at all, which some LAN relays
	// and most submission-on-25 setups want.
	Username string

	// Password is a secret.Secret rather than a string so that a Config
	// reaching a log line through %v cannot leak it.
	Password secret.Secret

	TLS TLSMode

	// HELO overrides the name announced to the server. Needed where the relay
	// checks it against forward DNS, which is common enough on self-hosted
	// Postfix to be worth exposing.
	HELO string

	// Logo is an optional inline image for the HTML part. Optional in the
	// strongest sense: nothing about the alert depends on it rendering.
	Logo *InlineImage

	Timeout time.Duration
}

// DefaultTimeout bounds one SMTP conversation.
//
// Comfortably inside channel.DefaultSendTimeout so that a slow relay produces
// an SMTP error naming the host rather than an anonymous context deadline.
const DefaultTimeout = 25 * time.Second

// Channel sends alerts by SMTP.
type Channel struct {
	cfg Config

	// send is the transport, held as a field so message construction can be
	// tested without an SMTP server. The part structure is the part of this
	// channel most likely to regress, and it must be testable offline.
	send func(ctx context.Context, m *mail.Msg) error
}

// New builds a channel and refuses a configuration that cannot work.
func New(cfg Config) (*Channel, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	if cfg.Host == "" {
		return nil, errors.New("email: host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("email: port %d is not a port", cfg.Port)
	}
	cfg.From = strings.TrimSpace(cfg.From)
	if cfg.From == "" {
		return nil, errors.New("email: from address is required")
	}
	to := make([]string, 0, len(cfg.To))
	for _, r := range cfg.To {
		if r = strings.TrimSpace(r); r != "" {
			to = append(to, r)
		}
	}
	if len(to) == 0 {
		return nil, errors.New("email: at least one recipient is required")
	}
	cfg.To = to
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Logo != nil {
		if len(cfg.Logo.Data) == 0 {
			return nil, errors.New("email: logo is configured but has no data")
		}
		if cfg.Logo.ContentID == "" {
			cfg.Logo.ContentID = DefaultLogoContentID
		}
		if cfg.Logo.Filename == "" {
			cfg.Logo.Filename = "logo.png"
		}
		if cfg.Logo.ContentType == "" {
			cfg.Logo.ContentType = "image/png"
		}
	}

	c := &Channel{cfg: cfg}
	c.send = c.dialAndSend

	// Refuse addresses the message builder cannot use, here rather than on the
	// first alert. The same call the real path makes, so there is nothing to
	// drift: an address that fails now would have failed every delivery, and
	// that failure would otherwise surface at 3am as a line on an incident
	// record instead of as a refused configuration.
	if err := c.addresses(mail.NewMsg()); err != nil {
		return nil, err
	}
	return c, nil
}

// Name is the identifier used in policy stage lists and diagnostics.
func (c *Channel) Name() string { return "email" }

// Send delivers one alert.
func (c *Channel) Send(ctx context.Context, a channel.Alert) error {
	m, err := c.buildMessage(a)
	if err != nil {
		return err
	}
	return c.send(ctx, m)
}

// Test sends a harmless message proving host, TLS, auth and routing all work.
func (c *Channel) Test(ctx context.Context) error {
	m, err := c.buildTestMessage()
	if err != nil {
		return err
	}
	return c.send(ctx, m)
}

// tlsMode resolves TLSAuto against the port.
func (c *Channel) tlsMode() TLSMode {
	if c.cfg.TLS != TLSAuto {
		return c.cfg.TLS
	}
	if c.cfg.Port == 465 {
		return TLSImplicit
	}
	return TLSSTARTTLS
}

func (c *Channel) client() (*mail.Client, error) {
	opts := []mail.Option{
		mail.WithPort(c.cfg.Port),
		mail.WithTimeout(c.cfg.Timeout),
	}
	switch c.tlsMode() {
	case TLSImplicit:
		// Implicit TLS: TLS before the SMTP banner. This is the case net/smtp
		// cannot express, and port 465 is what most hosted providers hand an
		// operator first.
		opts = append(opts, mail.WithSSL())
	case TLSNone:
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default:
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}
	if c.cfg.HELO != "" {
		opts = append(opts, mail.WithHELO(c.cfg.HELO))
	}
	if c.cfg.Username != "" {
		// AutoDiscover negotiates from what the server advertises, and refuses
		// the plaintext-safe-only mechanisms on an unencrypted connection.
		// Pinning a mechanism here would mean a working relay stops working
		// the day it drops one.
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(c.cfg.Username),
			mail.WithPassword(c.cfg.Password.Reveal()),
		)
	} else {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	}

	cl, err := mail.NewClient(c.cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("email: smtp client for %s:%d: %w", c.cfg.Host, c.cfg.Port, err)
	}
	return cl, nil
}

// dialAndSend is the real transport.
//
// One dial per delivery rather than a pooled connection. Alerts are rare and
// bursty, mail servers drop idle sessions without telling anyone, and a
// half-dead pooled connection fails the ONE send that mattered. The queue in
// front of this channel is what keeps the cost off the ingest path.
func (c *Channel) dialAndSend(ctx context.Context, m *mail.Msg) error {
	cl, err := c.client()
	if err != nil {
		return err
	}
	if err := cl.DialAndSendWithContext(ctx, m); err != nil {
		// The host and port are in the message; the credential never is.
		return fmt.Errorf("email: sending via %s:%d (%s): %w",
			c.cfg.Host, c.cfg.Port, c.tlsMode(), err)
	}
	return nil
}

// String renders the channel without its credentials. See the identical method
// on the ntfy channel for why this is necessary: secret.Secret redaction does
// not survive being reached through an unexported struct field, so without
// this, %v on a *Channel prints the SMTP password in cleartext.
func (c Channel) String() string {
	return fmt.Sprintf("email{host:%s port:%d tls:%v from:%q recipients:%d password:<redacted>}",
		c.cfg.Host, c.cfg.Port, c.cfg.TLS, c.cfg.From, len(c.cfg.To))
}
