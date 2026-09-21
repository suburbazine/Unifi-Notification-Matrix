# Security policy

This program is given a view of somebody's cameras and doors, holds the
credentials that let it keep that view, and puts one listener on the public
internet so an acknowledgement can arrive from a phone. A report about any of
that is worth more than a feature request, and it will be treated that way.

## Reporting a vulnerability

**Mail licensing@xtremission.com.** It is a secure mailbox and it reaches a
person, not a queue — so the details belong in the first mail rather than
after a round trip asking for somewhere to put them. Put *security* in the
subject; it is the same address the licence points at and that is what sorts
one from the other.

If you would rather keep the whole thing on GitHub, private reporting is
enabled here:
[**Report a vulnerability**](https://github.com/suburbazine/Unifi-Notification-Matrix/security/advisories/new).
The thread stays private between you and the maintainer until an advisory is
published, it carries attachments, and it is the better channel if you want a
published advisory or a CVE with your name on it at the end. Either channel
reaches the same person; take whichever you trust more.

**Please do not** open a public issue, a pull request or a discussion for
anything that would tell somebody how to reach a stranger's installation
before there is a fix to point at.

### What helps

- The version (`notifymatrix version`), the platform, and whether it is a
  Windows service, a systemd unit or a UniFi appliance install.
- What an attacker would need to be able to reach — the LAN, the forwarded
  acknowledgement port, an already-authenticated session, the machine itself.
- The smallest thing that demonstrates it. A failing test against this
  repository is ideal; a description in prose is fine.

### What to leave out

**Do not send anything from a real site.** Camera and door names are room names
and door names, a console address is a home address, and an acknowledgement
token is live until its incident closes. Redact them, or reproduce it against
`notifymatrix demo`, which runs the whole interface over fabricated data with
nothing pointed at anybody's building.

**Test against your own equipment only.** A probe or a request aimed at a
console you do not own is an unauthorised scan run from your address, and it is
not something this project can accept a report from.

## What happens next

- **Within 3 days:** acknowledgement that a human has read it.
- **Within 7 days:** whether it is confirmed, what its blast radius looks like,
  and roughly when a fix lands.
- **On the fix:** a release, a `CHANGELOG.md` entry that says plainly what was
  wrong and who it affected, and a published advisory.

This is a small project. The honest commitment is those first two dates and a
fix as soon as one exists — not a fixed remediation window regardless of
severity. Please give it 90 days, or until a release ships, whichever comes
first. If something is already being exploited, say so and that clock does not
apply.

Credit goes in the advisory and the changelog under whatever name or handle you
want, or none. **There is no bounty.** Saying so plainly is better than leaving
you to find out after the work.

## Supported versions

| Version | Supported |
| --- | --- |
| The most recent release | Yes |
| Anything older | No — upgrade |

Fixes ship forward, on the current release. Nothing is backported, and while
this is pre-1.0 that is the only promise that would be kept. Upgrading is one
binary and a restart, and the interface has an updater that verifies the
signature before it swaps anything.

## What is in scope

Roughly in order of how much a finding there would matter:

- **The acknowledgement listener.** It is the only part intended to face the
  internet. Anything that acknowledges an incident without a valid token,
  reaches anything other than `/ack/` on that port, distinguishes a real token
  from a well-formed wrong one by timing or response, or takes the daemon down
  from unauthenticated requests.
- **The secret store.** Console and channel credentials are encrypted at rest.
  Anything that reads them back without the key, recovers the key from
  somewhere it should not be, or leaks a credential into a log, the audit
  record, an error page or the interface.
- **Authentication to the interface.** The setup token, the password, the
  session, and anything that lets an unauthenticated request do something an
  authenticated one should have been needed for.
- **The event sources.** TLS pinning to the console, the inbound webhook
  receiver and its token, and anything in event handling that a crafted payload
  can push somewhere it should not go.
- **The probe's two promises.** It talks to local addresses only — RFC 1918,
  loopback, link-local, IPv6 ULA and Tailscale's range — enforced against the
  resolved socket address on both the HTTP and WebSocket paths. And nothing
  identifying reaches its report file. **A way around either is a real
  finding**, and the second one matters more than any schema contribution.
- **The release chain.** A published binary that does not reproduce from its
  tag, a Sigstore bundle or provenance attestation that verifies against an
  identity it should not, or an updater that would install something it should
  have refused.

## Already known, and written down

These are documented, not overlooked. A report is still welcome if you can make
one of them worse than described — but this is why they will not be treated as
news.

- **The acknowledgement token travels in cleartext by default.** HTTPS on that
  port is not built in, and the ACME challenges that would automate it need
  inbound 80 or 443, which residential connections commonly block. The blast
  radius of an intercepted token is bounded: it acknowledges one incident —
  stopping that escalation — and grants nothing else. `web.ack_base_url`
  accepts an `https://` address if you are already terminating TLS in front of
  it.
- **The random acknowledgement port is not a security measure.** A scan finds
  an open port whatever its number. The token is what protects an
  acknowledgement; the port only avoids the handful scanners hammer constantly.
- **A UniFi appliance install runs as root, in `/data`.** It is explicitly not
  the recommended way to run this — see [`docs/GATEWAY.md`](docs/GATEWAY.md),
  which says so and says why. Findings there are still in scope; the
  configuration itself is a known trade, not a discovery.
- **An installation that runs on the equipment it watches cannot report its own
  failure.** It shares fate with that equipment. The interface says so on every
  screen, including signed out.
- **A call cannot be acknowledged from the handset**, and there is no live
  configuration reload. Both are missing features, listed in the README.

## Out of scope

- Findings about UniFi Protect, Access, Network or UniFi OS themselves. Report
  those to Ubiquiti. If one changes what this program should do, that is a bug
  here and worth an issue.
- Anything that needs an attacker to already be an authenticated operator, or
  to already have the machine. An operator can stop the service and read the
  database; that is what the password is for.
- Demo mode. It fabricates everything, refuses to run against a real
  installation, and constructs no channel.
- Missing hardening with no demonstrated consequence — a header, a cipher
  preference, a scanner's score on its own.
- Denial of service that requires the local network and unlimited requests
  against an interface that is meant to be on the local network.

## Verifying what you downloaded

If you are about to report that a binary behaves strangely, check that it is
the binary that was published. Both commands are in the
[README](README.md#verifying-a-download), and the second needs nothing trusted
in advance:

```bash
gh attestation verify notifymatrix-linux-amd64 --repo suburbazine/Unifi-Notification-Matrix
```

**A binary that does not verify is itself the report.** Send that one first.
