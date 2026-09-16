# UniFi Notification Matrix

<p align="center">
  <a href="https://github.com/suburbazine/Unifi-Notification-Matrix/releases/latest/download/notifymatrix-windows-amd64.exe"><img alt="Download for Windows, 64-bit" src="https://img.shields.io/badge/Windows-x64%20(.exe)-0078D4?style=for-the-badge&logo=windows&logoColor=white"></a>
  <a href="https://github.com/suburbazine/Unifi-Notification-Matrix/releases/latest/download/notifymatrix-linux-amd64"><img alt="Download for Linux, 64-bit" src="https://img.shields.io/badge/Linux-x64-1B1B1B?style=for-the-badge&logo=linux&logoColor=white"></a>
  <a href="https://github.com/suburbazine/Unifi-Notification-Matrix/releases/latest/download/notifymatrix-linux-arm64"><img alt="Download for Linux, ARM64" src="https://img.shields.io/badge/Linux-arm64-1B1B1B?style=for-the-badge&logo=linux&logoColor=white"></a>
</p>

<p align="center">
  <a href="https://github.com/suburbazine/Unifi-Notification-Matrix/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/suburbazine/Unifi-Notification-Matrix?include_prereleases&sort=semver&label=release"></a>
  <a href="https://github.com/suburbazine/Unifi-Notification-Matrix/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/suburbazine/Unifi-Notification-Matrix/total?label=downloads"></a>
  <a href="https://github.com/suburbazine/Unifi-Notification-Matrix/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/suburbazine/Unifi-Notification-Matrix/ci.yml?branch=main&label=CI"></a>
  <img alt="Signed and reproducible" src="https://img.shields.io/badge/builds-signed%20%2B%20reproducible-2ea44f">
  <a href="LICENSE.md"><img alt="Licence" src="https://img.shields.io/badge/licence-PolyForm%20Noncommercial-blue"></a>
</p>

<p align="center">
  <sub>
    Windows binaries are Authenticode-signed and timestamped; every binary
    ships a Sigstore bundle and SLSA provenance.<br>
    <b><a href="#verifying-a-download">Check what you downloaded</a></b> —
    it takes one command, and this is a program you are about to give
    a view of your cameras and doors.
  </sub>
</p>

> **Status: all three products ingest.** Protect, Access and Network.
> Built and tested: the incident lifecycle, the durable store, the escalation
> scheduler, the rule engine, acknowledgement, the secret store, configuration,
> the three sources, the inbound webhook receiver, the ingest supervisor and
> its deadman, the ntfy and email channels, the audit record, the local web UI,
> the capability probe, the setup checklist, and Windows-service / systemd
> integration.

UniFi tells you a thing happened. Once.

If nobody was looking at their phone in that minute, the event is gone — no
re-alert, no acknowledgement, no record that a human ever saw it. For
convenience notifications that is fine. For a door forced open at 3am, or a
camera that went dark an hour before a break-in, it is the whole failure.

**This turns a one-shot UniFi event into a tracked incident that keeps
escalating until a human closes it.**

- Ingests from UniFi **Protect**, **Access** and **Network** — the API where
  one exists, and an inbound webhook for the alarms that exist nowhere else.
- **Tells you what is left to configure**, checked against your real setup:
  `notifymatrix setup`. It can tell "configured" from "actually working".
- **Derives the two door alarms UniFi Access does not report at all**: a door
  forced open, and a door held open past a threshold. Neither exists as a
  readable value on any Access surface.
- Escalates on a policy ladder that widens over time: push, then email, then
  (later) an automated phone call.
- **Acknowledgement works from a phone with one tap**, no login required.
  For somebody off-site, a second listener carrying *only* the acknowledgement
  route can be pinned to a random high port — so a firewall forward has
  something safe to point at instead of publishing your status page.
- **Notices its own sources dying.** Every source declares how long its silence
  may last, and silence past that becomes an incident — because a dead source
  and a quiet site look identical from outside.
- Fans out to **ntfy**, **email**, **Pushover** and a **generic JSON webhook**
  — so it slots into whatever you already run. Voice is planned.
- Every channel has a **"send a test" button** that reports what actually
  happened to that attempt, including the service's own error text.
- A **local web UI**: status is visible to anyone on the LAN so it works as a
  wall display, and every change requires a password.
- An **append-only audit record** in plain JSONL — including the events a rule
  *silenced*, because "why was I not paged" is the hard question.
- A **capability probe** that asks your console what it actually exposes, so
  firmware revisions nobody here has seen can still be described. See below.
- Runs as a Windows service or a systemd unit. Single static binary, no runtime
  to install.
- API keys are encrypted at rest — **DPAPI** on Windows, and a machine-bound
  equivalent on Linux.

**New here? [docs/SETUP.md](docs/SETUP.md) walks through a first installation
from nothing.**

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design,
[docs/SOURCES.md](docs/SOURCES.md) for what each UniFi application actually
exposes, and [docs/DESIGN-RULES.md](docs/DESIGN-RULES.md) for the rules the
code follows and why.

---

## The alarms that need a rule made by hand

Some UniFi alarms are **not readable by any API**: WAN outages, threat
detections and PoE faults in Network; disk failure, storage and power loss in
Protect. They exist only as **Alarm Manager** rules that push to a URL — and no
API can create those rules, so nothing can provision them for you.

This product is designed *for* that rather than around it. You add a hook, it
generates a URL, you paste that URL into the rule, and then:

```
 check 5. Create the UniFi Alarm Manager rules
        now: configured, but nothing has ever arrived at wan-offline
             -- the rule may not exist yet
```

A hook that looks right is not evidence that anybody made the rule, so the
checklist reports it as **unverified** until an alarm actually arrives. Press
Test in UniFi and it changes to done.


---

## What it can and cannot see on UniFi Access

Access is the product with the largest gap between what you would expect and
what it reports, so it is worth being explicit.

**Derived here, because Access reports neither:**

| Alarm | How |
|---|---|
| Door forced open | The door became open *while locked*, with no unlock shortly before it. Decided on the transition, not the current state — "locked and open" is also where an ordinary entry ends up on a fast-relocking lock. |
| Door held open | The door position has read open for longer than the threshold (60s by default). |

**Read from the system log:** denied credentials, and the console's own
`critical` topic. The log lags by up to ~3.5 minutes, so the poll floor is
three minutes and rows are de-duplicated by row id rather than by time.

**Not offered, because the feature does not exist in Access:**
anti-passback (an unshipped roadmap item since 2022), tamper (no representation
on any surface), and battery-low (the line is entirely PoE). A rule that can
never fire is worse than no rule.

> **Most doors cannot be watched this way.** Forced and held both need a door
> position sensor, and `door_position_status` reads `"none"` on any door
> without one — a measurement across 28 doors on one console found 26 of them.
> The status page reports how many of your doors actually have a sensor, so
> this is visible rather than assumed.


---

## The capability probe

UniFi's surfaces are version-gated and under-observed. Protect's event
vocabulary went from 16 types to 39 between firmware revisions; Network's alarm
payload has spelled its message field four different ways. Documentation does
not fix that — observing real consoles does.

```bash
notifymatrix probe --host 192.168.1.1
```

It asks your console which endpoints answer and listens on each push socket,
then writes a JSONL report saying what this build does not handle (`NEW`) and
what it expects that your firmware does not have (`GONE`). It is useful on its
own, and you may choose to contribute it.

**Three things about it are worth knowing before you run it.**

**It only talks to local networks.** RFC 1918, loopback, link-local, IPv6 ULA
and Tailscale's range. Nothing else, enforced in the dialer against the actual
socket address rather than the hostname, on both the HTTP and WebSocket paths.
There is no flag to widen it — a probe pointed at an address you do not own is
an unauthorised scan run from your machine and your address.

**Nothing identifying reaches the file.** A raw probe of a UniFi console is a
map of your building: camera names are room names, door names are door names.
So names, MACs, IPs, ids, tokens and timestamps are replaced with meaningless
per-report counters *at capture time*, before anything is written. What
survives is field names, structure, types, UniFi's own vocabulary
(`smartDetectZone`, `CONNECTED`) and your firmware version — which is all a
schema contribution needs.

**Nothing is uploaded.** Contributing is a separate command that prints the
entire file first, so you read the exact bytes before deciding:

```bash
notifymatrix probe submit
```

If anything in that output identifies your site, that is a bug in this tool and
reporting it matters more than the contribution does.


---

## Licence — read this before you integrate

This project is **source-available, not open source.** It is licensed under the
[PolyForm Noncommercial License 1.0.0](LICENSE.md).

**You may** use, modify and distribute it for any noncommercial purpose —
personal use, hobby projects, research and study, and use by charities,
educational institutions, public research bodies, public safety and health
organisations, environmental organisations, and government institutions,
regardless of how they are funded.

**You may not** use it for a commercial purpose without a separate commercial
licence. That includes deploying it at a business, using it to deliver a paid
service, or bundling it into a product you sell.

Commercial licensing: **licensing@xtremission.com**

GitHub labels this repository "Other" because PolyForm is not an OSI-approved
licence. That is expected, not an error.

---

## Building

Requires **Go ≥ 1.26**. No other toolchain.

```
go build ./cmd/notifymatrix
```

Builds are `CGO_ENABLED=0` by design — it produces static binaries that run
anywhere including Alpine and Docker, and it keeps releases reproducible enough
that you can verify a published binary matches its tag.

Builds are reproducible: from a clean clone at the same tag, with the Go
version in `.go-version`,
`go build -trimpath -ldflags "-s -w -buildid= -X main.version=…"` produces the
released bytes exactly — verified against a published release, not assumed. That is the point of publishing source for
a security tool — source nobody can check against the binary buys very little.

## Verifying a download

Released binaries are signed. The strongest check needs no key trusted in
advance, and proves **which workflow in which repository** built the file:

```bash
cosign verify-blob notifymatrix-linux-amd64 \
  --bundle notifymatrix-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/suburbazine/Unifi-Notification-Matrix/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Download the `.sigstore.json` alongside the binary — it holds the signature,
the signing certificate and the transparency-log proof in one file.

```bash
gh attestation verify notifymatrix-linux-amd64 --repo suburbazine/Unifi-Notification-Matrix
```

On Windows the `.exe` is Authenticode-signed and timestamped
(`Get-AuthenticodeSignature`). Full instructions — including how to rebuild
from source and compare hashes yourself — are in
[docs/RELEASING.md](docs/RELEASING.md).

> Do not drop `--certificate-identity-regexp`. Without an identity constraint
> cosign verifies a signature from *anyone*, which proves nothing about who
> built your binary.

---

Copyright (c) 2026 Xtremission LLC
