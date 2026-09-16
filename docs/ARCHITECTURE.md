# UniFi Notification Matrix — architecture

Status: **settled; ready to build against.** The UniFi event surfaces, the
Linux secret store, and the voice/exposure questions were researched in
September 2026 and are recorded in [SOURCES.md](SOURCES.md). The open items in
§11 are field measurements and one licence-of-the-console question, none of
which block starting.

Stack: **Go**, `CGO_ENABLED=0`, single static binary per platform.
Licence: **PolyForm Noncommercial 1.0.0** (source-available; commercial use
requires a licence from Xtremission LLC).

---

## 1. What this product is

UniFi tells you a thing happened. Once.

Protect pushes a notification, Access writes a log line, Network flips a device
to offline — and if nobody was looking at their phone in that minute, the event
is gone. There is no re-alert, no acknowledgement, and no record that a human
ever saw it. For convenience notifications that is fine. For a door forced open
at 3am, or a camera that went dark an hour before a break-in, it is the whole
failure.

**This product's entire reason to exist is turning a one-shot event into a
tracked incident that keeps escalating until a human closes it.**

Everything else — the extra channels, the email, the eventual phone call — is
delivery plumbing in service of that. If the escalation engine is right and the
channels are mediocre, the product works. If the channels are beautiful and the
escalation engine loses an alarm across a service restart, it is worthless.
That ordering decides every trade-off below.

### What it deliberately is not

- **Not a UniFi replacement.** It does not store video, mirror the console, or
  re-implement Protect's UI. It reads events and it nags.
- **Not a general automation engine.** No scripting language, no node graph.
  Rules map events to severities and policies; that is the ceiling. Anything
  more expressive belongs in Home Assistant or Node-RED, which this product
  feeds via webhook rather than competes with.
- **Not a cloud service.** It runs on the operator's own machine, on the same
  LAN as the console. There is no account, no relay, and nothing phones home.

---

## 2. The central abstraction is the Incident, not the notification

A notification is a message that was sent. An incident is a condition that is
still true. Only the second one can be nagged about, and only the second one
can be acknowledged.

```
  Source ──► Event ──► Rule ──► Incident ──► Escalation ──► Channels
                                    ▲                           │
                                    └────────── Ack ◄───────────┘
```

- **Event** — something a source observed. Immutable, timestamped, normalised.
- **Rule** — decides whether an event opens, updates, or closes an incident,
  and at what severity. Also supplies the **dedup key**.
- **Incident** — durable state with a lifecycle (§4). This is the unit the
  product is about.
- **Escalation** — a policy attached to a severity that decides *when* to
  re-alert and *through which channels*, widening over time.
- **Channel** — a way to reach a human. Stateless; it sends and reports.
- **Ack** — a human asserting they have seen it. Arrives from any channel.

**Dedup is not an optimisation, it is correctness.** A camera flapping on a bad
PoE port generates fifty offline/online events in a minute. That is one
incident — `protect/camera/<id>/offline` — which opens once, absorbs the
subsequent events as updates, and re-alerts on *its own* schedule rather than
the event rate. Without this, the first genuine alarm storm trains the operator
to ignore the product, which is a worse failure than not sending at all.

---

## 3. Module layout

Layered so that ingest, decision and delivery are separable: a source knows
nothing about channels, and a channel knows nothing about UniFi.

`✓` exists and is tested; `·` is not written yet.

```
✓ cmd/notifymatrix/     main; CLI verbs (version, selfcheck)
  internal/
  ✓ unifi/              shared per-console pacing, backoff, TLS + cert pinning
    source/
  ✓   protect/          Protect ingest: two WebSockets + reconciliation sweep
  ·   access/           Access ingest: notifications socket + system-log tail
  ·   network/          Network ingest: poll + Alarm Manager webhook
  ·   inbound/          generic webhook receiver (Alarm Manager, other apps)
  ✓ event/              Event, Entity, the shared condition vocabulary
  · rule/               matching, severity mapping, dedup-key assignment
  ✓ incident/           lifecycle (state derived, not stored) + Store interface
  ✓ store/              SQLite implementation of incident.Store
  ✓ escalate/           policies, the scheduler, re-alert timing
    channel/
  ✓   (root)            Alert, Channel interface, per-channel bounded queue
  ✓   ntfy/  email/
  ·   pushover/  webhook/  voice/
  · ack/                HMAC token mint + verify, ack routes
  ✓ secret/             Secret type, the four-tier prefix chain
  · config/             YAML, written by the web UI, source of truth
  · service/            install/uninstall, recovery actions, single-instance (§9a)
  · selfcheck/          diagnostics for "it is running and nothing happens"
  · audit/              append-only record: every event, delivery, ack
  · web/                local UI: setup, live incidents, ack
```

**The store is `internal/store`, not inside `internal/incident`.** The
interface lives with the type it carries (`incident.Store`) and the SQLite
implementation lives apart from it, so nothing in the lifecycle logic can quietly
acquire a dependency on a database.

`internal/unifi`, `internal/source/access` and `internal/source/protect` build
on prior in-house implementations of these APIs rather than starting from the
published specifications alone. The rules they carry forward — and the reasons
for each — are in [DESIGN-RULES.md](DESIGN-RULES.md), which is worth reading
before changing anything in those packages: most of it looks like
over-engineering until the failure it prevents actually happens.

---

## 4. The incident lifecycle

```
                    ┌──────────────────────────────────────┐
                    │                                      │
  event ──► [OPEN] ──► [ALERTING] ──► [ACKNOWLEDGED] ──► [RESOLVED] ──► [CLOSED]
                 │           │              │                 ▲
                 │           └── re-alert ──┘                 │
                 │              (escalating)                  │
                 └── source reports condition cleared ────────┘
```

| State | Meaning | Re-alerts? |
|---|---|---|
| `OPEN` | Rule matched; not yet delivered | — |
| `ALERTING` | Delivered at least once, no human response | **Yes**, on the policy ladder |
| `ACKNOWLEDGED` | A human asserted they have seen it | No |
| `RESOLVED` | The source reports the condition cleared | No |
| `CLOSED` | Terminal. Acknowledged *and* resolved, or manually closed | No |

Two independent facts, deliberately not collapsed into one:

- **Acknowledged** — a *person* responded.
- **Resolved** — the *condition* ended.

They are orthogonal and both matter. A door still standing open that someone
has acknowledged should stop paging but must not disappear from the board — it
is an open obligation. A door that closed itself at 3am with nobody ever
acknowledging is a thing the morning shift needs to see, not something the
system quietly erases. Collapsing these into a single `done` flag loses exactly
the case the product exists for.

An acknowledged-but-unresolved incident that later re-opens (the condition
recurs after clearing) becomes a **new** incident with a link to its
predecessor, rather than reviving the old one. Reviving would make the ack
apply to an event the acknowledger never saw.

### Durability is not negotiable

**The incident store must survive a process restart, a crash, and a reboot with
the alarm still alarming.** A watchdog that forgets its alarm when it restarts
is the specific failure this product cannot have — and service restarts are
most likely during exactly the power and network events that generate alarms.

Consequences:

- The store is **on disk and transactional**, not in memory with periodic
  flush. Embedded SQLite via `modernc.org/sqlite` — pure Go, no cgo — rather
  than `mattn/go-sqlite3`, which needs cgo and is disqualified by §10.
- Escalation schedule state is **derived from the store**, never held only in
  a timer. On start, the scheduler reconciles: every `ALERTING` incident is
  re-armed from its persisted `last_alert_at` and policy.
- An incident whose next re-alert was due *during* the downtime fires
  immediately on start, **once** — not once per missed interval. A restart must
  not produce a burst.

---

## 5. Escalation and acknowledgement

### Policy, not hardcoded ladder

A policy attaches to a severity and states: the re-alert interval, whether it
backs off or stays flat, which channels are in play at which stage, and when
(if ever) it gives up.

```yaml
policies:
  critical:
    stages:
      - after: 0s      channels: [ntfy, email]
      - after: 2m      channels: [ntfy, email, pushover]
      - after: 10m     channels: [ntfy, email, pushover, voice]
    repeat_every: 5m          # after the last stage, keep nagging
    give_up_after: never      # critical never gives up
    quiet_hours: ignore       # critical ignores quiet hours
  high:
    stages:
      - after: 0s      channels: [ntfy]
      - after: 15m     channels: [ntfy, email]
    repeat_every: 30m
    give_up_after: 4h
```

`give_up_after: never` is the default for `critical`, and it is deliberate: a
product whose top severity eventually gives up has a silent failure mode
precisely when nobody is around, which is when it matters. The operator can
change it; the default will not do it for them.

**Quiet hours never apply to `critical`.** They are available for lower
severities. A product that can be configured into silence during an alarm is
one support call away from a very bad outcome, so the control does not exist
at that level.

### Acknowledgement must work from a phone, without a login

This constraint drives more of the design than it looks like it should.

The person receiving a 3am ntfy push is not going to VPN in and sign into a web
UI. So an ack must be reachable as **a single tap on an unauthenticated URL**
carrying its own authority:

```
https://<host>/ack/<incident-id>/<token>
```

- `token` is an **HMAC** over `(incident-id, opened-at)` keyed by a
  per-installation secret. Unguessable, verifiable without a lookup table, and
  scoped to exactly one incident — a leaked token acknowledges one alarm and
  grants nothing else.
- It is **single-purpose**. The route acknowledges and returns a confirmation
  page. It cannot read incidents, change config, or reach any other surface.
- It is **idempotent**. Two taps is not an error.
- The ack is **attributed to the channel it arrived through** (`ack via ntfy`),
  not to a user, because there is no identity here. The audit record says what
  is actually known and not one word more.

Ack arrives from:

| Route | Mechanism |
|---|---|
| ntfy | action button pointing at the ack URL |
| email | link in both the plain-text and HTML parts |
| web UI | authenticated button |
| inbound webhook | `POST /api/ack` with the token |
| voice *(later)* | DTMF "press 1" — §8, pending research |

Reachability from outside the LAN is the operator's decision, documented with
its trade-offs in §9. **It is not required for the product to work** — an
operator on the LAN, or on a VPN, acknowledges fine with nothing exposed.

---

## 6. Secrets at rest

The `Secret` type carries over from earlier in-house work **whole**,
including the property that makes it worth carrying: it
marshals to a *prefixed* string recording **how** it was protected, and its
`String()` returns `<redacted>`, so a secret reaching a log line through `%v`
is a non-event. `Reveal()` is the only path to plaintext, named so that every
use site is greppable.

That design already anticipated this project. Its non-Windows file says:

> If macOS or Linux ever ships, this is the file that must grow a real keystore
> — Keychain and Secret Service respectively — rather than the place to shrug.

Linux ships here, so that file grows up. Two things are already decided:

- **Windows: DPAPI machine scope**, unchanged. `CRYPTPROTECT_LOCAL_MACHINE`
  because the service account and the interactive operator must share one
  config — the daemon runs as a service and is configured from a browser
  session. Prefix `dpapi:`.
- **Whatever Linux gets, it must not lie.** The prefix states what actually
  happened. A config claiming protection it does not have is worse than one
  that admits it, because the second can be noticed.

### Linux: `systemd-creds` primary, with a real fallback chain

**Secret Service is the wrong answer, and the failure is specific rather than
theoretical.** `go-keyring` calls `dbus.SessionBus()`; for a systemd *system*
unit there is no `$DBUS_SESSION_BUS_ADDRESS` and no `/run/user/<uid>/bus` (a
system unit with `User=` gets no logind session), so it falls through to
exec'ing `dbus-launch` — which dies with *"Cannot autolaunch D-Bus without X11
$DISPLAY"*. Worse, if a session bus **is** manufactured, `go-keyring`'s
`Unlock` waits on an unbounded `<-promptSignal` with no timeout: a locked login
keyring makes the daemon **hang forever** rather than fail. `secret-tool` is
the same libsecret client on the same bus and fails identically.

Secret Service is the right answer for a desktop application with a logged-in
user. It is the wrong one for a daemon, and the difference is easy to miss
because the API is identical in both cases — it simply never returns.

**Primary: `systemd-creds`, shelled out** — no cgo, no Go binding, no D-Bus.
Stored base64 behind an `sdcreds:` prefix exactly parallel to `dpapi:`.

**The key mode is chosen explicitly and is never `auto`.** `auto` tries TPM2 and
then falls back to the host key — and the host key lives in
`/var/lib/systemd/credential.secret`, which is *"only accessible to the root
user"*. Since the service runs as `notifymatrix` (§9a), that fallback is not
available to it, so `auto` would make the outcome depend on a path we cannot
take and fail at *write* time rather than at probe time. The probe decides
while a lower tier can still be chosen:

| Mode | Needs | Worth |
|---|---|---|
| `host+tpm2` | root **and** a TPM | strongest available |
| `host` | root | matches DPAPI machine scope exactly, including its weakness — both fall to a full disk image |
| `tpm2` | `/dev/tpmrm0` only | key derived from the TPM, never on disk, so a stolen disk yields nothing. **The mode an unprivileged service can actually reach** |

Which means the unit needs `SupplementaryGroups=tss` on any machine with a TPM,
and the probe **opens** the device rather than stat-ing it: `/dev/tpmrm0` is
typically `root:tss` mode 0660, so presence is not access, and stat would
report a tier that fails on first write.

It is the right primary because it is the only option that is simultaneously
OS-native (already present on Debian 12, RHEL 9, Ubuntu 24.04 — zero install
steps), genuinely unattended, and cgo-free by construction. `--tpm2-pcrs=`
**defaults to empty**, so credentials survive reboots and firmware or kernel
updates with no re-seal, no prompt and no PIN.

**The honest calibration**, which belongs in the docs rather than in a sales
sentence: `--with-key=host` matches DPAPI machine scope *exactly, including its
weakness* — both fall to a full disk image (`credential.secret` there, the
`SYSTEM`+`SECURITY` hives here). Where a TPM exists, `auto` silently upgrades
to `host+tpm2`, which is stronger than anything Windows offers.

**The fallback chain is the majority path, not decoration.** `systemd-creds`
needs systemd ≥ 250; Ubuntu 22.04 LTS ships 249.11, Alpine has no systemd, and
Docker has neither the binary nor a durable host key. Probed at write time, and
the result recorded in the file:

| Tier | Prefix | Mechanism | Rescues |
|---|---|---|---|
| 1 | `sdcreds:` | `systemd-creds`, systemd ≥ 250, readable `/var/lib/systemd/credential.secret` | Debian 12, RHEL 9, Ubuntu 24.04 |
| 2 | `tpm2:` | Seal under the SRK, no PCR policy, via `github.com/google/go-tpm` (**verified cgo-free**; *not* `go-tpm-tools`) | Ubuntu 22.04, Alpine, TPM-passthrough Docker |
| 3 | `agekey:` | `golang.org/x/crypto/nacl/secretbox` under a 0600 key file owned by the service user, in a 0700 directory, absolute path recorded in config — **already an indirect dependency, zero new modules** | Everything else |
| 4 | `plain:` | Not encrypted, and says so | Dev builds |

> **Docker trap.** `--with-key=auto` in a container does **not** fail — it
> succeeds *silently*. The TPM2 check fails on `detect_container()`, but the
> host-key check only tests for a temporary filesystem, and an overlay2
> writable layer is not tmpfs. So it writes `credential.secret` into the
> ephemeral layer and emits a valid blob with no error and no warning — and
> every secret becomes unreadable on the next container restart. Tier 1 must
> explicitly refuse when a container is detected and fall to tier 2 or 3.

**Config gains a `secrets` metadata block** carrying a keyed-hash host
fingerprint. Today a decrypt failure escapes `UnmarshalJSON` and surfaces from
`Open` as a **parse error** — a config carried between machines reports as
corrupt rather than as foreign. The fingerprint turns that into a named
message.

Two things to settle before first ship, because both cost a migration
afterwards — the same reasoning already recorded for the Windows scope choice:

- **Does the Linux service run as root?** `--with-key=host` must read
  `/var/lib/systemd/credential.secret` (0600 root). Under `User=notifymatrix`
  the write path needs a small root helper, or tier 2 (which needs only group
  `tss`), with reads coming from `LoadCredentialEncrypted=`.
- **Linux tiers 1 and 2 are strictly tighter than DPAPI machine scope** —
  root/`tss` only, where DPAPI allows any local account. That is an
  improvement, but it means a config written by the service cannot be read by
  an operator-run CLI without `sudo`. Intentional, and it needs to be the
  documented behaviour rather than a surprise.

---

## 7. Sources

Full surface detail, payload shapes and traps: **[SOURCES.md](SOURCES.md)**.
The decisions that follow from it:

### Protect — official WebSockets

Protect is commonly assumed to have no push surface for third parties. That is
true of the *unofficial* paths most integrations historically used, and false
of the current API. The official
Integration API has carried `subscribe/events` and `subscribe/devices` since at
least the v6.2.83 spec, on the **same `X-API-Key`** as REST. That is the
primary ingest path — no local admin credentials, no private endpoint.

Three consequences that are structural rather than incidental:

- **Two sockets, not one.** Camera disconnect is not an event type; it is a
  `state` flip to `DISCONNECTED` on the *devices* channel. Watching only
  `subscribe/events` means never learning a camera went dark, which for this
  product is a headline failure rather than a gap.
- **No resume cursor on either socket.** A reconnect loses everything that
  happened during the gap, with no way to detect that it did. **Every reconnect
  triggers a paced REST reconciliation sweep**, and open-alarm state is
  re-derived from that sweep rather than from an assumption that the stream was
  continuous.
- **NVR storage, disk failure and power loss are absent from the public API
  entirely**, so they arrive only via Alarm Manager's outbound webhook — whose
  payload identifies devices by **bare MAC**. A MAC→deviceId map built from
  `GET /v1/cameras` is required for those alarms to be actionable.

The unofficial `ws/updates` socket is **rejected**, despite being the only path
that carries everything in one resumable stream. It requires storing a local
admin username and password rather than an API key, and Home Assistant — its
largest consumer and the reason it stays exercised — is migrating off it onto
the same public API. The reasoning is recorded in SOURCES.md §1 so it is not
relitigated every time someone notices how convenient it looks.

### Access — the socket is a lock-state accelerator, not an alarm surface

Both captured message shapes carry lock state and `remain_unlock` and **nothing
else** — no door position, no tamper, no offline, no battery, no emergency
state. System logs are therefore the **engine of record** for every Access
alarm class, with the socket as an accelerator on top.

- **Poll floor is ~3 minutes**, set by measured log *indexing lag* (up to ~3.5
  min), not by the 220 ms pacer. Polling faster buys nothing and spends budget
  the Protect reconciliation sweeps need.
- **Overlap windows and dedupe on `LogEntry.ID`.** `since`/`until` are seconds
  while `event.published` is milliseconds, and boundary semantics have never
  been measured. The row id can be trusted for correctness; the time boundary
  cannot.
- **A connected-but-silent socket must drive an automatic fallback to
  polling.** On unfamiliar hub hardware the socket connects and then says
  nothing, which in this product is silent total failure of the Access source.
  Counting unrecognised messages is what makes that visible; acting on the
  count is what makes it survivable.
- **Three rules are not offered, because the features do not exist**:
  anti-passback (an unshipped roadmap item since 2022), held-open-past-threshold
  (an open feature request — derived by polling `door_position_status` instead),
  and battery-low (the Access line is entirely PoE). Offering a rule that can
  never fire is worse than omitting it.

### Network — no event surface in the API at all

The Local Integration API (`/proxy/network/integration/v1/`, Network 9.0+) is
broad — sites, devices, clients, firewall CRUD — and contains **zero**
occurrences of "event", "alarm", "webhook" or "subscribe". Network's events
come from **its own Alarm Manager** (Network 9.3+, separate from Protect's),
and there is no other path.

Its payload is undocumented, field-inconsistent across firmware (the message
field has been `message`, `msg`, `text` and `description`), and carries **no
controller timestamp** — unlike Protect's, which does. Stamp on arrival and say
so in the incident.

### One operational consequence of pinning

**A certificate pin mismatch stops the source**, and does not retry. That is
DESIGN-RULES §1 applied literally — pinning refuses rather than warns, and only
a pin mismatch is terminal — but it has a consequence worth stating before
somebody meets it at 3am: a console whose certificate is legitimately renewed
will stop being ingested until an operator re-pins it.

That is the intended trade. Trust-on-first-use is an operator action, so
silently accepting a new certificate would defeat the pin on exactly the
connection an attacker would target. What makes it survivable is that the
failure is **loud**: `Run` returns the error rather than looping, the supervisor
sees a source that stopped, and the §9 deadman raises it as an incident through
the ordinary escalation machinery. A pin mismatch must never be the quiet kind
of failure.

### The shape this forces

**Ingest is a fallback hierarchy, and polling is a permanent backstop rather
than a fallback.** Every push path here can fail silently: Protect's sockets
have no cursor, Access's socket can connect and stay mute, and webhook delivery
depends on the console being able to route to us — which fails for cloud-hosted
controllers and most reverse proxies, with no error on either end.

**No source can self-provision its own push path.** Alarm Manager rules are
UI-configured in all three products with no API to create them. Onboarding must
walk the operator through it with a Test Alarm verification step, designed
*for* that rather than apologising for it.

And the same logical event arriving by two routes must collapse to one incident
(§2) — which is why the dedup key belongs to the rule rather than to the
source.

## 8. Channels

Ported from proven code, with their recorded field knowledge intact:

| Channel | Rules it must keep ([DESIGN-RULES.md](DESIGN-RULES.md) §5) |
|---|---|
| ntfy | text fields as **query params, not headers** — headers cannot carry newlines and need RFC 2047 for non-ASCII; bounded 429 retry honouring `Retry-After` |
| Pushover | severity→priority map |
| JSON webhook | stable `event` discriminator, with a transitional legacy field whenever it changes |
| Email | **plain text is always the base part**, HTML added as an alternative — a security alert must survive HTML-stripping gateways; inline CID logo |
| Voice | new; Twilio first, see below |

Email is the one real build cost: Go's stdlib `net/smtp` is frozen and
minimal. `github.com/wneessen/go-mail` (cgo-free) handles implicit TLS on 465
and multipart/alternative with inline CID parts.

### Voice — the top rung, and it does not require exposing an endpoint

The obvious assumption is that "press 1 to acknowledge" needs a public callback
URL, because DTMF normally arrives on a real-time inbound webhook during the
call. **That assumption is wrong for every provider surveyed.** All of them
expose a poll-by-call-id path that returns the collected digits after the fact:
Twilio via the Studio Execution Context, Amazon Connect via
`GetContactAttributes`, and Bland, Vapi and Retell via a plain
`GET /calls/{id}`. An early finding claimed these were webhook-only; the
adversarial pass established that was a search failure rather than a real gap.

**Build against Twilio first**, as two separable capabilities:

1. **Speak-and-hang-up** for the non-top rungs — a plain REST POST to the Calls
   resource with a Twilio-hosted TwiML Bin. Trivial from Go, zero inbound
   exposure.
2. **Press-1-to-acknowledge** for the top rung — one Studio Flow authored once
   in Twilio's console (Say → Gather Input), triggered by REST, with the daemon
   polling `GET /v2/Flows/{FlowSid}/Executions/{Sid}` for the digit.

**Keep the escalation script terse.** Twilio bills TTS **per 100 characters**,
not per request — Basic free, Premium Standard $0.0008, Neural $0.0032,
Generative $0.0130 per 100 chars. Cost scales with prompt *length* independently
of call duration, so a verbose alert script is charged for being verbose. (For
comparison, Amazon Connect lands near $0.043/min all-in plus a mandatory DID —
roughly 9× the naive quote, and the heaviest integration of the seven.)

**The strongest argument against the Studio-polling design**, recorded because
it may well win later: the daemon needs an inbound HTTP receiver anyway (§9),
so standing up one tunnel and using each provider's native webhook `Gather`
would be more uniform — and would keep the top rung's behaviour inside
versioned code rather than in Twilio-console configuration that no code diff
will ever show. The polling design is chosen for the first release because it
makes voice work with **nothing exposed at all**; revisit it once the tunnel
story is settled in practice.

**Delivery never blocks ingest.** A greylisting mail server will otherwise
drag the whole ingest cycle progressively later — this is a failure mode that
has been observed in production, not a hypothetical. Sends run on a background
worker with a bounded queue, and the queue is **per channel**, so a stalled
SMTP connection cannot delay an ntfy push behind it.

A delivery failure is recorded on the incident and **does not count as an
alert** for escalation purposes. If every channel failed, the incident has not
been alerted, and the next attempt must come sooner rather than later.

---

## 8a. Exposure — what must be reachable, and from where

The single question an installer will get wrong, so the product answers it
rather than leaving it to a support call. Sources are split by trust, because
they genuinely differ:

| Traffic | Reachability needed | Protection |
|---|---|---|
| Protect / Network / Access Alarm Manager → us | **None.** Same LAN | Bind LAN-only; shared-secret header (`Authorization: Bearer`, supported on the POST action) |
| Voice provider → us | **None**, by design (§8 polls instead) | n/a |
| Operator's phone → ack URL | **Yes**, from wherever they are | HMAC token, single incident, idempotent (§5) |
| Other SaaS senders → us | Yes, if used | HMAC-in-header, timestamp + nonce **bound into the signed material**, ~5 min replay window |

**The consoles need nothing exposed.** They are on the same LAN as the daemon
and connect outbound to it. Any design that starts by port-forwarding for
UniFi's sake has misread the problem.

**Only the ack URL genuinely wants outside reachability**, and even that is
optional — an operator on the LAN or on a VPN acknowledges fine with nothing
exposed. Where it is wanted, the shipped default is a **Cloudflare Tunnel**:
no port forward, no inbound firewall rule, no certificate to manage. Tailscale
Funnel is offered where Tailscale is already the site's remote-access story.
ngrok is for development and is labelled as such.

**mTLS is not offered.** It is impractical against every cloud sender in scope
and would be security theatre on the LAN path, which already has a bearer token
and no route from outside.

One open operator-experience question, recorded rather than guessed: whether
the LAN-only Protect listener should *also* require the shared secret, for
defence in depth against a compromised LAN device. It costs the installer one
paste into Alarm Manager's custom-header field. Leaning yes — a security
product that trusts its own LAN unconditionally has made the assumption that
most incidents disprove.

---

## 9. Failing loud

A security product that silently stops working is worse than no product,
because it occupies the slot a working one would have.

- **Source deadman.** Every source declares an expected liveness interval.
  Silence beyond it raises an incident *about the source* — "Protect has sent
  nothing for 30 minutes" — through the same escalation machinery. This catches
  the failures that matter most: a revoked API key, a console reboot that never
  finished, a pulled cable.
- **Scheduled self-test.** A synthetic incident at a configured interval
  (default weekly), delivered through every enabled channel and
  auto-acknowledged. It proves the whole path, not merely that the config
  parses.
- **A socket that is live but mute is a fault, not a success.** Unrecognised
  messages are counted, and a channel that connects and never says anything
  intelligible is reported rather than trusted.
- **Delivery failures are surfaced, never only logged.** Repeated failure on a
  channel is itself an incident.

---

## 9a. Running as a service, and coming back by itself

A watchdog that stops when somebody logs out is not a watchdog. The product
must survive a logout, a crash and a reboot with no human involved, and it must
be controllable without one either.

### The GUI question is already answered, and that is why the web UI won

**A GUI application cannot run as a Windows service.** Services run in Session
0, isolated from the interactive desktop, so a native window cannot appear
there. Every product that tries ends up with two processes — a headless
enforcer and a separate viewer — and then has to stop them fighting each other.

The choice in §5 of a **headless daemon plus a local web UI** removes that
problem rather than solving it. The operator's interface is a browser page
served *by* the service, so there is no Session 0 boundary to cross, no second
process, and the same interface works from a phone on the LAN.

### Supervision

| | Windows | Linux |
|---|---|---|
| Survives logout | Service, inherently | systemd unit, inherently |
| Starts at boot | `StartType: Automatic` | `WantedBy=multi-user.target`, enabled |
| Restarts on crash | **SCM recovery actions** | `Restart=always`, `RestartSec=5` |
| Restart storm guard | reset period | `StartLimitIntervalSec` / `StartLimitBurst` |

**Recovery actions are the part that is usually missed.** Installing a service
with `StartType: Automatic` covers reboot and logout but does **not** restart it
after a crash — the SCM leaves a crashed service stopped unless failure actions
are set explicitly. Prior in-house work installs the service correctly and never
sets them, so a crash at 2am is silent until somebody notices. Set them at
install time: restart on first, second and subsequent failures, with a reset
period measured in hours rather than minutes.

**A restart-storm guard must not be able to give up permanently.** systemd's
default is to stop trying after a burst, which is the wrong polarity here: a
daemon that has crash-looped five times still needs to be trying at 4am. Use a
long `StartLimitIntervalSec` with `Restart=always` and accept a slow loop, never
a terminal stop.

### A crash is itself an incident

On start, the daemon compares a clean-shutdown marker against what it finds. An
unclean previous exit raises an internal incident through the ordinary
escalation machinery.

This matters more than it sounds. Without it, a crash loop is *invisible* — the
service restarts, the web UI looks healthy, and the only evidence is a gap in
the event history that nobody reads. The deadman in §9 catches a source going
quiet; this catches the product itself going quiet, which is the failure an
operator has no other way to see.

### Exactly one instance, enforced

The classic way this breaks is a service **and** a logon task both running:
two processes ingesting the same events and sending duplicate alerts, on a
product whose credibility depends on not crying wolf. Prior work removes the
logon task when installing the service, which is right but relies on knowing
every way the app could have been started.

**A single-instance lock is held by whichever process owns the data directory**
— a lock file on Linux, a named mutex on Windows. A second instance refuses to
start and says which process holds it. The lock is on the *data directory*, not
the executable, so two installations with separate configs remain legal.

### Control surface

- **The web UI** shows service state and offers stop and restart. It cannot
  *start* the service, for the obvious reason that it is served by it.
- **CLI verbs** — `install`, `uninstall`, `start`, `stop`, `status` — always
  work, and self-elevate through UAC on Windows rather than failing with an
  access-denied message the operator has to interpret.
- **Double-clicking the executable** when it is not running as a service enters
  a control mode: it reports service state, offers to install and start it, and
  opens the browser on the UI. An operator who has never used a command line
  must be able to get from "downloaded a file" to "it is running and will keep
  running" without being told to open a terminal.

### The account: `User=notifymatrix`, decided

Least privilege, which is the idiomatic systemd answer and matches the
tighter-than-DPAPI posture already recorded in §6. It has one real consequence
and it is worth stating plainly rather than discovering later.

**The daemon can read a host-key credential but can never write one.** The host
key is root-only, so an unprivileged process cannot encrypt against it. This
splits credential handling into two paths that are complementary rather than
redundant:

| Path | Who writes it | Binding | Rotatable from the UI |
|---|---|---|---|
| `LoadCredentialEncrypted=` | an administrator, once, with privilege | `host+tpm2` — the strongest on the machine | **No** — rerun `systemd-creds encrypt` |
| Provider chain (§6) | the daemon, from the web UI | `tpm2`, else key file | Yes |

systemd decrypts the first as **root at unit start**, before dropping
privileges, and places the plaintext in a directory owned by the service user.
So a credential provisioned that way gets a binding the consuming process could
never have produced for itself.

**The provisioned path wins when both are present.** An administrator who went
to the trouble of seeding a credential has stated an intent, and silently
preferring one the UI happened to write would override it. Diagnostics must say
which path a secret came from, because "my change in the UI did nothing" is
otherwise baffling.

The cost is honest: on a machine with **no TPM**, an unprivileged daemon
storing a key from the web UI falls to the key-file tier, which is not
machine-bound. The alternatives were running as root, or refusing to accept
keys from the UI at all. Neither is better.

Windows has no equivalent problem: DPAPI **machine** scope (§6) was chosen
precisely so the `LocalSystem` service and the operator's browser session share
one config. That decision pays off here.

- **`CGO_ENABLED=0`, always.** Load-bearing three times over: it produces static
  Linux binaries that run anywhere including Alpine and Docker, it makes builds
  reproducible enough that a reader can verify a release matches its tag, and
  it disqualifies both `mattn/go-sqlite3` (§4) and libsecret bindings (§6).
  Those are consequences of the constraint, not coincidences — the constraint
  is chosen first and the dependency list obeys it.
- **Targets**: `windows/amd64`, `linux/amd64`, `linux/arm64`. arm64 is not
  optional; a large share of this audience runs on a Pi, a NAS, or a small
  UniFi-adjacent box.
- **Windows signing**: Azure Trusted Signing, as already configured
  (`eus.codesigning.azure.net`, `Xtremission-LLC`), moved from the current
  workstation `az login` flow to **federated credentials (OIDC)** from GitHub
  Actions so no long-lived secret sits in the repo.
- **Linux signing**: `cosign sign-blob` keyless via Actions OIDC, verifiable
  against the Rekor transparency log, plus a detached GPG `.asc` because distro
  packagers still expect one.
- **Both**: SLSA provenance via `actions/attest-build-provenance`, verifiable
  with `gh attestation verify`.
- **Licence**: PolyForm Noncommercial 1.0.0. Source-available, not OSI open
  source — GitHub will label the repository "Other", which is expected rather
  than a problem to work around. The README states the restriction plainly at
  the top: a licence people discover only after integrating is a licence that
  generates grievance instead of revenue.

---

## 11. Open items

Items 1–4 of the original list are **closed** by the September 2026 research —
see §6, §7, §8, §8a and [SOURCES.md](SOURCES.md). What remains:

1. **Bench-test Alarm Manager's delivery behaviour.** ~15 minutes: point an
   alarm at a local endpoint that returns 500, then 200-after-delay, then times
   out, and log what arrives. Ubiquiti publishes no delivery contract at all,
   so until this is measured the receiver treats it as at-most-once. Worth
   knowing whether that is pessimistic.
2. **Does a Device Issue or Storage Disk Alert payload identify the disk or
   device beyond `triggers[].key` and a MAC?** Every published sample is a
   camera detection. If the infrastructure alarms also reduce to
   `{key, MAC}`, disk failure arrives as an essentially anonymous ping and
   needs a follow-up probe to say what actually failed.
3. **Can Access's Alarm Manager send a webhook at all?** Ubiquiti's own
   action-availability table says Webhook is Network & Protect only; community
   reports describe an Access-side Delivery URL. A direct contradiction in the
   sources. Needs one look at a live console.
4. ~~Which account the Linux service runs as.~~ **Decided**: `User=notifymatrix`
   with `LoadCredentialEncrypted=` for administrator-provisioned secrets and
   the provider chain for UI-managed ones. See §9a.
5. **Is power loss a Protect trigger, or only a Network one?** Ubiquiti
   documents Power (PoE issues, power loss) under *Network* triggers. If it is
   Network-only, that is a second console app to configure and a second webhook
   shape to parse for what most operators would call one alarm.
6. **Rule configuration surface.** YAML is right for the repository and for
   version control; a non-expert installer needs a form. Probably: the web UI
   writes the YAML and the YAML stays the source of truth, on the principle
   that nothing the operator configures should be hidden in a file they cannot
   see.
7. **Multi-console.** Sites with more than one UniFi OS host. The console facts
   in `internal/unifi` are per-host and the pacer is per-client, so this is
   structural — better decided now than retrofitted, though not needed for the
   first release.
