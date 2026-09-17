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

`✓` exists and is tested; `~` was folded into something else; `·` is not written
yet — nothing carries it any more, now that the voice channel has landed.

```
✓ cmd/notifymatrix/     run, install/…/status, incidents, selfcheck
  internal/
  ✓ unifi/              shared per-console pacing, backoff, TLS + cert pinning
    source/
  ✓   protect/          Protect ingest: two WebSockets + reconciliation sweep
  ✓   access/           Access ingest: socket + system-log tail + door polling
  ✓   network/          Network ingest: device polling (the API has no events)
  ✓ inbound/            webhook receiver: the alarms no API exposes
  ✓ setup/              what is left to configure, rendered everywhere
  ✓ ingest/             runs the sources; the deadman that notices a dead one
  ✓ event/              Event, Entity, the shared condition vocabulary
  ✓ rule/               matching, severity mapping, event → incident
  ✓ incident/           lifecycle (state derived, not stored) + Store interface
  ✓ store/              SQLite implementation of incident.Store
  ✓ escalate/           policies, the scheduler, re-alert timing
    channel/
  ✓   (root)            Alert, Channel interface, per-channel bounded queue
  ✓   ntfy/  email/  pushover/  webhook/
  ✓   voice/            Twilio: speaks the alert and hangs up (§8). No ack path
  ✓ ack/                HMAC token mint + verify, ack routes
  ✓ secret/             Secret type, the four-tier prefix chain
  ✓ config/             YAML, source of truth; validation that refuses at startup
  ✓ service/            install/uninstall, recovery actions, single-instance (§9a)
  ~ selfcheck/          folded into the CLI and the UI's health view
  ✓ audit/              append-only record: every event, delivery, ack
  ✓ probe/              capability discovery, pseudonymised, local networks only
  ✓ web/                local UI: status public, changes gated
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
      - after: 0s
        channels: [ntfy, email]
      - after: 2m
        channels: [ntfy, email, pushover]
      - after: 10m                                     # operator-written
        channels: [ntfy, email, pushover, voice]
    repeat_every: 5m          # after the last stage, keep nagging
    give_up_after: never      # critical never gives up
    quiet_hours: ignore       # critical ignores quiet hours
  high:
    stages:
      - after: 0s
        channels: [ntfy]
      - after: 15m
        channels: [ntfy, email]
    repeat_every: 30m
    give_up_after: 4h
```

The `voice` rung above is an **example an operator would write, not a shipped
default**. The ladders in `escalate.DefaultPolicies` name no voice stage at any
severity: the channel is built and opt-in, because a default that places billed
phone calls at 3am is not one to choose on an operator's behalf. See §8.

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
| voice | **Nothing. A call cannot be acknowledged**, in what is built: it speaks and hangs up. DTMF "press 1" is designed (§8) and not written |

**Voice is the one channel that can only wake somebody, not hear from them.**
The call speaks and hangs up, so an incident that was announced by telephone is
still acknowledged from a link in another channel or from the interface, and the
ladder keeps calling until that happens. That is the price of building the
speak-and-hang-up half first, and it is recorded here rather than left to be
discovered from a ringing phone.

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
state. So the Access source has **three inputs, not one**, and that is forced
by the surface rather than chosen:

1. the notifications **socket**, for fast lock state,
2. the **system log**, which is the engine of record for denials,
3. a **door-position poll**, because held-open does not exist anywhere.

- **Poll floor is ~3 minutes**, set by measured log *indexing lag* (up to ~3.5
  min), not by the 220 ms pacer. Polling faster buys nothing and spends budget
  the Protect reconciliation sweeps need.
- **Overlap windows and dedupe on the row id.** `since`/`until` are seconds
  while `event.published` is milliseconds, and boundary semantics have never
  been measured. The row id can be trusted for correctness; the time boundary
  cannot. **The watermark advances only when every topic succeeded** — a
  partial window looks exactly like a complete one, and on a log with no cursor
  a row skipped is a row gone.
- **A connected-but-silent socket is reported as a fault.** On unfamiliar hub
  hardware the socket connects and then says nothing, which is silent total
  failure of the fast half of this source. Both known shapes came from one hub
  model on one day, so this is the likely failure, not a remote one.
- **Three rules are not offered, because the features do not exist**:
  anti-passback (an unshipped roadmap item since 2022), tamper (no confirmed
  representation on any surface), and battery-low (the Access line is entirely
  PoE). Offering a rule that can never fire is worse than omitting it.

#### The two alarms an access-control system owes you, and neither exists

**Door forced** and **door held** are the reason somebody buys door control,
and UniFi Access reports neither in a machine-readable way. Access computes
"Unauthorized Opening" internally and does not expose it; held-open is an open
feature request. So both are **derived here**, and the derivation is the
interesting part.

**Held open** is the easy one: a door position that has read open for longer
than a threshold.

**Forced** is not, because the obvious rule is wrong. "Locked and open" is the
state a forced entry ends in — and it is *also* the state an ordinary entry
ends in on any lock that relocks while the door is still swinging. A rule on
the current pair raises a critical alarm every time somebody walks through.

The transition is what separates them:

```
  normal entry:  unlock  ->  open  ->  relock   (open happened while unlocked)
  forced entry:  locked  ->  open             (open happened while locked)
```

So forced is decided at the moment the door *becomes* open, never afterwards.
Polling alone cannot see that ordering either — a lock that opens and relocks
between two reads looks like it was never unlocked — so the test is not "is it
locked now" but **"was it unlocked recently"**, with the socket supplying the
timestamps and a grace window (45s) as the bound. That is what the socket is
for, and it is why the socket being mute is a reported fault rather than a
tolerable degradation.

Two honest limits:

- **On a cold start the classification is skipped.** A door already open when
  the daemon first looks has no knowable ordering. It is still reported, as
  held-open, which is what it observably is rather than a guess about how it
  got that way.
- **`door_position_status` is `"none"` on most doors.** A measurement across 28
  doors on one console found 26 with no sensor fitted. `"none"` is not
  `"close"`, and treating it as shut would show 26 reassuring green rows for
  doors the product cannot see at all — so Health reports how many doors can
  actually be watched, and it is usually a small number.

### Network — no event surface in the API at all

The Local Integration API (`/proxy/network/integration/v1/`, Network 9.0+) is
broad — sites, devices, clients, firewall CRUD — and contains **zero**
occurrences of "event", "alarm", "webhook" or "subscribe". It will tell you
what every device *is*; it will never tell you that something *happened*.

So the Network source is two halves that do not resemble each other:

- **Polling**, for device reachability. With no events, the only way to tell a
  device that WENT down from one that is merely still down is to have looked
  before — so the source remembers, and a device must read down for three
  minutes before it is an incident, because a poll landing during a reboot must
  not page anybody.
- **An inbound webhook** for everything else. WAN outages, threats, PoE faults
  and client events exist only in Network's own Alarm Manager (9.3+).

It is also the only source with **no prior in-house client to copy shapes
from**. Every field name and every state value comes from documentation rather
than from a console anybody here has queried, which changes two things: the
decoding is tolerant of both the documented envelope and a bare array, and the
state vocabulary is treated as **unestablished**.

That last one is an uncomfortable trade, taken deliberately. A state absent
from the recognised lists is never alarmed on — so a future firmware value
meaning "down" would pass unreported. The alternative, treating every
unrecognised state as an outage, pages the operator every time Ubiquiti adds a
value, and an alarm product that cries wolf gets switched off, which costs
more. So the unknown is made **visible** instead: counted by name in Health and
surfaced by `notifymatrix probe`, which is how the list gets corrected.

### The alarms that no API exposes, and designing for that

Some alarm classes exist **only** as Alarm Manager rules: Network's WAN,
threat and PoE triggers, and Protect's NVR disk failure, storage and power
loss, which are absent from the public API entirely.

**Alarm Manager rules are created in the UniFi UI and in no API.** This product
cannot provision its own push path. A person has to make the rule by hand.

Three consequences, and they shape `internal/inbound` completely:

- **The URL is the discriminator, not the payload.** The payload is
  undocumented and has spelled its message field `message`, `msg`, `text` and
  `description` across firmware, with no controller timestamp at all. So each
  Alarm Manager rule points at its OWN hook URL, and the meaning is attached to
  the token rather than parsed out of the body — because the operator chooses
  the URL when they create the rule, which makes it the one fact about an
  inbound alarm that is knowable.
- **GET is accepted, unlike the acknowledgement endpoint.** There, GET must not
  act, because a mail scanner prefetching a link in an alert would acknowledge
  an alarm nobody saw. Here, Alarm Manager offers GET or POST and nothing
  prefetches a hook URL — it is never sent to anybody. What is true of both is
  that the URL is a credential.
- **Receipt is tracked, because configuration is not evidence.** Nothing can
  verify a rule exists except an alarm arriving through it, so the receiver
  counts arrivals per hook and every setup surface reports a hook that has
  never fired as **unverified** rather than done.

### Running them: the supervisor, and the deadman

A source that is constructed does nothing. That is not a truism here — it was
the actual state of this daemon for several milestones: the Protect source was
complete, tested and never instantiated, so `notifymatrix run` started, served
the interface, ran the escalation scheduler and **ingested nothing at all**,
while every health surface it had reported green.

`internal/ingest` runs them, and it has a second job that is easy to leave out:

**A source that dies quietly is indistinguishable from a quiet site**, and on
an alarm product those are opposite situations. One means nothing is happening;
the other means nothing would be reported if it did. So every source declares
a liveness window, and silence past it becomes an incident that escalates like
any other — raised through the internal path, so an operator ignore rule aimed
at a noisy camera cannot silence the product reporting that it has stopped
working. It resolves when the source speaks again: a deadman that raises and
never clears teaches people to ignore the one message that means the product
itself is broken.

Three rules about failure, all of them the same rule:

- **A source that cannot run stops, and says so.** Sources return an error only
  for something reconnecting cannot fix. Looping on that would spin against a
  configuration that cannot work — but a stopped source is invisible, so it
  raises an incident first.
- **One broken source does not stop the others.** A site whose Access key is
  wrong still wants its cameras watched. Refusing to start anything removes
  working coverage to punish a typo.
- **Nothing configured is said out loud.** A daemon with no sources will never
  raise anything from a console, which is the single most important thing its
  operator could be told.

The same reasoning changed what the configuration *refuses*. Everything
`Validate` reports prevents startup, and two things had ended up there that
should not have: a console with `insecure_skip_verify` and no pin yet — which
is an ordinary UniFi console on day one — and a console listing the
unimplemented `network` source. Both are now **warnings**: said at startup and
shown in the interface, but not a reason to leave a site unmonitored. An
unpinned daemon that is watching beats a pinned one that is not running, and an
operator locked out at setup never reaches the step that fixes it.

### Telling somebody what is left to do

Every surface in this product reported what was WRONG. None of them reported
what had never been DONE — and those are different questions. A configuration
that validates, a service that is running and a status page that is entirely
green can all coexist with a product that will never raise an alarm, because
nobody added a console, or enabled a channel, or made the Alarm Manager rule
that is the only way some events exist at all.

`internal/setup` is one assessment rendered in several places — the terminal
(`notifymatrix setup`), the first-run screen, and a tab in the interface — so
they cannot drift apart and disagree about what is left.

Four things make it useful rather than decorative:

- **Every step says what goes wrong if it is skipped.** "Do this" without "or
  else" is an instruction people postpone.
- **Every step says what is true NOW**, read from the real configuration and,
  where it matters, from the running process. Whether a webhook has ever fired
  is not knowable from a file.
- **Ready is not the same as complete.** A console, a source and a channel is a
  working product; the rest makes it better. Telling somebody they are not
  ready when they are is how a checklist gets ignored.
- **The configuration file carries its own instructions**, rewritten on every
  save — including the saves the interface makes, so the guidance is not
  removed from the person who has just proved they edit this file.

One security note that a test found rather than review: a hook URL carries its
token, and the checklist is public so a wall display can show that nothing is
set up. Gating the URL field is not enough if the instruction prose next to it
also contains the URL. It lives on exactly one field now, and a test asserts it
appears nowhere else.

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
| Pushover | severity→priority map; **priority 2 is never emitted** — see below |
| JSON webhook | a **versioned envelope**, pinned by a golden test; HMAC signing bound to a timestamp |
| Email | **plain text is always the base part**, HTML added as an alternative — a security alert must survive HTML-stripping gateways; inline CID logo |
| Voice | **speak-and-hang-up only** — one REST POST to Twilio's Calls resource carrying **inline TwiML**; script capped because TTS is billed per 100 characters; on no default ladder; **no acknowledgement path at all** — see below |

Email is the one real build cost: Go's stdlib `net/smtp` is frozen and
minimal. `github.com/wneessen/go-mail` (cgo-free) handles implicit TLS on 465
and multipart/alternative with inline CID parts.

### Pushover: the emergency priority is refused, on purpose — *built*

Pushover's priority 2 is exactly the feature this product provides: the service
itself re-alerts on its own timer until somebody acknowledges. Using it would
be the obvious move and it is the wrong one.

**It is a second escalation ladder with a second acknowledgement that this
product cannot see.** Acknowledging in Pushover would silence the phone while
the incident kept escalating on every other channel; acknowledging the incident
would not stop Pushover. Two acknowledgement systems that do not know about
each other is strictly worse than one, and the interface contract already says
so in general terms: a channel must not retry beyond its own bounded policy,
because the ladder above it provides persistence.

So critical and high map to priority 1, medium to 0, low and info to -1, and a
test asserts no request can carry priority 2 for any severity.

### The generic webhook: the payload is a published contract — *built*

The moment somebody writes an automation against it, changing the shape breaks
them silently. So it carries a `version` field and is pinned by a **golden
test** whose comment says that failing it is a decision to make deliberately
rather than a test to update.

Signing binds a timestamp INTO the signed material — `timestamp + "." + body`,
returned as `X-NotifyMatrix-Signature: sha256=<hex>` alongside
`X-NotifyMatrix-Timestamp`. A signature over the body alone is replayable
forever, because a captured pair stays valid; binding the timestamp is what
makes a replay detectable by a receiver that checks it.

Three refusals fall out of that:

- **Redirects are not followed.** A redirect would resend the signed body, with
  its valid signature, to a host the operator never configured.
- **Static headers cannot override the signature, timestamp or content type.**
  An operator who set the signature header by hand would break every receiver's
  verification, in the direction where the receiver rejects real alarms.
  Refused at construction and again in configuration validation.
- **The snapshot is not included.** Base64 in every request would multiply the
  size of an ordinary alert for a field most receivers ignore.

The URL itself is treated as a credential, because for most receivers it is
one — Home Assistant, Slack and n8n all put an unguessable token in the path or
query — so it never appears whole in an error string.

### Voice — half built: it speaks, and it cannot be answered

The design below was two separable capabilities. **The first is built and the
second is not**, and the gap between them is the difference between waking
somebody and hearing from them:

| | State |
|---|---|
| **Speak-and-hang-up** — REST POST to Twilio's Calls resource, the alert spoken by `<Say>`, call ends | **Built.** `internal/channel/voice`, channel name `voice` |
| **Press-1-to-acknowledge** — Studio Flow triggered by REST, daemon polls the Execution Context for the digit | **Designed only.** Not written, and not started |

So voice today is a way of making a phone ring with a sentence attached. It is
**not** an acknowledgement route (§5), and the ladder above it keeps escalating
until a human acknowledges somewhere else.

**The inbound-exposure reasoning stands, and is why the second half can still be
built this way.** The obvious assumption is that "press 1 to acknowledge" needs
a public callback URL, because DTMF normally arrives on a real-time inbound
webhook during the call. **That assumption is wrong for every provider
surveyed.** All of them expose a poll-by-call-id path that returns the collected
digits after the fact: Twilio via the Studio Execution Context, Amazon Connect
via `GetContactAttributes`, and Bland, Vapi and Retell via a plain
`GET /calls/{id}`. An early finding claimed these were webhook-only; the
adversarial pass established that was a search failure rather than a real gap.
The built half needs even less than that: it is one outbound request and it
reads nothing back, so there is no inbound path in this product at all.

**What the built half does differently from the plan above:** the TwiML is sent
**inline** on the create-call request rather than hosted as a TwiML Bin. The
script carries this incident's severity, entity and time, so a Bin would have to
be either rewritten before every call or reduced to a message that says nothing
specific — and a console-hosted Bin is configuration no code diff would ever
show, which is the same objection recorded against Studio below.

**Three things the built half cannot do, said plainly because each one is a way
an operator could believe an alarm was delivered when it was not:**

- **Twilio's `201` means *queued*, not *answered*.** It proves the request was
  accepted: not that the phone rang, not that a human picked up, not that it
  did not go to voicemail. Call status is knowable only from a StatusCallback
  webhook or by re-fetching the call resource, and neither is built. The channel
  therefore reports **dispatch**, and the ladder is what keeps the promise.
- **A trial Twilio account defeats it entirely.** Twilio plays its own message
  before the TwiML runs and asks the callee to press a key to proceed, so an
  unattended phone hears nothing while the API returns a clean `201`. The
  credential check refuses a trial account outright rather than calling it
  configured.
- **A fan-out that partly fails reports success.** One accepted call means
  somebody was told, so the delivery is not an error — and the other numbers'
  failures go no further, because the `Channel` interface has nowhere to put a
  warning on a send that succeeded. A number that has been dead for months looks
  exactly like one that answers, and the credential check cannot find it either:
  it deliberately places no call. Only a real alert, or somebody dialling the
  number themselves, shows that. A per-channel warning path is the fix and it
  does not exist yet.

**The test button does not place a call**, and that is a deliberate divergence
from the `Channel` interface's "sends a harmless message": a call costs money and
rings a human, and a self-test that does that is one an operator switches off —
which costs the whole proof rather than part of it. It does an unbilled
authenticated `GET` of the account resource instead, which proves the credential
pair and the account's state (active, and not trial) and proves nothing about
whether the caller ID can reach the recipients. Because that is a different
promise from every other channel's test, the interface prints its own wording
rather than the generic "Sent."

**Keep the escalation script terse.** Twilio bills TTS **per 100 characters**,
not per request — Basic free, Premium Standard $0.0008, Neural $0.0032,
Generative $0.0130 per 100 chars. Cost scales with prompt *length* independently
of call duration, so a verbose alert script is charged for being verbose, on
every recipient of every repeat. The built channel caps the spoken script and
defaults to a Basic voice, where the per-character cost is zero and only the
minutes are billed. (For comparison, Amazon Connect lands near $0.043/min
all-in plus a mandatory DID — roughly 9× the naive quote, and the heaviest
integration of the seven.)

**Retries are shorter here than in any other channel, on purpose.** Posting to
`/Calls` is billed and side-effecting: a retry whose response was lost rings
somebody a second time. Twilio documents that a `429` was *not processed* and is
safe to retry; it documents nothing of the kind about a `500`, so that case gets
exactly one. Everything else — an unverified caller ID, an unverified trial
destination, a country the account may not call, a bad token — is a
configuration fact that will fail identically forever and is not retried at all.

**The strongest argument against the Studio-polling design**, recorded because
it may well win when the second half is built: the daemon needs an inbound HTTP
receiver anyway (§9), so standing up one tunnel and using each provider's native
webhook `Gather` would be more uniform — and would keep the top rung's behaviour
inside versioned code rather than in Twilio-console configuration that no code
diff will ever show. The polling design was chosen because it makes voice work
with **nothing exposed at all**; that remains an open choice, and the inline-TwiML
decision above is a point in the counter-argument's favour.

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
| Voice provider → us | **None.** What is built never hears back at all: one outbound POST, nothing read afterwards. The unbuilt press-1 half would poll rather than be called back (§8), so it needs nothing inbound either | n/a |
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

### Scoping a port forward — *built*

The tunnel answer above is right and people will still forward a port, because
their router has a form for it and a tunnel is another thing to run. So the
product has to make the version they will actually do survivable.

**A NAT forward cannot restrict by path.** Forwarding the interface's port
publishes everything on it — including the status page, which §8b makes
readable without a password so a wall display works. That trade was taken on
the reasoning that anyone on that LAN can query the console directly anyway.
**It does not survive contact with the open internet**, and nothing in the
configuration made the difference visible.

So `web.ack_listen` starts a **second listener carrying only `/ack/`**.
Everything else on that port is a 404 — the status page, the settings API, and
the webhook receiver, which has its own token and its own reasons to stay put.
A forward now has something safe to aim at.

Set it to `auto` and the port is **chosen at random from the IANA dynamic range
(49152–65535) on first start and written back to the configuration**, where it
stays. Three details decide whether that is useful or harmful:

- **It is bound before it is written down.** The listener that proved the port
  is the one the daemon keeps. Closing it to re-open later leaves a window for
  something else to take the port — and a pinned port this daemon cannot bind
  is worse than no pin at all, because the firewall rule and every
  acknowledgement link already sent point at it permanently.
- **It never changes again.** A port that moved on each start would break the
  forward and every link already delivered.
- **It is not a security control, and the code says so.** A port scan finds an
  open port whatever its number. What a random port buys is that the forwarded
  port is not one of the handful scanners probe constantly, and that it will
  not collide with something else. The HMAC token is what protects an
  acknowledgement. `crypto/rand` rather than the clock, because a port derived
  from install time is guessable, which would undo even that much.

Three configurations are then **warned about at every start**, not refused:

| | |
|---|---|
| Public ack URL, no `ack_listen`, main listener on `0.0.0.0` | a forward would publish the status page and the sign-in |
| Public ack URL over plain `http` | the ack token is in the URL and readable in transit |
| `ack_listen` on loopback, or equal to `listen` | it scopes nothing, or cannot receive a forward at all |

The first is deliberately conditioned on the main listener being bound to every
interface. Somebody running a reverse proxy has it on loopback, is already
scoping by path, and must not be nagged about a risk they have dealt with.

RFC 6598 space is treated as private throughout, because it is what Tailscale
hands out — and a Tailscale address is the *good* answer here. Warning about it
would push people off the safest option toward the one with a firewall rule.

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

## 8b. The operator interface: status open, changes gated

**Status is readable without signing in. Every change needs the password.**

The reason is a wall display. An operator wants the incident board on a screen
in an office or a comms room, and a screen that has to be signed into is a
screen that shows a login prompt at 3am. So the incident list, the health view
and the "why is nothing happening" surface are public on the LAN.

The trade is stated rather than hidden: **that board is reconnaissance for
anyone already on the LAN.** It names cameras that are offline and doors that
are open. That is accepted because it is the same LAN the consoles are on — an
attacker there can query the console directly — and because the alternative
makes the wall display useless.

What is never public, to anyone, signed in or not:

- **Secret values.** Not redacted on the way out — never placed in the
  structure that is serialised. The settings view has no field capable of
  holding one; it reports `api_key_set: true` and nothing more.
- **The audit record**, which names what was silenced and by which rule.
- **Anything that writes.**

Authentication is PBKDF2-HMAC-SHA256 with a per-password salt and a
self-describing stored hash, so the iteration count can rise later without
invalidating what is stored. **There is no "no password set means everyone is
authenticated" path**: the first password is set with a one-time token the
daemon prints at startup, and the token is spent exactly once — but handed back
if the password cannot be stored, so a disk error does not lock an operator out
of their own fresh install. Sessions live in memory and die with the process,
which on a restart is correct rather than inconvenient.

Failed sign-ins are throttled per client, and `X-Forwarded-For` is deliberately
ignored: honouring it on a LAN listener would let one device rotate the
throttle key on every attempt.

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
  a control mode: it reports service state, *offers* to install and start it —
  as a question answered where they are, not a command printed for them to
  retype — and prints the address of the UI once it is running. An operator who
  has never used a command line must be able to get from "downloaded a file" to
  "it is running and will keep running" without being told to open a terminal.
  Opening the browser for them is not done yet; the address is printed instead.

  Two details make this work rather than merely intend to.

  **The window is held open.** Explorer destroys the console the instant a
  console program exits, so the first version of this printed its whole
  control mode into a window that vanished — reported as *"it just opens and
  closes silently"*, which for a downloaded security tool reads as broken or
  as evasive. `GetConsoleProcessList` returning 1 means this process owns the
  console alone, which is what a double-click looks like; started from a shell
  the console is shared, there are two or more processes in the list, and
  nothing pauses.

  **The offer is gated on somebody being there.** It is asked only when the
  console is owned alone *and* stdin is a real console, and a closed or
  redirected stdin answers no. The branch installs a Windows service and
  raises a UAC prompt, so the failure to avoid is an unattended run consenting
  to a system change because there was nobody present to decline it.

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
- **Windows signing**: Azure Artifact Signing (formerly Trusted Signing), moved
  off the workstation `az login` flow to **federated credentials (OIDC)**, so no
  long-lived Azure secret sits in the repository. The federated subject is
  pinned to a GitHub **environment** rather than a tag, because Entra ID does
  not accept wildcards in the subject and a tag-based subject would need a new
  credential per release — and the environment doubles as an approval gate in
  front of the signing key.
- **Linux signing**: `cosign sign-blob` keyless via Actions OIDC, verifiable
  against the Rekor transparency log. A verifier can check *which workflow in
  which repository* produced a binary, which a bare detached signature cannot
  tell them. Detached GPG is **optional** and second choice: it needs a
  long-lived private key in secrets, and exists only because distro packagers
  expect an `.asc`.
- **Both**: SLSA provenance via `actions/attest-build-provenance`, verifiable
  with `gh attestation verify`.
- **Reproducible**: `-trimpath -ldflags "-s -w -buildid="` with the toolchain
  pinned in `.go-version`. Verified: the same tag built from two different
  working directories produces identical bytes, and differs without
  `-trimpath`. Published source that cannot be checked against the published
  binary loses most of the value of publishing it.
- **The release is a draft.** Somebody looks at it before it is public.

Implemented in `.github/workflows/`; the operator-facing half — how to verify a
download, and the one-time Azure setup — is [RELEASING.md](RELEASING.md).
- **Licence**: PolyForm Noncommercial 1.0.0. Source-available, not OSI open
  source — GitHub will label the repository "Other", which is expected rather
  than a problem to work around. The README states the restriction plainly at
  the top: a licence people discover only after integrating is a licence that
  generates grievance instead of revenue.

---

## 10a. Capability probe and community submissions — *built*

The problem this solves is already recorded in [SOURCES.md](SOURCES.md) and it
is not going away: **the surfaces this product reads are version-gated and
under-observed.** Protect's event vocabulary went from 16 types at spec v6.2.83
to 39 at v7.3.53. Only **two** Access notification message shapes have ever
been captured, both from one hub model on one day. Network's Alarm Manager
payload is undocumented and its message field has been spelled four different
ways across firmware.

No amount of reading documentation fixes that. The only thing that does is
observing real consoles, which means the operators who run them.

**The shape:** `notifymatrix probe` enumerates what a console actually exposes
— which endpoints answer, which event types arrive on each socket, which
fields are present — and writes a JSONL capability report. Diffed against what
this build knows, it produces two useful things locally (what this console has
that we do not handle, and what we expect that this console does not) and one
useful thing collectively: a file the operator may choose to contribute with
`notifymatrix probe submit`.

The two local findings are marked in the summary as `NEW` (a path this build
does not use, answering) and `GONE` (a path this build depends on, absent).
They mean opposite things and neither is an error.

### There is prior art, and it is most of the way there

Earlier in-house work already built a field probe of exactly this shape, and
its instincts are right: read-only by default, the one state-changing call
gated behind an explicit opt-in flag, a hard refusal to ever call the
irreversible endpoint, credentials taken from the environment or prompted
without echo and never written to the report, and credential-bearing stream
URLs redacted out of the output. Start from that, not from scratch.

A second, earlier probe targeted **Access specifically**, and it carries the
one design insight that decides whether a capability probe works at all:

> **Per-event-type buckets.** The notifications stream is dominated by repeated
> state-sync messages, so a flat capture of the first N messages is filled
> entirely by those and crowds out the rare message class you are probing for.
> Counting every message but storing only the first samples of EACH type makes
> a one-in-a-thousand event type impossible to miss.

That is not a refinement, it is the difference between a probe that discovers
something and one that confirms what you already knew. It also pairs with an
operator-in-the-loop window — the probe tells the operator to trigger the
action they want captured *now*, during the listen — because some event classes
only exist when somebody does something.

It is also read-only, never raises, bounds both its listen time and its message
count, applies the same certificate-pin check as the main client ("no reason to
talk to an impostor either"), and tells the operator to review the bundle
before sharing it.

> **This reframes a finding in SOURCES.md.** That document records that only
> **two** Access notification message shapes have ever been captured, and reads
> it as a limit of the hardware. The probe's own notes say an earlier capture
> hit a flat 50-message cap on state-sync spam — which is exactly the failure
> the bucketed version was built to fix. So "two shapes" may be partly an
> artifact of how the capture was taken, not a fact about the console. That
> makes running a bucketed probe against a real Access hub more valuable than
> it looked, not less.

**What neither probe does is the part this needs.** Its reports redact
*credentials* but keep *identity* — real camera names and device ids sit in
the field-data files. For a local diagnostic pasted into a support thread with
a known party, that is a reasonable line. For a submission published to a
public repository it is not, because a camera name is a room name and a door
name is a door name.

So the probe is inherited; the **pseudonymisation layer is new**, and it was
the only genuinely new engineering here. It is described below.

One more thing the inherited designs did not have to worry about: bucketing on
a single field is enough for Access, whose type lives in a top-level `event`,
but not for Protect, which carries a frame verb (`add`, `update`) at the top
level and the actual event type underneath at `item.type`. Bucketing on the top
level alone collapses every event into two buckets and reproduces exactly the
crowding-out that bucketing exists to prevent. The key is therefore a composite
of whichever discriminator paths are present, which covers both products
without either one's parser.

### Local networks only, enforced in the dialer

**A probe is a scanner.** Pointed at an address the operator does not own it is
an unauthorised port and endpoint scan against somebody else's infrastructure,
run from their machine and their IP. Shipping that is shipping a liability with
a friendly CLI.

So the probe may reach RFC 1918 space, loopback, link-local, IPv6 ULA, and
RFC 6598 (included because it is Tailscale's range, and Tailscale is a common
and legitimate way to reach a console remotely). Nothing else.

**Enforced in the dialer's `Control` hook, not in a pre-flight check.** That
distinction is the whole design: `Control` runs after DNS resolution and before
connect, with the ACTUAL socket address, so it catches what a check on the
hostname cannot —

- a name that resolved to a private address when checked and a public one when
  dialled (DNS rebinding),
- a redirect to a public host,
- a second address on a multi-homed name.

A pre-flight `CheckHost` exists as well, but only to give a clear error at the
CLI. It is not the protection.

Also: **no proxy is consulted** (a proxy makes the connection go to the proxy —
possibly local — while the request reaches anything beyond it), and redirects
are refused outright rather than followed and re-checked.

**There is no override flag, deliberately.** An escape hatch named something
like `--allow-remote` is a flag that ends up in a forum post, and the
protection is then one copied command line away from being off. A test asserts
the range list can never contain a default route, so widening this is a
deliberate act with a test to delete.

`internal/probe` implements this, on both the HTTP client and the WebSocket
dialer. The socket half needed saying separately: gorilla's dialer carries its
own default `net.Dial`, so a deleted `NetDialContext` still compiles and still
connects — it just silently stops being restricted. A test dials a public
address through the capture dialer and requires `ErrNotLocal`.

### The constraint that decides the design

**A raw probe of a UniFi console is a map of somebody's building.** Camera
names are room names. Door names are door names. MACs, site topology, user
counts, and — on the wrong endpoint — credential-bearing URLs. A submission
pipeline that published that would be a serious breach dressed as a community
feature, and it would be entirely our fault.

So the pipeline is **capture → redact → SHOW THE OPERATOR → submit**, and
never fewer steps than that:

- **Redaction is not optional and not a flag.** It happens at capture time,
  before anything is retained — there is no code path in `internal/probe` that
  stores a raw frame and redacts later, because a report written from a crash
  dump or a future refactor would then carry real data.
- **The operator reads the exact bytes before anything leaves.**
  `notifymatrix probe submit` prints the whole file and then explains how to
  contribute it. It is a separate command precisely so the printing cannot be
  skipped.
- **Submission is never automatic and there is no phone-home.** The submit
  command uploads nothing; it prints an issue URL.
- **Firmware version and model are the payload.** A report that cannot say
  which console produced a shape is not worth having, so those are kept — and
  they are also the only identifying facts that genuinely need to be.

### How the redaction actually works

Three decisions carry it, and each is a deliberate rejection of the obvious
alternative.

**1. It is an allowlist, not a denylist.** Every string is replaced unless
something specific says to keep it. A denylist — "redact fields called `name`,
`mac`, `email`" — fails on the field nobody anticipated, and *finding fields
nobody anticipated is the entire purpose of a probe*. The failure mode of an
allowlist is a less informative report; the failure mode of a denylist is a
published address book.

What survives is **field names** (they are the schema), **structure** (nesting
and array lengths), **types**, **booleans**, **small non-negative integers**,
and the values of a short list of **vocabulary fields** — `type`, `modelKey`,
`state`, `alarmType`, `version` and a handful more. Those name no person, room
or device; they are chosen by Ubiquiti.

Three fields were considered for that list and deliberately left off. `code`
can be a door PIN. `reason` and `result` carry prose far more often than they
carry an enum. A field whose values are *usually* safe is not a field whose
values may be published.

Even an allowlisted field is checked: a value that is MAC-, UUID-, IP-, email-
or token-shaped is replaced regardless of what it arrived in, and so is
anything longer than 64 characters or wordier than four words. A field name is
evidence about a value, never proof — and length alone does not separate
`UVC G6 PTZ` from `Front Door forced open by Jane`.

**2. Pseudonyms are counters, not hashes.** A hash of a MAC is not an
anonymisation: the MAC space is small and camera names come from a small
dictionary, so a hash of either is recoverable by brute force in seconds. A
counter discloses nothing, because there is nothing to grind against.

**3. They do not survive the report.** Counters restart for every run, so two
submissions from one site share no label and cannot be linked to each other.
Within a report the mapping is stable, which preserves the genuinely useful
fact that two fields held the same value.

Numbers get the same treatment as strings: small integers are enum ordinals,
ports and counts and are kept; epoch-shaped integers are replaced with
`<epoch_ms>` or `<epoch_s>`, because *when* something happened at a site is
exactly what a published file must not carry; and non-integers become
`<float>`, because a latitude is an address.

The thing that is easy to miss, and was missed until the probe was run against
a dead port: **the redaction has to cover what this process says about the
console, not only what the console says.** A refused connection produces
`dial tcp 192.168.1.1:443: ...`, and that was being written into the report as
the stream status. Error strings are scrubbed of addresses now, with a test.

### The report is a schema summary, not a pile of samples

Each endpoint and each message type carries a **field summary**: for every
dotted path, the types seen, how many times it appeared, how many *distinct*
values it held, and the values that were publishable. That, not the three
retained samples, is the payload.

It also degrades well. A field whose values were all replaced still reports
that it exists, what type it is, and that it held (say) four distinct values —
which reads as "probably an enum worth asking about" while disclosing none of
the four. Cardinality is safe to publish; the values are not.

A field that is a string on one firmware and an array on another shows up as a
path with two types. That is the exact trap that silently drops every bulk
`devices` envelope, so it is worth surfacing on its own.

### What it refuses

- **Anything that is not a GET.** Checked in the request path, not merely
  implied by the catalogue, because the table that only contains safe entries
  is one hurried edit from not.
- **`disable-mic-permanently`**, which needs a factory reset to undo. The
  inherited probe refused this in prose and by not writing the call; here it is
  a rule the code checks.
- **Rosters and credentials** — `/users`, `/credentials`, `/visitors`,
  `/nfc_cards`, `/pin_codes`, `/clients`. Pseudonymisation would reduce them to
  a row count, so fetching them buys the schema nothing, and pulling a
  credential table into a process that writes files is a bad shape even when
  the writing is safe.
- **Redirects**, and **proxies** are never consulted.

The catalogue deliberately includes paths this build does *not* use. A probe
that only asks about what is already handled can only confirm what is already
known, and the whole reason this exists is that Protect's vocabulary grew from
16 types to 39 without anybody here noticing.

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
