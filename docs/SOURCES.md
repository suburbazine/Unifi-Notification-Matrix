# The three source surfaces

What each UniFi application will actually tell us, how, and where it lies.

Researched September 2026. Every claim here survived an adversarial
re-verification pass; where the first-round finding was wrong, the correction
is what is recorded and the original is noted so it is not re-derived.

**Version-gate everything.** Both Protect's event vocabulary and Network's
Alarm Manager are version-dependent. Read `GET /v1/meta/info` and branch on
`applicationVersion` rather than assuming a spec.

---

## 1. UniFi Protect

### There IS an official push surface

Protect is widely assumed to offer third parties no event stream, which is why
most integrations reach for the unofficial socket. That assumption is out of
date. The official Integration API has carried two documented WebSocket
channels since at least the v6.2.83 spec:

| Channel | URL |
|---|---|
| Events | `wss://{host}/proxy/protect/integration/v1/subscribe/events` |
| Device changes | `wss://{host}/proxy/protect/integration/v1/subscribe/devices` |

Both authenticate with the **same `X-API-Key` header** as REST. No local admin
account, no session cookie, no private endpoint. This is the primary ingest
path.

The spec declares no `securitySchemes` at all, so the header name is
established by working code rather than by documentation — `uiprotect`'s
`_auth_public_api_websocket()` returns exactly `{"X-API-KEY": key}`. Note the
casing difference from Protect's REST surface, which is conventionally written
`X-API-Key`; header names are case-insensitive, so either works.

### Message envelope

Flat JSON text frames, discriminated on `type`:

```json
{"type": "add"    , "item": { ...event... }}
{"type": "update" , "item": { ...event... }}
```

Every event carries `id`, `modelKey` (`"event"`), `type`, `start` (Unix **ms**),
`device` (a Protect **device id**, not a MAC), and optionally `end`,
`smartDetectTypes[]`, `metadata`. `update` frames typically carry only `end`.

**Metadata scalars are wrapped**, which is the shape most likely to be got
wrong on first pass:

```json
"metadata": {
  "sensorType":              {"text":   "smoke"},
  "sensorBatteryPercentage": {"number": 14}
}
```

`{"text": v}` for every enum/string (`sensorType`, `sensorValue`, `status`,
`sensorMountType`, `alarmType`, `button`, `inputState`, `inputChannel`, `pin`,
`deviceId`, `deviceName`); `{"number": v}` for numerics.

### The event vocabulary is version-gated, and the jump is large

**v7.3.53 carries 39 event types. v6.2.83 carried 16.** Everything in the
alarm-hub family, NFC, fingerprint, vape, the smoke-fault family, and
relay/digital-input arrived after 6.2.83.

The 39: `ring`, `motion`, `smartDetectZone`, `smartDetectLine`,
`smartDetectLoiterZone`, `smartAudioDetect`, `lightMotion`, `sensorMotion`,
`sensorOpened`, `sensorClosed`, `sensorButtonPressed`, `sensorWaterLeak`,
`sensorTamper`, `sensorBatteryLow`, `sensorAlarm`, `sensorVape`,
`sensorExtremeValues`, `sensorSmokeTest`, `sensorSmokeBatteryLow`,
`sensorSmokeNeedsCleaning`, `sensorSmokeFault`, `sensorCoFault`,
`sensorSmokeEndOfLife`, `relayInputChanged`, `cameraDigitalInputChanged`,
`alarmHubMotion`, `alarmHubEntryOpened`, `alarmHubEntryClosed`,
`alarmHubSmoke`, `alarmHubGlassBreak`, `alarmHubButtonPress`,
`alarmHubTamper`, `alarmHubDeviceTamper`, `alarmHubRelaySwitched`,
`alarmHubBatteryLow`, `alarmHubBatteryConnected`, `nfcCardScanned`,
`fingerprintIdentified`.

`smartDetectTypes`: person, vehicle, package, licensePlate, face, animal.
`sensorAlarm.metadata.alarmType.text`: smoke, CO, glassBreak.

### Four traps

**1. Camera disconnect is not an event.** There is no `disconnect`,
`cameraDisconnected` or `offline` in the discriminator. Offline detection is a
**field flip on the devices channel**: `{type:"update", item:{modelKey:"camera",
id, state:"DISCONNECTED"}}`, where `state` is the enum `CONNECTED | CONNECTING
| DISCONNECTED`. A product that watches only `subscribe/events` never learns a
camera went dark.

**2. The devices channel emits bulk envelopes where `id` is an ARRAY.**
`devicesAdd` / `devicesBulkUpdate` / `devicesBulkRemove` carry one payload
covering many devices. `uiprotect` expands these to one frame per device.

> **A parser that reads `item.id` as a string silently drops every bulk
> update.** Silently — no error, no unrecognised-message counter. This is the
> single highest-risk decode bug in the Protect path and it must have a test.

**3. There is no resume cursor.** Neither socket accepts a `lastUpdateId`. A
reconnect loses everything that happened while disconnected, with no way to
detect that it did. For a product whose entire purpose is re-alerting until
acknowledged, a silently-missed event during a console reboot is the failure
that ends the product.

> **Every reconnect must trigger a paced REST reconciliation sweep**
> (`GET /v1/cameras`, `/v1/sensors`, `/v1/nvrs`) and re-derive open-alarm state
> from it, rather than trusting the stream to have been continuous.

**4. NVR storage, disk failure and power loss are absent from the public API
entirely.** `GET /v1/nvrs` returns exactly: `id`, `modelKey`, `name`, `type`,
`guid`, `mac`, `doorbellSettings`, `armMode`. No disk array, no utilisation, no
health, no power. Home Assistant lists Disk Health and Storage sensors as
full-access-only, i.e. private API. **These must come from Alarm Manager.**

### Alarm Manager — the outbound webhook

Needed for exactly the classes the API cannot carry: **Device Issue** and
**Storage Disk Alerts**. Trigger categories are AI/Object Detection, ID
Recognition, Activity, System, Sensors — documented as "Categories include",
so treat it as the naming authority, not a complete enumeration.

Protect's payload **is** documented and **does** carry a timestamp (Network's
does not — §3):

```json
{"alarm": {"name": "...",
           "sources":    [{"device": "<MAC>", "type": "include"}],
           "conditions": [{"condition": {"type": "is", "source": "person"}}],
           "triggers":   [{"key": "person", "device": "<MAC>",
                           "eventId": "...", "timestamp": 1760282368873}],
           "eventPath": "/protect/events/event/<id>",
           "eventLocalLink": "https://<host>/protect/events/event/<id>"}}
```

`device` is a **bare MAC**, not a device id. Build a MAC→deviceId map from
`GET /v1/cameras` so an alarm becomes actionable.

- **Custom headers are supported on POST**, including `Authorization: Bearer`.
  The docs describe headers under the GET action, but that is a contrast of
  what each method *adds*, not a statement that POST excludes them. Build for
  POST + bearer; keep `?token=` only as fallback.
- **No HMAC signing exists.** Treat the webhook as unauthenticated by default.
- **The delivery contract is entirely undocumented.** Not merely "no retry
  policy stated" — Ubiquiti publishes no timeout, no backoff, no status-code
  semantics, no delivery log, and no redelivery control. **Assume at-most-once.
  Return 200 immediately and persist before doing any work.**
- **Parse the body regardless of `Content-Type`** — the docs show the body but
  name no content type. Do not 415 on a surprise.

**Known recurring regression:** Alarm Manager sometimes fires at detection
*end* rather than *start*. This is a version-dependent defect — it broke around
Protect 4.1.53, was fixed, and broke again in the 7.1.x/7.2.x line in 2026. It
is **not** architectural, and the tempting explanation that it follows from the
API's `start`/nullable-`end` shape is wrong. Detect and tolerate it; do not
design around it as a law.

### Do not build on `wss://.../proxy/protect/ws/updates`

The unofficial socket still works, and it is genuinely tempting: it is the only
path delivering smart detections **and** camera disconnect **and**
`driveFailed`/`driveSlow` **and** power events in one stream with a resumable
cursor. That is the strongest argument against everything above.

It loses anyway:

- It requires storing a **local admin username and password** — API keys are
  rejected outright. That is a categorically worse credential to hold than an
  API key, in a product whose whole configuration surface is credentials.
- It speaks an undocumented binary frame format.
- **Home Assistant, by far its largest consumer and the reason it stays
  exercised at all, is publicly migrating off it onto the same public API.**
  Building on it now is building on a path its own ecosystem is abandoning.

---

## 2. UniFi Access

### The WebSocket carries far less than the name suggests

Only **two message shapes** have been observed in practice —
`access.data.v2.location.update` and `access.data.v2.device.update` — and both
came from a single hub model. Treat the vocabulary as unestablished: other
hardware may emit shapes nobody has captured, which is the reasoning behind the
connected-but-silent detection in ARCHITECTURE.md §7.

**Neither carries door position, tamper, offline, battery, or emergency
state.** Only lock state and `remain_unlock`. The socket is a lock-state
accelerator, not an alarm surface. Every alarm class must come from elsewhere.

### What exists, and what genuinely does not

| Alarm class | Where it actually lives |
|---|---|
| Invalid credential / denied | System logs (`door_openings`, `admin_activity`) — **confirmed** |
| Door forced open | Console-computed state "Unauthorized Opening" (locked + DPS open). DPS status updates appear in system logs (`device_events`) as informational rows — **no confirmed distinct machine-readable value** |
| Held/propped open past threshold | **Does not exist.** An explicit, still-open feature request in Access's Alarm Manager. Must be derived by polling `door_position_status` |
| Hub / reader offline | Only via Alarm Manager **System → "Device status changed"**, which is generic across status transitions. Offline must be re-derived from the payload; the UI offers no offline-only subscription |
| Tamper | No confirmed representation on any surface |
| Battery low | **Not applicable.** The entire Access line is PoE — hubs and readers alike. The only battery is an *external* backup on the Enterprise Access Hub |
| Anti-passback | **Does not exist as a feature.** A roadmap item requested since Aug 2022, still unshipped as of mid-2026, acknowledged three separate times by Ubiquiti staff. It is in no policy documentation and no release notes |

> The first research pass reported anti-passback as "a real, shipping
> capability, just not an Alarm Manager trigger." That was wrong and the
> adversarial pass caught it. **Do not offer an anti-passback rule.**

### Access has its own Alarm Manager — but its webhook action is unresolved

Architecturally shared with Network and Protect, with Access-specific trigger
categories (Unlocks, Denied, Doorbell, User, System) and Access-specific
actions (Unlock/Lock Door, Evacuate, Lockdown).

**Ubiquiti's own action-availability table lists the Webhook action for
"Network & Protect" only** — while community reports describe an Access-side
webhook Delivery URL. This is a direct contradiction in the sources and it is
**not resolved**. Verify against a live console before any design depends on
it.

### Polling the system logs: the pacer is not the constraint

The binding constraint is **log indexing lag, measured at up to ~3.5 minutes**
— not the 220 ms console pacer. Consequences:

- **Poll floor ≈ 3 minutes.** Polling faster buys nothing and spends the rate
  budget that §1's reconciliation sweeps need.
- **Overlap the windows and dedupe on the log row id.** `since`/`until` are
  UNIX **seconds** while `event.published` is **milliseconds**, and the
  inclusive/exclusive boundary semantics are not documented and have not been
  measured. The time boundary cannot be trusted for correctness; the row id
  can.
- **Never advance the watermark when the log query errors.** Return no rows
  rather than partial ones: a truncated window looks complete, and attribution
  built on it names the wrong actor.

### Emergency state has no read-back

`SetEmergency` infers success by re-reading every door's lock state, which is
ambiguous against ordinary scheduled closes and silent on partial failure.

> **Never let the matrix infer lockdown by aggregating door locks.** Either be
> the system of record that issued the command, or treat any inferred "site
> appears locked down" signal as advisory only — never as a trigger for
> automated action.

---

## 3. UniFi Network

### The official Local Integration API is real, and broader than its reputation

`https://{console}/proxy/network/integration/v1/...`, introduced in **Network
9.0 (Jan 2025)**, documented through v10.4.57. Covers sites, devices, clients,
networks, WiFi, hotspot vouchers, switching, ACLs, DNS policies, and full
firewall CRUD.

It does **not** cover port forwards, historical statistics, or events and
alarms of any kind. The OpenAPI spec contains **zero** occurrences of "event",
"alarm", "webhook" or "subscribe".

Auth is `X-API-Key`. The spec declares no security scheme — the keys are
absent, not null — but Ubiquiti's first-party Network documentation names the
header directly, so this does **not** need inferring from sibling products.

### Network has its own Alarm Manager, and this is the correction that matters

**UniFi Network gained outbound webhooks via its own Alarm Manager in Network
9.3 (July 2025)** — separate from Protect's, with WAN-offline, threat, PoE,
device and client triggers, and a Webhook action (GET or POST to a custom URL).

This is the Network event surface. There is no other.

Two hard limits:

- **Alarm Manager rules are UI-configured only.** Nothing in any official API
  creates them, so the product **cannot self-provision its own push path**.
  Onboarding must walk the operator through it, with a Test Alarm verification
  step, and be designed *for* that rather than around it.
- **The payload is undocumented and field-inconsistent.** The message field has
  appeared as `message`, `msg`, `text` and `description` across firmware, and
  it carries **no controller timestamp** — unlike Protect's (§1), which does.
  Stamp on arrival and say so.

### Site Manager cloud API

`api.ui.com` — cross-site aggregation, ISP/WAN uptime-downtime at 5-minute
granularity, and a Cloud Connector that proxies any local Integration API call
for consoles not directly reachable.

- **Rate limit is 100 req/min per console**, not the local ~10 req/s. Budget
  the remote path separately.
- Freshness *is* measurable at runtime, contrary to the first-round finding:
  `GET /v1/devices` returns per-console `updatedAt` (RFC3339) and `GET /v1/hosts`
  returns `lastConnectionStateChange`. Use them rather than assuming latency.
- The "API key is read-only" note applies to Site Manager's own cloud
  resources, all of which are reads. The Connector is a transparent proxy and
  passes writes through — not a contradiction, a scope the note omits.
- Doc inconsistency: the Connector's prose example omits the `/proxy/` segment
  that its own parameter example includes. This is a **cross-spec** disagreement
  between Site Manager 1.0.0 and Network 10.4.57, not an internal one.

### Legacy cookie API

`POST /api/auth/login` then `/proxy/network/api/s/{site}/stat/event` still
works, and remains what Home Assistant actually uses — an API-key PR to
`aiounifi` was opened and closed unmerged on 11 Sep 2026. Touch it only for
port forwards and deep event history, behind probe-and-cache path discovery,
and only after testing whether `X-API-Key` alone suffices.

### Pacing

Use `nextHeartbeatAt` from `statistics/latest` to pace per-device polling
against the device's own cadence rather than a fixed timer. And share the
`unifi.Pacer` — §1's reconciliation sweeps and this client are drawing on one
budget that is already spent.

---

## 4. What this means for ingest

Three products, three different shapes, and only one of them has a real event
stream:

| | Protect | Access | Network |
|---|---|---|---|
| Official push | **Yes** — 2 WebSockets, API-key auth | Partial — WS carries lock state only | **No** |
| Resume cursor | No | n/a | n/a |
| Poll unavoidable | Yes, for reconciliation after every reconnect | **Yes** — system logs are the engine of record | **Yes** — the permanent backstop |
| Outbound webhook | Yes, documented, timestamped | **Unresolved** | Yes, undocumented, untimestamped |
| Self-provisioning | No — Alarm Manager is UI-only | No | No |

**Polling is unavoidable in all three.** Not as a fallback — as a permanent
backstop, because every push path here can fail silently: Protect's sockets
have no cursor, Access's socket can connect and stay mute on unfamiliar
hardware, and webhook delivery requires the console to route to us, which fails
for cloud-hosted controllers and most reverse proxies with no error on either
end.

That is the justification for the deadman in ARCHITECTURE.md §9. Every one of
these surfaces can stop delivering without saying so, so the product must
notice silence itself.
