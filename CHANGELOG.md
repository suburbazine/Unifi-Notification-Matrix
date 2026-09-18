# Changelog

What changed in each release, written for somebody deciding whether to upgrade
rather than for somebody reading the diff.

Every published release has a section here, and the release workflow **refuses
to build a tag that does not** — before anything reaches the signing
certificate. A release whose notes say only how to verify the binary tells a
downloader nothing about what they are installing.

Format: newest first. Dates are the release date. Versions link to the compare
view against the release before them.

## [0.1.8] — 2026-09-18

### Fixed

- **A momentary alarm that cleared quickly was never delivered at all.** If the
  condition resolved inside the tick interval, the incident opened, resolved,
  and nobody was told. Momentary conditions now deliver even when they clear
  first. Applied per condition: motion, smart-detect, loitering and
  audio-detect stay as state conditions deliberately, because for those the bug
  had been acting as noise suppression, and fixing it everywhere at once would
  have turned a quiet site loud.
- Uptime, last delivery and last error now appear on the health view. They were
  dead fields — served as zero and never set.

### Added

- **Rules can apply only during part of the day**, and shift severity by tiers
  rather than multiplying it. A window gates the whole rule, is evaluated when
  the incident is raised, and uses the site's time zone.
- **Xtremission Link** — a paired first-party product can raise incidents here,
  and take over a capability while it is genuinely serving it. Inert until an
  operator pairs something.
  - Its own TLS listener on a separate port, with a certificate the peer pins.
  - HMAC request authentication with the channel tag *inside* the signed
    string, so a signature minted for one channel cannot be replayed on
    another.
  - Crockford pairing codes: ten minutes, single use, voided after five wrong
    answers, with the certificate fingerprint bound into the proof — so
    something terminating TLS in the middle cannot complete a pairing even
    holding the code.
  - Durable event-id idempotency, so a peer can retry without raising twice.
  - A capability claim a peer loses *while still alive*, when it reports it
    cannot see what it claimed. Being reachable is not the same as being able
    to serve, and the difference is otherwise invisible: every other indicator
    reads healthy.
  - A per-peer rate limit, counted after authentication so a stranger cannot
    spend a real peer's allowance by naming it.
- **Pairing from the Settings page**: offer a code, cancel it, forget a peer,
  and read what peers have actually done here. Every failure on the link port
  answers a bare 404, so nothing on the wire distinguishes a wrong key from a
  wrong clock; the real reason reaches the operator through session-gated
  receipts, each with a typed cause.
- `GET /hello` on the operator listener, **unauthenticated**, naming the
  product and where its channels are. It discloses nothing the root page did
  not already serve to a signed-out reader — the one new fact is the link
  listener's port.
- `GET /link/hello` on the link listener, **unauthenticated but answering only
  while a pairing code is on offer**. Outside that window it is byte-for-byte
  indistinguishable from a route that does not exist.

### Notes

The Link protocol is verified against independent implementations rather than
against itself. Conformance vectors from two other products are pinned as
tests, and the first live pairing between products ran end to end before this
release.

## [0.1.7] — 2026-09-17

### Fixed

- A listen address this machine does not have is refused at startup, instead of
  stopping the service and taking the interface that could fix it down with it.
- `web.ack_listen` says what to type, and only loopback is called loopback.

### Added

- Why a run stopped is recorded where it can be found afterwards.
- A chart of how an event becomes an acknowledged incident, in the README.

## [0.1.6] — 2026-09-17

### Fixed

- **Alarms are announced in the site's time zone, not the server's.** A voice
  call reading out "at 3:14 PM" was using the machine's clock, which is right
  when the machine sits at the site and wrong when it is a server on UTC.

### Added

- A chart of how a change becomes a release, at the top of the README.

## [0.1.5] — 2026-09-17

### Fixed

- Hook URLs point at the listener that actually serves hooks.

## [0.1.4] — 2026-09-17

### Added

- **The operator interface was rebuilt.** Settings is one page with a section
  rail and a Save per section, so a save posts only the keys it owns and leaves
  every other section as typed.
- Operators are told what they can write a rule about, rather than having to
  know the vocabulary.
- A hook can be proved to work without waking anybody, and its URL and header
  are shown where the hook was created.

### Fixed

- Machine output is no longer shown to a person on two screens.
- Screenshots recaptured against the interface that exists.

## [0.1.3] — 2026-09-17

### Added

- **The voice channel**: Twilio, speak the alarm, hang up.

### Fixed

- A tagless clone breaks the rebuild-and-compare recipe, and now says so.

## [0.1.2.1] — 2026-09-16

### Fixed

- **A source is measured by whether it is in contact, not by whether it had
  news.** A quiet camera and a dead console looked identical.
- A four-part version compares correctly.

## [0.1.2] — 2026-09-16

### Fixed

- **An alarm nobody was told about is never given up on.**
- A condition that came back before anybody saw it is treated as a new alarm.
- The ladder climbs while its first rung is failing, instead of stalling there.
- A partial save no longer deletes the rest of the configuration.
- A camera's offline incident clears when it returns through `CONNECTING`.
- An update whose binary disagrees with its tag is refused.
- The ntfy topic is kept out of an error that gets published, and the
  configuration and its secrets are kept off a shared machine.
- The current-password check is throttled; the Access socket no longer holds up
  shutdown; an unelevated install reaches the prompt it promises; the config
  file's own instructions parse.

## [0.1.1] — 2026-09-16

### Fixed

- Audit detail wraps, and password managers are kept out of the settings
  fields.

## [0.1.0] — 2026-09-16

First release of the 0.1 line.

### Added

- A Webhooks tab, with outbound endpoints as a list.

### Fixed

- One bad field no longer takes down the daemon, the save, or the whole ladder.

## 0.0.1 release candidates — 2026-09-16

Ten release candidates covering the first working product: the incident
lifecycle and escalation policy, the Protect, Access and Network sources, the
ntfy, email, Pushover, webhook and inbound-hook channels, acknowledgement
links, the audit record, the capability probe (local networks only), service
supervision and crash detection, the operator interface, the in-app updater,
demo mode, and the signed reproducible release pipeline.

They are not listed individually. Nothing was installed from them that a 0.1
release does not supersede.

[0.1.8]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.2.1...v0.1.3
[0.1.2.1]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.2...v0.1.2.1
[0.1.2]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.0.1-rc10...v0.1.0
