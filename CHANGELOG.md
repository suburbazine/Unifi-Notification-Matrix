# Changelog

What changed in each release, written for somebody deciding whether to upgrade
rather than for somebody reading the diff.

Every published release has a section here, and the release workflow **refuses
to build a tag that does not** — before anything reaches the signing
certificate. A release whose notes say only how to verify the binary tells a
downloader nothing about what they are installing.

Format: newest first. Dates are the release date. Versions link to the compare
view against the release before them.

## [Unreleased]

### Added

- **A security policy, and a private channel to use it on.**
  [`SECURITY.md`](SECURITY.md) names where a report goes — GitHub's private
  advisories, which are enabled on this repository — what is in scope, and
  what happens after you send it.

  It also lists what is **already known and written down**: the acknowledgement
  token travelling in cleartext, the random acknowledgement port not being a
  security measure, and an appliance install running as root. Those are
  documented trades, not oversights, and somebody should not spend a weekend
  rediscovering one.

  And it says what a report must not contain. A real site's camera names are
  room names, its console address is a home address, and its acknowledgement
  tokens are live until their incidents close — `notifymatrix demo` reproduces
  the whole interface with none of that attached to anybody.

- **A description on the repository itself**, which had none. A security tool
  that does not say what it is on the page where people find it is asking a
  lot.

## [0.3.4] — 2026-09-19

**Gateway installs on 0.3.1 through 0.3.3 cannot start.** The daemon looked for
its encryption key in a directory it was not using and refused to run rather
than continue without credentials it could not read. Take this one. Windows and
ordinary Linux installs are unaffected and always were.

### Added

- **The interface now says when this installation cannot report its own
  failure.** Running on the equipment it watches, the daemon shares fate with
  it — so "all clear" and "this died an hour ago and cannot tell you" render
  identically, which is the exact state this product exists to refuse.

  Until now that was said only to stderr and the audit log. A service has no
  console, so the warning reliably reached nobody while the one screen an
  operator actually looks at said nothing.

  It appears as a banner on every screen **including signed out**, because a
  wall display is precisely who needs the caveat, and in the Health tab beside
  "will this come back on its own" — where somebody is already asking the
  neighbouring question. The public wording names the limitation and not the
  hardware or the fix; the signed-in one can say both.

  **It clears itself.** The problem was never where the daemon runs, it is
  that nothing outside the machine would notice it stop — so pairing a peer at
  another site makes it false, and the warning goes away rather than needing
  to be dismissed.

### Fixed

- **The encryption key now follows `--data-dir`.** It never did. The key-file
  tier took its path from `$STATE_DIRECTORY`, else a hardcoded
  `/var/lib/notifymatrix/secret.key` — and `SetKeyFile`, whose own comment said
  config called it, was never called by anything.

  On an ordinary Linux install those two answers coincide, because
  `StateDirectory=` puts the state at `/var/lib/notifymatrix` and that is also
  the data directory. They stop agreeing the moment anything runs with
  `--data-dir` somewhere else, and the UniFi gateway unit is the first shipped
  configuration that does: it cannot use `StateDirectory` at all, since that
  directive is always relative to `/var/lib` while the gateway keeps state on
  `/data`.

  The symptom was a daemon that refused to start, reporting — correctly, and
  uselessly — that *the key file does not match the value in the config*,
  naming a path in a directory it was not using. Every entry point that reads
  or writes the config now binds the key beside it.

## [0.3.3] — 2026-09-19

**If you installed 0.3.1 or 0.3.2 on a UniFi gateway, take this one.** Those
two shipped an install that crash-loops on first run and puts its state
somewhere other than where the documentation says. Nothing else is affected:
Windows and ordinary Linux installs behave exactly as they did.

Existing gateway installs keep their state at `/var/lib/notifymatrix`. To move
it where 0.3.3 expects, before setting a password:

```bash
systemctl stop notifymatrix
mkdir -p /data/notifymatrix && mv /var/lib/notifymatrix/* /data/notifymatrix/
```

then re-run the install.

### Fixed

- **The gateway install crash-looped, and the install put everything in the
  wrong place.** Both found by running 0.3.1 on a real UniFi gateway; neither
  was reachable from any test here.

  The unit denies `@privileged`, and **SQLite chowns its database when running
  as root** so a root-created file inherits the directory's ownership.
  `@chown` is inside `@privileged`, so seccomp killed the daemon with `SIGSYS`
  the moment the store opened — a zero-byte database, a journal beside it, and
  systemd restarting it into the same wall fifty-six times. The appliance unit
  now re-permits `@chown` and only `@chown`; `@setuid`, `@mount`, `@module`,
  `@raw-io`, `@reboot` and `@swap` stay denied, and the ordinary unit is
  unchanged because an unprivileged service never takes that branch.

  Separately, the gateway data directory never applied. `main.go` resolves it
  for every subcommand before dispatching, so `Install` was always handed a
  non-empty path and its "use `/data` if nothing was asked for" branch could
  never fire. Everything agreed on `/var/lib/notifymatrix` so consistently
  that nothing looked wrong until somebody went looking for `config.yaml`
  where the documentation said it was. The platform answer now comes from one
  place every command reads.

- **The gateway install instructions downloaded into the state directory.**
  `install` copies the program to `/usr/local/bin` and points the unit there,
  so the download left a stray binary and a checksum file sitting next to the
  config and the incident store. It downloads to a temporary directory now,
  and the page says which of the two paths holds what.

## [0.3.2] — 2026-09-19

### Fixed

- **Stopping the service no longer claims it is restarting.** The Health tab
  branched only on *start*, so pressing **Stop the service** produced the
  restart message — "this page will go quiet for a few seconds while it
  restarts" — to somebody who had just deliberately stopped their monitoring.
  It now says what state that leaves behind, that the page itself is about to
  stop responding because the service serves it, and it says so in warning
  colours rather than success green. Nothing reloads afterwards, because there
  is nothing to reload into.

  This product exists to stop a state reading as healthy when it is not, and
  that was the interface doing it about the one action that leaves nothing
  watching at all.

### Changed

- **The gateway page and the README now lead with why it exists**, which is
  *because it could, not because it should* — complete with a stick figure
  eyeing a large red button. The substance underneath is unchanged and
  deliberately unfunny: shared fate is still the reason not to do it, the
  daemon still says so at every start, and `docs/GATEWAY.md` still lists what
  was never verified on real hardware. It is the supported way to do an
  unrecommended thing, which is a different promise from a recommendation.

  Shipped in 0.3.1 without any of this, so it arrived reading like a feature
  rather than a curiosity.

## [0.3.1] — 2026-09-19

One added deployment target and nothing else. Existing installations are
unaffected: there is no schema change, no configuration change, and nothing
different about how the daemon behaves anywhere it already runs.

### Added

- **It installs on a UniFi gateway.** `install` detects UniFi OS — UCG, UXG,
  UDM, UDR, EFG — and adjusts itself: state under `/data` (the persistent
  partition, and not configurable), `ReadWritePaths` instead of
  `StateDirectory`, no `tss` group because there is no TPM and systemd fails a
  unit naming a group that does not exist, a memory fence so a fault here
  cannot take capacity from routing and inspection on the same box, and a
  refusal to install with under 256 MB available. No flag to pass: these are
  corrections for the platform rather than preferences, and an operator who had
  to know to ask for them would get a unit that does not start.

  **It is the wrong place to run this, and it says so at every start.** Hosted
  on the gateway, the daemon shares fate with the equipment it watches: when
  that box reboots, wedges or loses power, the alarm about it is the one thing
  that cannot be sent. Cover it with a peer paired at another site, or an
  off-site heartbeat that alarms on silence — either is enough, and with
  neither you have monitoring that cannot report its own death. See
  `docs/GATEWAY.md`, which is honest about the rest of the trade too: the
  service runs as root, and the secret store falls to the key-file tier, which
  is not machine-bound.

  For operators with no spare hardware. Not a recommendation.

## [0.3.0] — 2026-09-19

Two new operator-facing surfaces, and the results of two security reviews.

**Read the security section before upgrading if you have peers paired or
unusual configuration**: sessions now end after seven days however much they
are used, product slugs that were previously accepted are now refused, and a
failed pairing fingerprint no longer counts against your pairing code.

### Added

- **The rules are now checked against what this site has actually had.** Every
  other surface in this product reports on what arrived; nothing reported on
  what was *configured and never matched* — which is invisible by construction,
  because a rule pointing at a device that no longer answers to that id
  produces no event, no error and no entry anywhere. It simply never fires,
  and the board stays green. Settings → Rules now opens with a review of every
  entity a rule names, against the permanent record added in 0.2.0.

- **When a device has been re-adopted, it offers to repoint the rule.** A UniFi
  device id is generated *at adoption time*, so re-adopting hardware gives it a
  new id and silently detaches every rule naming the old one. The MAC is the
  only identifier that survives both that and a rename, and the record keeps
  it — so when one id goes quiet and another turns up carrying the same MAC,
  the page says so and offers a one-click fix. A match on the name alone is
  offered too, and is labelled as the weaker evidence it is.

  The review reports nothing at all when the record could not be read, or is
  empty. "Nothing is wrong" and "nothing was checked" look identical on a
  screen and are opposite facts, so it says which one it means.

- **A peer's new condition can be approved from the page instead of by editing
  YAML.** The vocabulary a peer may use is closed and stays closed — an
  undeclared condition is still refused, and nothing arrives until you say yes.
  What changes is what saying yes costs. A peer shipping a twelfth condition
  used to mean opening `config.yaml` on the machine, or re-pairing the product,
  which rotates a working credential in order to fix a spelling.

  Settings → Peer link now lists what a paired peer has tried to send and been
  refused for, with its own words, its proposed severity, and how many events
  it has cost. Approving one takes a meaning you write yourself and runs the
  same validator pairing runs. Only a condition the peer has actually been
  refused for can be approved, so this is not a second way to write
  configuration.

  A refusal for an undeclared condition is now labelled `undeclared-condition`
  rather than lumped in with `invalid-envelope`, because you do a different
  thing about it: one is a bug to report to the peer's author, the other is a
  decision waiting for you.

### Security

Two independent reviews of the whole codebase and of the acknowledgement path.
Neither found anything critical; both found real things. Nothing below changes
what any of these ports are willing to SERVE — that half was already settled —
only what a hostile request COSTS.

- **The acknowledgement listener is bounded.** It is the one port this product
  tells you to forward, so it will be found by background scanning within days
  and probed indefinitely afterwards, and it shared a process, a SQLite
  connection pool and a write lock with the escalation engine. It now caps
  request headers at 8 KiB (Go's default allows a megabyte, per request), holds
  at most 256 connections, and refuses past 64 requests in flight rather than
  queueing them behind the database lock the alarm path needs. The failure this
  prevents is not a refused acknowledgement — that is cheap — it is an alarm
  that cannot be delivered because the ack port is busy.

- **A malformed acknowledgement request no longer reaches the database.** A
  token is always exactly 22 base64url characters, so almost everything that
  port receives is now refused on shape alone: no allocation, no HMAC, no
  SQLite read. Previously every three-segment path cost one query, and a
  megabyte of junk in a path segment was handed to the database as a parameter.

- **Ten acknowledgements a minute per address,** with a burst of twenty. A
  human opens one link and taps it once; nothing legitimate arrives in a
  stream. Keyed on the peer address and deliberately **not** on
  `X-Forwarded-For`, which on an exposed port is written by whoever is calling.
  If you front this with a reverse proxy, limit there too.

- **"No such incident" and "wrong token" now take the same time.** They always
  returned the same page and the same status; the miss path skipped the HMAC
  and answered measurably faster, which is exactly the incident-id enumeration
  the single error class exists to prevent, arriving through the clock instead
  of through the body.

- **The peer link port no longer writes to disk when a stranger knocks.** Every
  refusal — no such route, wrong method, unsigned, bad signature, clock skew,
  every pairing failure — was appended to `audit.jsonl` with an fsync. That is
  one synchronous disk flush per packet from anybody who can reach the port,
  and because the audit file rotates, enough of them would evict the record of
  who acknowledged what. Refusals that required a credential are still audited;
  all of them still appear in full, with their reason, on the session-gated
  receipts page where they were always the most use.

- **`web.ack_base_url` is checked properly.** A base URL carrying a query
  string, a `#fragment` or a username parses fine, looks reasonable, and
  silently breaks every acknowledgement link — the token ends up somewhere the
  route never matches, or somewhere a browser never sends. Refused at
  validation with an explanation. A hand-written `web.ack_key` shorter than 16
  bytes is now reported too.

- **The demo installation generates its own acknowledgement key** instead of
  signing with a fixed one from the source. Harmless while a demo stays on
  loopback, wrong the first time somebody forwards a port to show a colleague.

- **A signed request can no longer be replayed while it is still in window.**
  The skew window is symmetric on purpose — a peer whose clock runs fast has to
  work — but the replay cache expired a nonce by when the request ARRIVED, so a
  request stamped nearly a window ahead had its nonce forgotten while its own
  timestamp was still valid, and the identical signed request was accepted a
  second time. Nonces now expire on the timestamp the request carried, which is
  exactly as long as anything bearing it could still pass the skew check.

- **The peer link port bounds its request head** at 8 KiB, and **receipts no
  longer retain whatever a stranger sends.** Three receipt fields come straight
  off the wire before anyone has authenticated — the link id header, the URL
  path, and the reason quoting the offending value back — and two hundred of
  them are held until the next restart. Each is clipped to 256 bytes, on a rune
  boundary so the page never renders a broken character.

- **A pairing that fails to happen no longer swaps the credential in memory.**
  A re-pair wrote into the slice the running configuration points at before the
  save was attempted, so a save that failed left this process using the new key
  — with the old one already dead — while the peer was told the pairing failed.
  Intermittent by construction, because it was invisible whenever the slice
  happened to be exactly full.

- **Product slugs are validated.** A slug becomes the event source, the first
  segment of every stored dedup key for ever, and the path segment of the
  unpair route — so one containing a slash was a peer that could not be
  unpaired from the page at all. Now lower-case letters, digits and hyphens,
  at most 32, and not one of this product's own source names: a peer calling
  itself `access` would mint dedup keys indistinguishable from the native
  source's. Enforced at pairing and when reading the configuration.

- **A stranger can no longer void your pairing code.** `MaxCodeAttempts` exists
  to stop a code being ground down by guessing, but a wrong TLS fingerprint or
  an unapprovable manifest also spent an attempt — so anybody who could reach
  the port during a pairing window could burn all five with junk that never
  came near the code, and you would be told it was voided after five wrong
  answers. Only a failed proof counts now.

- **Two link ids differing only in case are no longer confused.**
  Authentication matched byte for byte while the peer lookup matched
  case-insensitively, so a request could authenticate against one credential
  and resolve to the other peer — arriving under the wrong product's slug, with
  the wrong manifest deciding what it may send.

- **The plaintext-credential check covers all ten credential fields,** not
  five. `ack_key` was among the missing ones, which signs every acknowledgement
  link this product sends: pasted into the file by hand it would have sat there
  readable and nothing would have said so. A test now walks the configuration
  struct with reflection and fails the build if a credential field is added
  without extending the list.

- **A signed-in session now has an absolute ceiling of seven days.** The
  existing timeout refreshed on every request, so a tab left open on a wall
  display — which polls — never let it expire, and the honest answer to how
  long the cookie was good for was "until the daemon restarts". Signing out
  also gets the cross-origin check every other state change has.

## [0.2.1] — 2026-09-19

**If you script installations, read the note at the end of this entry.**

### Changed

- **`install` now hands you the setup token and waits until you say you have
  it.** It used to print `install: ok` and stop. The service then started,
  minted the one-time token and wrote it to a file — announcing it on a
  console that does not exist, because a Windows service has no stdout. The
  operator saw two words, opened the interface, and was asked for a token
  nothing had ever shown them.

  Worse on the elevated path: an unprivileged `install` relaunches itself in a
  new elevated window, which Windows destroys the instant the program exits.

  Now the install waits for the service to write the token, shows it, and does
  not return until the operator types `copied`. A word rather than Enter,
  because Enter is what people press to make a prompt go away — that would be
  a pause dressed up as a confirmation.

  It never blocks an unattended install: redirected, piped or absent stdin all
  mean nobody is there, and a deployment hanging for ever is a far worse
  failure than an unread prompt. It also says plainly that closing the window
  does not lock you out, because `notifymatrix setup-token` retrieves it — a
  prompt implying the value was unrecoverable would be a lie. Re-installing
  over an existing password waits for nothing, since no token is minted.

  **Scripted installs:** a run with redirected, piped or absent stdin never
  prompts, so CI, MDM and scheduled tasks are unaffected. A script run by hand
  from a terminal inherits that terminal, so it WILL stop and wait — which is
  usually right, because somebody is sitting there. To opt out, redirect stdin:
  `notifymatrix install < NUL` on Windows, `< /dev/null` elsewhere.

## [0.2.0] — 2026-09-19

The 0.1 line ran from the first working product to a paired first-party
integration. This starts a new minor line, and it starts it by having the
product check something about itself that it had only ever checked about a
download.

### Added

- **The daemon now checks, at every start, that it is running the binary it
  was installed as** — and raises an incident when it is not.

  This closes a gap the product already knew about and did nothing with.
  Installing warns that a service running out of a user-writable folder is
  "a file anybody running as that user can replace, choosing what runs as the
  service account next time it starts, with no prompt and none of the
  updater's signature checking involved". That was true, and nothing looked
  afterwards: the replacement started, ran with the service account's
  privileges, and every surface read healthy.

  What is reported: a binary that **changed without its version changing**
  (an update changes both; a replacement changes one), and on Windows a binary
  that **stopped being signed** or that is **signed by a different publisher**
  than the one this installation ran before. An ordinary update is silent, and
  a change is reported once rather than at every start — an alarm that repeats
  forever for something the operator has decided to live with becomes
  wallpaper, and takes the credibility of every other alarm with it.

  **What it cannot do, stated plainly.** It is a tripwire, not a defence:
  anyone who can rewrite both the binary and the reference beside it can
  silence it. It earns its keep where those two differ in privilege — most
  sharply on Windows, where the install can sit in a user-writable directory
  while the data directory is ACL'd to administrators and SYSTEM.

  **On Linux it detects change, not authenticity.** There is no Authenticode
  for an ELF binary, and the sigstore bundle published beside a release is not
  installed alongside it and would need a verifier this program does not
  embed. So Linux gets the hash comparison and no publisher identity — which
  catches a careless replacement and cannot tell you the original was
  authentic. On a default install the binary and the data directory are both
  root-owned, so there is no privilege asymmetry there to rely on either.
  `notifymatrix selfcheck` now says which of these applies on the machine you
  run it on, rather than leaving a quiet startup to be read as a guarantee.

### Changed

- **The record of what this site has is now permanent, and survives a
  restart.** It was a map in memory, capped at 500 entries, evicting the least
  recently seen. Both of those were wrong for the question it turns out to
  answer.

  Not in memory, because the useful question is asked *after* a restart: the
  power goes out, the site comes back, and the operator needs to know what it
  HAD — not what answered afterwards. Not evicted by recency, because the
  least recently seen entity after a lightning strike is the camera that was
  destroyed. The old policy discarded precisely the rows the record exists to
  preserve, keeping the survivors and forgetting the losses.

  Each entity now carries when it was **first** seen as well as last, because
  "here since March, stopped reporting on Tuesday" and "there is no such
  camera" are different sentences and only one of them describes a loss. A
  rename updates the row rather than creating a second one, which the old
  in-memory key did.

  Unbounded is safe here and that was checked rather than assumed: every
  source keys entities on adopted hardware or on a configured hook, and
  nothing emits one per DHCP lease. A row is about 200 bytes, so twenty
  thousand of them is four megabytes.

- **The MAC address is now recorded for every entity that has one.** Nothing
  matches on it yet. It is there because it is the only identifier that
  survives both of the two ways an entity's identity breaks: a UniFi device id
  is generated at adoption time, so re-adopting a hub recreates every camera or
  door under it with a new id and silently detaches every rule naming one —
  while a rename breaks every rule naming one by name. The id survives a
  rename; the name survives a re-adoption; only the MAC survives both.

## [0.1.10] — 2026-09-18

**No functional change. There is no reason to upgrade to this from 0.1.9.**
The binary behaves identically; what changed is a rule written down and a test
that enforces it. Recorded as a release so the tag and the source agree, not
because anything on your machine needs replacing.

### Changed

- Backup file naming is now one rule rather than two undocumented habits,
  stated in docs/DESIGN-RULES.md §4 and enforced by a test that walks the
  source tree. A copy the product will clean up ends `.previous`; a copy the
  operator owns is qualified by what it restores into and ends `.bak` — so
  `notifymatrix.exe.previous` is deleted at the next successful start, while
  `incidents.db.v1.bak` survives until you delete it.

  No files were renamed and no paths changed. Both existing names already
  followed the rule; what was missing was the rule.

## [0.1.9] — 2026-09-18

### Added

- **A schema upgrade now takes a snapshot of the database first.** Upgrading is
  a one-way door — an older build refuses a database newer than itself, on
  purpose, because a downgrade that "mostly works" misreads live alarms — and
  until now the only way back was a backup nobody had been told to take. The
  copy is written beside the database as `incidents.db.v<schema>.bak`, named
  for the schema it restores into, and the version that took it is printed at
  startup.

  Taken by the migration rather than by the updater, so it covers every route
  in: the in-app updater, a replaced binary, a package manager, or somebody
  running the new version by hand. A fresh install and an ordinary restart take
  no copy. If the snapshot cannot be written the upgrade still proceeds and
  says so loudly, because a missing backup costs a way back while refusing to
  start costs the site its monitoring.

### Fixed

- **The page header was not sticking.** `height:100%` on `body` made it exactly
  one viewport tall, and a sticky child is confined to its containing block, so
  the header stuck for one screenful and then scrolled away like anything else.
  Height moves to the `html` element and `body` takes `min-height`.
- **The Settings section rail marked the wrong section.** It measured from the
  header's bottom edge, which had gone thousands of pixels above the viewport,
  so the rail pointed at a section the reader had passed several screens ago.
  The reference line is now clamped inside the viewport whether or not sticky
  is working, and over the last screenful it comes down to meet the final
  sections — which a fixed line could never reach, leaving Password
  unreachable at every width measured.

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

[Unreleased]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.10...v0.2.0
[0.1.10]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/suburbazine/Unifi-Notification-Matrix/compare/v0.1.8...v0.1.9
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
