# Design rules

Rules this codebase follows, and the reasoning behind each. They are written
down because most of them look like over-engineering until the failure they
prevent actually happens, and because the obvious "simplification" of several
of them is a regression.

If you are about to change something here, the reason is the part to argue
with — not the rule.

---

## 1. Talking to the console

**Pace conservatively, and share one pacer per console.** The console
rate-limits, the rate window is server-side, and its phase is unknown to us. A
client pacing exactly at the observed limit still trips when a burst straddles
a window boundary, so we sit meaningfully under it.

The pacer reserves its slot **under the mutex and sleeps outside it**. The
alternative — read the timestamp, release, sleep — has N goroutines all read
the same stale value and depart together. That looks paced in source and
arrives at the console as a burst.

> **One pacer per console, not per client.** This product talks to three
> applications behind one UniFi OS host. Three independently-paced clients
> multiply the request rate by three against a single shared budget. Any new
> caller shares the existing pacer; it does not add one.

**Back off exponentially with *half* jitter, not full.** Full jitter can return
near-zero and re-fire immediately, which against a rate limiter is precisely
the behaviour the backoff exists to prevent. Jitter at all is mandatory: a
console restart drops every client at the same instant, and they must not all
return together.

**Honour `Retry-After` only in its delta-seconds form, and only within a sane
bound.** The HTTP-date form requires both clocks to agree, and the console most
likely to send it is the one that just rebooted.

**A rejected credential is not a dead connection.** After a console restart the
reverse proxy answers 4xx and 5xx for a while as applications re-initialise.
Treating an auth failure as terminal means a correct key is permanently
abandoned because of a reboot. Only a certificate pin mismatch is terminal.

**Certificate pinning refuses; it does not warn.** The verification callback
runs after *every* handshake regardless of other TLS settings — that is what
makes a pin hold in the self-signed configuration it exists for. A pin mismatch
is a typed sentinel error, never a string match on a message.

**Trust-on-first-use is an operator action, never automatic.** A client that
silently learns a pin on first connection has no protection on the one
connection an attacker would target.

---

## 2. Decoding what comes back

**HTTP 200 is not success.** At least one of these APIs reports real failures
in the body of a 200 response. Any envelope must be checked before the payload
is believed.

**One bad record must not take out the whole call.** Collection endpoints
return the entire site in a single array decoded by a single unmarshal. A
strict typed decode does not lose one unexpected field — it fails the *entire*
request, so every downstream reader goes dark together. Decode defensively and
normalise per record.

**An unreadable value yields "no information", never a guess.** Where a state
is unknown, the model must be able to say so. Collapsing unknown into a
plausible default — "probably locked", "probably online" — reports security on
no evidence, and this product's entire job is not doing that.

**Truncation is detected, not returned.** Read one byte past the cap and error
when the body exceeds it. Reading exactly the cap cannot distinguish a complete
body from a longer one, and the result is a silently corrupt payload.

**Bulk envelopes are real.** At least one push channel delivers messages whose
id field is an *array* covering many devices. A parser that reads it as a
string drops every bulk message with no error and no counter. This has a test.

**A stream that connects and is never understood is a fault, not a success.**
Count unrecognised messages and surface a connected-but-silent channel as a
failure. Otherwise unfamiliar hardware produces a live-looking, never-updating
source — silent total failure, which for this product is the worst possible
outcome.

---

## 3. Credentials

**A stored secret records how it was protected.** Values are written with a
prefix naming the mechanism — `dpapi:`, `sdcreds:`, `tpm2:`, `agekey:`,
`plain:`.

> **The prefix must state what actually happened.** A config that labels an
> unencrypted development fallback as though it were encrypted is worse than
> one that admits it, because the second can be noticed. `plain:` means plain.

**A secret cannot reach a log by accident.** The secret type's `String()`
returns `<redacted>`, so a value reaching a format verb is a non-event.
Plaintext comes only from an explicitly named accessor, so every use site is
greppable and obvious in review.

**Some URLs are credentials.** Stream and snapshot URLs embed a path token that
is all anyone on the network needs to watch a camera. They are redacted to
scheme, host and port before they reach any log or error. On endpoints where
the body *is* the credential, report a byte count and never the content.

**Discard credential material at decode time.** Directory records can carry PIN
codes and card numbers. A struct field is all it takes for one to reach a crash
dump, so they are dropped during unmarshal and only their presence survives.

**Never put a secret in a URL.** Headers only.

---

## 4. Irreversible operations

Some endpoints on this hardware cannot be undone without a factory reset.

**They are not implemented, not behind a flag, and not behind a confirmation
dialog.** A guard that lives in a reviewer's memory is not a guard, so this is
enforced by a test that walks every non-test file in the package and fails the
build if the call appears. Adding one back breaks the build rather than a
customer's hardware.

---

## 5. Notification channels

**ntfy text fields go as URL query parameters, not headers.** Headers cannot
carry newlines — which multi-line alert bodies need — and require RFC 2047
encoding for non-ASCII. Query parameters handle both through ordinary URL
encoding. The attachment rides as the request body.

**Plain text is always the base part of an alert email; HTML is an alternative
layered on top.** A security alert must survive HTML-stripping gateways and
text-only alert pipelines. Any inline image is attached *into* the HTML part so
its content-id resolves in place rather than arriving as a stray attachment.

**Retry a rate-limited alert, but briefly and boundedly.** An alert that lands
ten minutes late is nearly useless; one dropped because a shared quota was
momentarily exhausted is worse. A few attempts with short backoff, honouring a
server-advised delay when it is present and sane.

**Delivery never blocks ingest.** Sends run on a background worker with a
bounded queue. A slow or greylisting mail server must not be able to drag the
ingest loop progressively later — and an unbounded queue turns a delivery
outage into a memory leak.

> **One queue per channel.** A single shared queue lets a stalled SMTP
> connection delay every push notification behind it.

**A failed delivery does not count as an alert.** If every channel failed, the
incident has not been alerted and the next attempt comes sooner, not later.

---

## 6. Changing an outbound contract

When a field that consumers switch on has to change, **ship the old value
alongside the new one**, with a dated comment saying to remove it once nothing
reads it. An integration that silently stops matching is a support call the
consumer cannot diagnose.

---

## 7. Building

**`CGO_ENABLED=0`, always, and it is load-bearing rather than tidy.**

- Static Linux binaries that run anywhere, including Alpine and containers.
- Builds reproducible enough that a reader can verify a published binary
  matches its tag — which for a source-available security tool is most of the
  point of publishing the source.
- It disqualifies dependency classes that would otherwise creep in, notably
  cgo-linked SQLite drivers and libsecret bindings. Those exclusions are
  consequences of the constraint, not coincidences: the constraint is chosen
  first and the dependency list obeys it.

Building with cgo merely *available* on the build machine silently produces a
binary with a libc dependency the target may not have, so it is set explicitly
rather than assumed.

**Tests and vet gate the build, before signing.** A signed broken binary is
worse than an unsigned one, because the signature is what persuades someone to
run it.
