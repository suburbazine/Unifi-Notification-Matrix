# UniFi Notification Matrix

> **Status: early development — not usable yet.** The architecture is settled
> and the foundations are built and tested: the incident lifecycle, the
> escalation policy, and the secret store. Ingest, channels, the durable store
> and the web UI are not written. The only working commands are `version` and
> `selfcheck`.

UniFi tells you a thing happened. Once.

If nobody was looking at their phone in that minute, the event is gone — no
re-alert, no acknowledgement, no record that a human ever saw it. For
convenience notifications that is fine. For a door forced open at 3am, or a
camera that went dark an hour before a break-in, it is the whole failure.

**This turns a one-shot UniFi event into a tracked incident that keeps
escalating until a human closes it.**

- Ingests from UniFi **Protect**, **Access** and **Network** — API where one
  exists, inbound webhook as a fallback.
- Escalates on a policy ladder that widens over time: push, then email, then
  (later) an automated phone call.
- **Acknowledgement works from a phone with one tap**, no login and no VPN.
- Fans out to **ntfy**, **Pushover**, **email**, and generic **JSON webhooks**,
  so it slots into whatever you already run.
- Runs as a Windows service or a systemd unit. Single static binary, no runtime
  to install.
- API keys are encrypted at rest — **DPAPI** on Windows, and a machine-bound
  equivalent on Linux.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design,
[docs/SOURCES.md](docs/SOURCES.md) for what each UniFi application actually
exposes, and [docs/DESIGN-RULES.md](docs/DESIGN-RULES.md) for the rules the
code follows and why.

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

Released binaries are signed: **Authenticode** via Azure Trusted Signing on
Windows, **cosign** (keyless, verifiable against the Rekor transparency log)
plus a detached GPG signature on Linux, with SLSA build provenance on both.

---

Copyright (c) 2026 Xtremission LLC
