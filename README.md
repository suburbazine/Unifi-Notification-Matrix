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

Builds are reproducible: given the same tag and the Go version in
`.go-version`, `go build -trimpath -ldflags "-s -w -buildid= -X main.version=…"`
produces the released bytes exactly. That is the point of publishing source for
a security tool — source nobody can check against the binary buys very little.

## Verifying a download

Released binaries are signed. The strongest check needs no key trusted in
advance, and proves **which workflow in which repository** built the file:

```bash
cosign verify-blob notifymatrix-linux-amd64 \
  --signature   notifymatrix-linux-amd64.sig \
  --certificate notifymatrix-linux-amd64.pem \
  --certificate-identity-regexp '^https://github\.com/suburbazine/Unifi-Notification-Matrix/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

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
