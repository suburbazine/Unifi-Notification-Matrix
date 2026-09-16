# Releasing, signing, and verifying

Two audiences. **§1 is for anyone who downloaded a binary** and wants to know
it is the one this repository built. **§2–4 are for whoever cuts releases.**

For a source-available security tool, published source that nobody can check
against the published binary buys very little. Everything below exists so the
check is actually possible.

---

## 1. Verifying a release you downloaded

Every released binary carries:

| | Windows | Linux |
|---|---|---|
| Code signature | **Authenticode**, timestamped | — |
| Detached signature | cosign (keyless) | cosign (keyless) |
| Transparency log | Rekor | Rekor |
| Build provenance | SLSA, via `gh attestation` | SLSA, via `gh attestation` |
| Optional | — | detached GPG `.asc` |

### cosign — works on any platform, nothing to trust in advance

This is the strongest check, and the one to prefer. It proves **which workflow
in which repository** produced the file. A bare signature only proves somebody
holding a key signed something; this identifies the builder.

```bash
cosign verify-blob notifymatrix-linux-amd64 \
  --signature   notifymatrix-linux-amd64.sig \
  --certificate notifymatrix-linux-amd64.pem \
  --certificate-identity-regexp '^https://github\.com/suburbazine/Unifi-Notification-Matrix/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`Verified OK` means this exact byte sequence was signed by a GitHub Actions run
in this repository, and that the signing certificate is in the public Rekor
transparency log.

> **`--certificate-identity-regexp` is not optional.** Without an identity
> constraint, cosign will happily verify a signature made by *anybody* with a
> Sigstore identity, which proves nothing about who built your binary. Any
> instructions that omit it — including ones you find elsewhere — are wrong.

### Build provenance

```bash
gh attestation verify notifymatrix-linux-amd64 --repo suburbazine/Unifi-Notification-Matrix
```

Reports the source commit, the workflow, and the runner that produced the file.

### Checksums

`SHA256SUMS` is itself signed, so verify it first and then use it:

```bash
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp '^https://github\.com/suburbazine/Unifi-Notification-Matrix/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Checking a hash against an *unverified* `SHA256SUMS` proves only that the file
matches a number supplied by whoever supplied the file.

### Windows Authenticode

```powershell
Get-AuthenticodeSignature .\notifymatrix-windows-amd64.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid` and `TimeStamperCertificate` must not be empty — the
timestamp is what keeps the signature valid after the signing certificate
expires.

### Rebuilding it yourself

Releases are built reproducibly. Given the same tag and the same Go toolchain,
you get the same bytes:

```bash
git clone https://github.com/suburbazine/Unifi-Notification-Matrix
cd Unifi-Notification-Matrix
git checkout v1.2.3
cat .go-version                       # install exactly this Go version

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -buildid= -X main.version=1.2.3" \
  -o notifymatrix-linux-amd64 ./cmd/notifymatrix

sha256sum notifymatrix-linux-amd64    # compare against SHA256SUMS
```

A mismatch is worth reporting. The usual innocent cause is a different Go patch
release — `.go-version` records the one the release used.

> The **Windows** binary will *not* match, because signing rewrites the file
> after the build. Verify that one with Authenticode or with cosign against the
> signed artefact.

---

## 2. One-time setup

### 2a. GitHub

Create an environment named **`release`** (Settings → Environments). The
Windows signing job is pinned to it. Optionally add required reviewers, which
puts a human approval in front of the code-signing key.

**Repository variables** (Settings → Variables — not secrets, none of these are
sensitive):

| Variable | Value |
|---|---|
| `AZURE_SIGNING_ENDPOINT` | `https://eus.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT` | `Xtremission-LLC` |
| `AZURE_CERT_PROFILE` | `Xtremission-LLC` |

**Repository secrets:**

| Secret | Value |
|---|---|
| `AZURE_CLIENT_ID` | App registration (client) ID — §2b |
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription holding the signing account |
| `GPG_PRIVATE_KEY` | *Optional* — §4 |
| `GPG_PASSPHRASE` | *Optional* — §4 |

None of these is a credential that can sign anything on its own. The Azure
values are **identifiers**; authentication happens through a short-lived OIDC
token minted per run.

### 2b. Azure — federated credentials, no stored secret

In **Entra ID → App registrations**, create an app (e.g.
`notifymatrix-release-signing`), then under **Certificates & secrets →
Federated credentials** add one of type *GitHub Actions deploying Azure
resources*:

| Field | Value |
|---|---|
| Organization | `suburbazine` |
| Repository | `Unifi-Notification-Matrix` |
| Entity type | **Environment** |
| Environment name | `release` |

which produces the subject:

```
repo:suburbazine/Unifi-Notification-Matrix:environment:release
```

**Why an environment and not a tag.** Entra federated credentials do not accept
wildcards in the subject, so `ref:refs/tags/v*` is not expressible — a
tag-based subject would need a new federated credential for every release.
The environment subject is stable and doubles as the approval gate.

Then grant the app permission to sign: on the Artifact Signing account, **Access
control (IAM) → Add role assignment → Trusted Signing Certificate Profile
Signer**, assigned to that app registration.

**Nothing in this flow puts a long-lived Azure credential in the repository.**
That is the point of moving off the workstation `az login` flow, where the
credential is whatever the person running the build happens to be holding.

---

## 3. Cutting a release

```bash
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

The workflow then:

1. **verify** — `go vet` and `go test -count=2` on Linux *and* Windows. The
   secret store is a different implementation per OS, so both must run.
2. **build** — `linux/amd64`, `linux/arm64`, `windows/amd64`, reproducibly.
3. **sign-windows** — Authenticode via Azure, then asserts the signature is
   `Valid` *and* timestamped before continuing.
4. **release** — checksums, keyless cosign signatures, optional GPG, SLSA
   provenance, and a **draft** release.

The release is a draft on purpose: look at it before it is public.

`workflow_dispatch` with an existing tag re-runs the whole thing, which is the
recovery path when a signing step fails midway.

### If signing fails

- **`AADSTS70021` / no matching federated identity** — the subject does not
  match. It must be exactly `repo:OWNER/REPO:environment:release`, and the job
  must actually declare `environment: release`.
- **403 from the signing endpoint** — the app registration is missing the
  *Trusted Signing Certificate Profile Signer* role on the account.
- **"signature is not timestamped"** — the timestamp server was unreachable.
  Re-run; never ship the binary untimestamped, because it starts failing
  validation on the day the certificate expires, on machines that ran it
  happily the day before.

---

## 4. GPG (optional, and weaker)

cosign keyless is the primary Linux signature. GPG exists only because distro
packagers and long-time Linux users expect a detached `.asc`.

It is **deliberately optional**, and worth understanding why it is second
choice: it requires a long-lived private key in repository secrets. That is a
thing that can leak, must be rotated, and proves only that someone holding the
key signed the file — where the keyless certificate proves *which workflow in
which repository* built it. If `GPG_PRIVATE_KEY` is unset the release still
ships, fully signed.

To enable:

```bash
gpg --full-generate-key                      # RSA 4096, or Ed25519
gpg --armor --export-secret-keys KEYID       # -> GPG_PRIVATE_KEY secret
gpg --armor --export KEYID > notifymatrix-signing-key.asc   # publish this
```

Publish the **public** key somewhere independent of the release artefacts —
a keyserver, or the project website. A public key distributed alongside the
thing it signs is not a check on anything.

---

## 5. Local builds

`build.ps1` (Windows) and `build.sh` (Linux) use the same flags as the release
workflow, so a local binary differs from a released one only by its version
string. Local builds are versioned `<describe>-dev` and are never mistakable
for a release — if a support case quotes a version, it must be possible to tell
which binary they ran.

`build.ps1` signs with whatever `az login` identity you are holding. That is
fine for a hand-carried test build and is **not** how releases are signed.
