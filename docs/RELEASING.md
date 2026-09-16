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
release — `.go-version` records the one the release used, and it is kept on the
**latest** patch of its line deliberately: CI runs `govulncheck`, and a Go
patch release is the usual way a standard-library vulnerability gets fixed
under you. The toolchain is a build input, so bumping it changes the expected
hashes.

> The **Windows** binary will *not* match, because signing rewrites the file
> after the build. Verify that one with Authenticode or with cosign against the
> signed artefact.

---

## 2. One-time setup

### 2a. What has to exist, in order

Four things, and they have to happen in this order — each one needs the one
before it:

| # | Where | What | Time |
|---|---|---|---|
| §2b | Azure | a Trusted Signing account, identity validation, a certificate profile | **days** (validation) |
| §2c | Entra ID | an app registration, a federated credential, **and a role assignment** | minutes |
| §2d | GitHub | three secrets, three variables, the `release` environment | minutes |
| §3 | — | tag and watch | minutes |

The two that catch people out, both of which fail long after the step that
caused them:

- **A federated credential authenticates; it does not authorize.** The role
  assignment in §2c is a separate action, and skipping it produces a 403 at
  signing time, after `azure/login` has reported success.
- **Identity validation takes business days.** Nothing else here does.

None of the six GitHub values is a credential that can sign anything on its
own. They are identifiers; authentication happens through a short-lived OIDC
token minted per run, and there is no long-lived Azure secret in the
repository at all.

### 2b. Azure — the signing account itself

**Do this part first.** The federated credential in §2c authenticates an app;
it cannot authenticate it to something that does not exist yet.

**Budget days, not minutes.** Identity validation for a public-trust
certificate is a real legal-entity check against Xtremission LLC, and Microsoft
takes business days over it. Everything else here is minutes. Start the
validation before you need the release.

1. **Register the resource provider**, once per subscription. Without this the
   portal will not offer Trusted Signing at all, and the error it gives does
   not say so:

   ```bash
   az provider register --namespace Microsoft.CodeSigning
   az provider show --namespace Microsoft.CodeSigning --query registrationState
   ```

2. **Create a Trusted Signing account** (the portal may still call it
   *Azure Trusted Signing*; the GitHub Action calls it Artifact Signing — same
   thing). **The region you choose decides the endpoint** you will put in
   `AZURE_SIGNING_ENDPOINT`, and there is no redirect between regions:

   | Account region | Endpoint |
   |---|---|
   | East US | `https://eus.codesigning.azure.net/` |
   | West US 2 | `https://wus2.codesigning.azure.net/` |
   | West Central US | `https://wcus.codesigning.azure.net/` |
   | North Europe | `https://neu.codesigning.azure.net/` |
   | West Europe | `https://weu.codesigning.azure.net/` |

   Read it back rather than trusting the table:

   ```bash
   az rest --method get --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>?api-version=2024-09-30-preview" --query "properties.accountUri"
   ```

3. **Complete identity validation**, under the account. Public Trust requires
   the legal-entity check. A *Test* certificate profile skips it and is useful
   for proving the pipeline works — but a binary signed with a test profile is
   **not trusted by Windows**, and SmartScreen will still warn. Use it to prove
   the plumbing, not to ship.

4. **Create a certificate profile** once validation succeeds. Its name is
   `AZURE_CERT_PROFILE`; the account name is `AZURE_SIGNING_ACCOUNT`.

### 2c. Azure — federated credentials, no stored secret

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

which must produce exactly this subject — check it in the app's federated
credential list afterwards, because a typo here fails as `AADSTS70021`, which
does not mention the subject:

```
repo:suburbazine/Unifi-Notification-Matrix:environment:release
```

**Why an environment and not a tag.** Entra federated credentials do not accept
wildcards in the subject, so `ref:refs/tags/v*` is not expressible — a
tag-based subject would need a new federated credential for every release.
The environment subject is stable and doubles as the approval gate.

**A federated credential authenticates. It does not authorize.** This is the
step most often missed, and it fails as a 403 from the signing endpoint long
after the login step has reported success. On the signing account, **Access
control (IAM) → Add role assignment → Trusted Signing Certificate Profile
Signer**, assigned to that app registration:

```bash
az role assignment create   --role "Trusted Signing Certificate Profile Signer"   --assignee <APP_CLIENT_ID>   --scope "/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>"
```

Role assignments take a minute or two to propagate. A 403 immediately after
creating one is not necessarily wrong yet.

**Nothing in this flow puts a long-lived Azure credential in the repository.**

### 2d. Tell GitHub about it

None of these six values is a signing credential. Three are identifiers that
happen to live in `secrets` because that is the context `azure/login` reads;
three are plain variables.

```bash
gh secret set AZURE_CLIENT_ID        --body "<app registration client ID>"
gh secret set AZURE_TENANT_ID        --body "<Entra tenant ID>"
gh secret set AZURE_SUBSCRIPTION_ID  --body "<subscription ID>"

gh variable set AZURE_SIGNING_ENDPOINT --body "https://eus.codesigning.azure.net/"
gh variable set AZURE_SIGNING_ACCOUNT  --body "<account name>"
gh variable set AZURE_CERT_PROFILE     --body "<certificate profile name>"
```

Then create the environment the credential's subject is pinned to. GitHub will
create it implicitly on the first run, but making it yourself is what lets you
put a human in front of the signing key:

```bash
gh api -X PUT repos/suburbazine/Unifi-Notification-Matrix/environments/release
```

Check it before you tag anything:

```bash
gh secret list && gh variable list
gh api repos/suburbazine/Unifi-Notification-Matrix/environments --jq '.environments[].name'
```

If `gh secret list` is empty, the workflow will fail at `azure/login` with an
empty client id — which reads like a broken action rather than a missing
setting.

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

- **`No subscriptions found for ***.` at the `azure/login` step** — THE FIRST
  FAILURE YOU WILL ACTUALLY HIT, and it does not look like what it is.
  Observed on the first real run of this workflow.

  The federation worked. The log says `Attempting Azure CLI login by using
  OIDC...` and there is no `AADSTS70021`, so the subject matched and the token
  was exchanged. What failed is the step afterwards: `az login` enumerates the
  subscriptions the principal can see, and an app registration with **no role
  assignment anywhere in the subscription** can see none, so the CLI exits 1.

  It is the missing role assignment from §2c, surfacing at login rather than at
  signing. Diagnose it in one command — an empty result is the whole answer:

  ```bash
  az role assignment list --assignee <APP_CLIENT_ID> --all -o table
  ```

  Then create it (§2c), wait a minute or two for propagation, and re-run the
  workflow with `workflow_dispatch` against the same tag.

  If the assignment exists and the subscription still is not found, check that
  `AZURE_SUBSCRIPTION_ID` is in the same tenant as `AZURE_TENANT_ID` -- an app
  in one tenant cannot see a subscription in another.

- **`AADSTS70021` / no matching federated identity** — the subject does not
  match. It must be exactly `repo:OWNER/REPO:environment:release`, and the job
  must actually declare `environment: release`.
- **403 from the signing endpoint** — the app registration is missing the
  *Trusted Signing Certificate Profile Signer* role on the account (§2c), or
  the assignment has not propagated yet. Authentication succeeding tells you
  nothing about authorization; they are separate steps and they fail at
  different points in the run.
- **`azure/login` fails with an empty client id** — the repository secrets are
  not set. `gh secret list` returning nothing is the whole diagnosis (§2d).
- **The endpoint rejects the account** — `AZURE_SIGNING_ENDPOINT` is for a
  different region than the account. There is no redirect between regions
  (§2b).
- **Identity validation still pending** — a certificate profile cannot be
  created until it completes, and it takes business days. A *Test* profile
  proves the pipeline without waiting, but Windows does not trust what it
  signs.
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
