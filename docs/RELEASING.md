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
| Detached signature | cosign (keyless), `.sigstore.json` | cosign (keyless), `.sigstore.json` |
| Transparency log | Rekor | Rekor |
| Build provenance | SLSA, via `gh attestation` | SLSA, via `gh attestation` |
| Optional | — | detached GPG `.asc` |

### cosign — works on any platform, nothing to trust in advance

This is the strongest check, and the one to prefer. It proves **which workflow
in which repository** produced the file. A bare signature only proves somebody
holding a key signed something; this identifies the builder.

Each binary ships with a `.sigstore.json` **bundle** beside it. One file, and
it contains everything the check needs: the signature, the short-lived signing
certificate, and the Rekor inclusion proof. Download it along with the binary.

```bash
cosign verify-blob notifymatrix-linux-amd64 \
  --bundle notifymatrix-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/suburbazine/Unifi-Notification-Matrix/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`Verified OK` means this exact byte sequence was signed by a GitHub Actions run
in this repository, and that the signing certificate is in the public Rekor
transparency log.

> Most cosign instructions written before cosign 3 pass a separate
> `--signature file.sig` and `--certificate file.pem`. Those flags are gone;
> `--bundle` replaces both. Every release of this project publishes bundles.

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
  --bundle SHA256SUMS.sigstore.json \
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

mkdir -p /tmp/rebuild                 # NOT inside the checkout -- see below
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -buildid= -X main.version=1.2.3" \
  -o /tmp/rebuild/notifymatrix-linux-amd64 ./cmd/notifymatrix

sha256sum /tmp/rebuild/notifymatrix-linux-amd64   # compare against SHA256SUMS
```

Two things have to be exactly right, and both fail quietly:

**`main.version` is the tag with its leading `v` stripped.** It is compiled
into the binary, so `1.2.3` and `v1.2.3` give different bytes.

**The checkout has to be clean — including of untracked files.** Go stamps
`vcs.modified` into every binary it builds from a repository, and *any*
untracked file sets it. Writing the output into the checkout is enough to do
it: the build succeeds, and the binary silently differs from the release. It
bites on the second architecture rather than the first, which makes it look
like an arm64 problem. Build somewhere outside the work tree, as above.

### If the hashes do not match

Ask the binary what went into it before assuming the release is wrong:

```bash
go version -m /tmp/rebuild/notifymatrix-linux-amd64   # yours
go version -m ./notifymatrix-linux-amd64              # the downloaded one
```

The two outputs should be identical. In order of likelihood:

- **`vcs.modified=true`, or a `+dirty` suffix on the `mod` line** — your
  checkout is not clean. `git status --porcelain` will show it; untracked
  files count.
- **`mod ... (devel)` instead of a version** — no VCS information reached the
  build at all. A `git worktree`, an export, or a source tarball does this.
  Use a real clone.
- **The `mod` line reads `v0.0.0-<date>-<sha>` where the release says
  `v0.1.3-0.<date>-<sha>`** — your clone has no TAGS. Go derives the main
  module's version from the nearest semver tag it can reach and compiles it
  into the binary, so a shallow or tagless clone produces different bytes from
  identical source. `git clone --depth 1 --branch <tag>` is the usual way to
  arrive here, and it is a tempting shortcut because it is much faster. Clone
  normally and `git checkout` the tag, as above.

  Note that a four-part tag such as `v0.1.2.1` is not valid semver, so Go
  ignores it and bases the pseudo-version on the last three-part tag before it
  — which is why a release tagged `v0.1.2.1` embeds a version derived from
  `v0.1.3`. That is expected, and it is not evidence of anything being wrong.
- **A different `go1.x.y` on the first line** — `.go-version` records the
  toolchain the release used, and it is kept on the **latest** patch of its
  line deliberately: CI runs `govulncheck`, and a Go patch release is the
  usual way a standard-library vulnerability gets fixed under you. The
  toolchain is a build input, so bumping it changes the expected hashes.
- **Identical metadata and different bytes** — now it is worth reporting.

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
| §2b | Azure | an Artifact Signing (formerly Trusted Signing) account, identity validation, a certificate profile | **days** (validation) |
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
control (IAM) → Add role assignment → Artifact Signing Certificate Profile
Signer**, assigned to that app registration:

```bash
az role assignment create \
  --role "Artifact Signing Certificate Profile Signer" \
  --assignee <APP_CLIENT_ID> \
  --scope "/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>"
```

**The role is called *Artifact* Signing, not *Trusted* Signing.** Microsoft
renamed the service and the role name followed, so instructions still carrying
the old name — including some of Microsoft's own — fail with a
`Role ... doesn't exist` error rather than a permissions error.

> If `az` itself reports *The system cannot find the file specified*, that is
> not this command failing. It is `az` not being on `PATH`: the installer adds
> it, but an already-open terminal keeps the environment it started with. Open
> a new one.

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
gh api -X PUT repos/suburbazine/Unifi-Notification-Matrix/environments/release \
  -F wait_timer=0 \
  -F prevent_self_review=false \
  -F can_admins_bypass=false \
  -f 'reviewers[][type]=User' -F 'reviewers[][id]=<YOUR NUMERIC USER ID>'
```

`gh api users/<login> --jq .id` gives the numeric id; the API takes ids, not
logins. See §3 for why `prevent_self_review` stays false and
`can_admins_bypass` does not.

> Required reviewers on an environment need a **public** repository on the
> free plan (this one is), or GitHub Pro/Team/Enterprise for a private one.
> Without it the `PUT` is accepted and the protection rule silently is not.
> Read it back, below, rather than assuming.

Check it before you tag anything:

```bash
gh secret list && gh variable list
gh api repos/suburbazine/Unifi-Notification-Matrix/environments/release \
  --jq '{admins_bypass: .can_admins_bypass,
         rules: [.protection_rules[] | {(.type): [.reviewers[]?.reviewer.login]}]}'
```

That last one must show a `required_reviewers` rule with a name in it. An
empty `rules` list means the gate is not there, whatever the `PUT` returned.

If `gh secret list` is empty, the workflow will fail at `azure/login` with an
empty client id — which reads like a broken action rather than a missing
setting.

---

## 3. Cutting a release

**Check what the next version number is** before anything else. `CHANGELOG.md`'s
`## [Unreleased]` section says so when it has been decided in advance, which is
the only place that decision survives between sessions. Do not infer it from
the size of the diff.

**Write the changelog entry as the work merges**, under `## [Unreleased]`, not
on the day you tag. Writing a whole section from memory at tag time is how
0.1.8 nearly shipped without one.

At release, rename that heading to the version and add its compare link:

```bash
$EDITOR CHANGELOG.md          # [Unreleased] -> [1.2.3] - <date>, add the link
scripts/changelog-section.sh v1.2.3   # what the release page will say
git commit -am "Changelog for v1.2.3"
git push
```

`CHANGELOG.md` must have a `## [1.2.3] — date` section before the tag exists.
The workflow refuses to build a tag without one.

Then tag:

```bash
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

The workflow then:

1. **changelog** — extracts this version's section, and **fails if there is
   not one**. It runs first, before anything is built, so a forgotten entry
   costs a commit rather than a second trip through the signing approval and
   a dead tag. The section becomes the top of the release notes.
2. **verify** — `go vet` and `go test -count=2` on Linux *and* Windows. The
   secret store is a different implementation per OS, so both must run.
3. **build** — `linux/amd64`, `linux/arm64`, `windows/amd64`, reproducibly.
4. **sign-windows** — **pauses for your approval** (see below), then
   Authenticode via Azure, then asserts the signature is `Valid` *and*
   timestamped before continuing.
5. **release** — checksums, SLSA provenance, keyless cosign bundles, optional
   GPG, and a **draft** release.

### Why the changelog is a gate rather than a habit

Until 0.1.8 the release notes carried the verification instructions and nothing
else, so the page told somebody how to check a binary was authentic without
telling them what was in it. `generate_release_notes` does not fix that: commit
subjects are written for this repository, not for somebody arriving at a
download page, and half of them are about tests.

An entry that is optional is an entry that gets skipped on exactly the release
that most needed one — the rushed fix at the end of a long day. So it is
checked by a job, and the job runs before the certificate is involved.

The release is a draft on purpose: look at it before it is public.

### The run will stop and wait for you

`sign-windows` declares `environment: release`, and that environment has
**required reviewers**. So the run gets as far as the three builds and then
parks at status `waiting`, with the signing job un-started. GitHub emails you;
the run page shows **Review deployments → Approve and deploy**.

Nothing has touched the certificate at that point. This is the whole reason
the gate exists: pushing a tag should not be sufficient, on its own, to sign
something with a publicly-trusted code-signing certificate in the name of a
real legal entity. The tag says *what* to build; the approval says *yes,
really, sign it*.

> **An agent may click it on the maintainer's behalf, and only when asked to
> do something that requires it** — "publish it", "cut a release". The rule is
> in `CLAUDE.md`, and it is stated here too so this section does not overclaim:
> a deployment record showing an approval does **not**, by itself, prove a
> human looked. "Push it" does not carry that permission, and neither does a
> release nobody asked for.
>
> What the gate still buys, under that rule, is that the instruction and the
> signature are separate events with a named decision between them — and that
> a run started by anything other than a person asking for one stays parked.

Two settings on that environment are load-bearing and easy to get wrong:

- **`prevent_self_review` must stay off.** With one maintainer, turning it on
  means nobody is left who can approve, and releases block forever.
- **`can_admins_bypass` is off**, deliberately. Left at its default the rule
  is advisory — an admin skips it. Since the admin and the reviewer are the
  same person here, bypassing and approving cost the same click; only one of
  them is a decision.

Between signing and publishing, the workflow runs §1's `cosign verify-blob`
command — identity constraint and all — against every artefact it just signed.
A verification recipe is otherwise the one part of a release nobody exercises
until an outsider tries it, and by then a wrong flag reads to them as *this
binary is not what it claims to be*.

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
  *Artifact Signing Certificate Profile Signer* role on the account (§2c), or
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
