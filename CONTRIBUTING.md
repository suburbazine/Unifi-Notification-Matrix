# Contributing

This is a **source-available** project with one maintainer, not a community
project looking for committers. That shapes what is useful to send and what is
likely to be declined, and it is fairer to say so here than after you have
spent a weekend on something.

The most valuable contributions to this project are not code.

## What is wanted most

**1. Security reports.** They go to [SECURITY.md](SECURITY.md), not here —
mail `licensing@xtremission.com` with *security* in the subject, or use
GitHub's private advisories. Not a public issue.

**2. Probe reports.** UniFi's event surfaces are version-gated and change
between firmware revisions; Protect's vocabulary went from 16 event types to
39 in one such change. Nothing fixes that except seeing what real consoles
actually send.

```
notifymatrix probe --host 192.168.1.1
notifymatrix probe submit
```

The second command prints the entire file first so you can read the exact
bytes before deciding. **If anything in it identifies your site, that is a bug
in this tool and reporting it matters more than the contribution does.**

**3. Bug reports from real installations.** Especially anything about the
things that cannot be tested here: firmware revisions nobody has, a UniFi
appliance surviving a firmware upgrade, a console configuration that is not
the one this was built against.

**4. Corrections to the documentation.** If a page told you something that
turned out to be false, that is a defect in the page and worth an issue even
if you already worked around it.

## What is likely to be declined

- **Features nobody discussed first.** Open an issue before writing the code.
  The answer may be "that belongs in the commercial product" or "that was
  tried", and both are cheaper to hear before the work than after.
- **Changes that reverse a rule in [docs/DESIGN-RULES.md](docs/DESIGN-RULES.md)
  without arguing with its reason.** Most of those rules look like
  over-engineering until the failure they prevent happens. The reason is the
  part to argue with; "this could be simpler" on its own is not an argument.
- **New dependencies**, particularly anything that needs cgo. Builds are
  `CGO_ENABLED=0` by design: static binaries, and releases reproducible enough
  that a reader can check a published binary against its tag.
- **Style-only churn.** `gofmt` is the standard and CI enforces it. Beyond
  that, matching the surrounding code beats improving it.

## What happens to code you send

This matters more here than in most repositories, so it is stated plainly
rather than buried.

This project is licensed under
[PolyForm Noncommercial 1.0.0](LICENSE.md), and Xtremission LLC separately
sells commercial licences to it. A contribution offered only under the
repository's own licence could not be included in those, which would mean
rewriting your work rather than merging it.

**By opening a pull request you confirm that:**

- the contribution is yours to give, and nobody else — an employer, a client —
  owns it; and
- you grant Xtremission LLC a perpetual, worldwide, irrevocable, royalty-free
  right to use, modify, sublicense and relicense it, including in commercially
  licensed versions of this product.

You keep your copyright. For anything substantial you may be asked to confirm
the above in writing before it is merged.

**If you cannot grant that, say so in the issue and do not send the patch.** A
clearly described bug is worth more than a patch that cannot be merged, and it
can be reimplemented without the question ever arising.

## Running the checks before you open a pull request

Requires Go **1.26.8** (`.go-version`). CI runs all of this on Linux *and*
Windows and both must pass — the secret store has an entirely different
implementation per platform, so cross-compiling proves only that it compiles.

```bash
gofmt -l .                  # must print nothing
go vet ./...
go test -count=2 ./...      # twice: a test that passes once and fails the
                            # second time has hidden state
go mod tidy                 # must leave go.mod and go.sum unchanged
```

```bash
CGO_ENABLED=1 go test -race -count=1 ./...
```

The race job is the one place cgo is deliberately on. It builds nothing that
ships, and the concurrency here is load-bearing: a shared per-console pacer, a
bounded per-channel delivery queue, and a store that ingest, the scheduler and
the interface all touch at once.

**Tests are expected to have been watched failing.** A green test proves
nothing until you have seen it go red for the reason you think it covers. If
you are adding one, break the code it covers once and check that it actually
catches it.

## Changelog

Anything a user would notice gets an entry under `## [Unreleased]` in
[CHANGELOG.md](CHANGELOG.md), written for somebody deciding whether to
upgrade rather than for somebody reading the diff.

The release workflow **refuses to build a tag with no section**, so this is a
hard requirement rather than a courtesy — but land the entry with the change,
not at tag time. Writing a release's notes from scratch on the day is how
0.1.8 nearly shipped without any.

## Code of conduct

There isn't one, deliberately. A code of conduct governs a community, and a
document promising enforcement that nobody is staffing is worse than no
document. Be civil; that is the whole of it. If this ever grows a community,
it grows one of those too.

## Licensing and commercial use

Noncommercial use is granted by the licence. Commercial use — deploying it at
a business, delivering a paid service with it, bundling it into something you
sell — needs a separate licence: **licensing@xtremission.com**.

GitHub labels this repository "Other" because PolyForm is not an OSI-approved
licence. That is expected, not an error, and it is the honest label: this is
source-available, not open source.
