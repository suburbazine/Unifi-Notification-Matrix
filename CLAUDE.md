# Working in this repository

## What the release words mean

These are the maintainer's words, and they mean exactly this much. Do not
widen them.

| Said | Means | Stops at |
| --- | --- | --- |
| **push it** | `git push` the branch. Commits go up. | No tag, no build, no binary, no signing. |
| **cut it**, **cut a release**, **publish it**, **ship it** | The whole release: changelog heading, tag, build, **approve the signing gate**, and publish the release so it is no longer a draft. | A published release, verified. |

"Push it" **never** starts a build. If a push would trip a release workflow,
say so and stop rather than letting it run.

## The signing gate

`sign-windows` runs in the `release` environment, which has required
reviewers, so a tagged run parks at `waiting` until somebody approves. The
approval is the sentence *yes, really, sign this with a publicly-trusted
certificate in the name of a real legal entity*.

**You may approve it — and only — when the maintainer has asked for something
in this session that cannot be finished without it** ("publish it", "cut a
release"). That instruction is the approval; clicking is carrying it out.

```bash
gh api -X POST repos/suburbazine/Unifi-Notification-Matrix/actions/runs/<id>/pending_deployments \
  -f environment_ids='[<id>]' -f state=approved -f comment='<why>'
```

`environment_ids` must be a real JSON integer array.

**Do not approve:**

- a run nobody asked you to make — including one you tagged on your own
  initiative;
- a run whose tag is not the commit the maintainer's instruction produced;
- a run where the changelog, the version or the diff is not what you expect —
  say what is off and ask, because the gate exists for precisely that;
- anything after the instruction has been satisfied. Permission does not
  carry into the next release.

**Say that you approved it, in the reply.** The deployment record will claim a
human approved; the only place that can be corrected is what you tell the
maintainer.

## Releasing

`docs/RELEASING.md` §3 is the procedure. Two things it says that are easy to
get wrong:

- **Read the next version out of `CHANGELOG.md`'s `[Unreleased]`.** Never
  infer it from the size of the diff. If it has not been decided, ask.
- **`gh release publish` does not exist.** Use
  `gh release edit <tag> --draft=false`, and then check `isDraft` rather than
  the exit code — a release that is still a draft is not published, whatever
  the command returned.

## Tests

A green test proves nothing until you have watched it go red. When you add
one, break the thing it covers and check that it actually catches it — and
prefer a mutation that still compiles, because one that does not is a build
error rather than a result.

Test the decision, not the renderer: passing the right value into a function
and checking the output says nothing about the code that chooses the value.

## The interface

Render the page. Do not read it and conclude. Several bugs in this repository
were invisible to every passing test and obvious in a browser within seconds.
