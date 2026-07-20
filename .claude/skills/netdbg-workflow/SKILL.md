---
name: netdbg-workflow
description: The required workflow for the network-debugger repo — how to track work as GitHub issues, what granularity to file them at, and how to land changes via PRs with gates and post-merge monitoring. Use at the START of any working session in this repo, before writing code, and whenever an idea or bug surfaces mid-work that should be captured rather than carried in conversation.
---

# network-debugger working process

This repo's work is tracked in GitHub issues and lands through gated PRs. Both exist for
one reason: **context gets cleared, and sessions end.** Anything held only in conversation
is lost. Issues are the durable memory; PR gates are the durable quality floor.

## At the start of every session

1. `./scripts/issues.sh list` — see open work.
2. `./scripts/pr.sh may-i-merge` — check whether self-merge is authorized. **This is
   per-session and off by default.** Do not assume a previous session's grant carries over;
   ask the user if it returns "no" and merging would otherwise block progress.
3. `git status` and `gh pr list` — check for work left in flight.

## Issues

`./scripts/issues.sh` wraps `gh`. Commands: `list`, `get <n>` (body + comments), `new`,
`comment`, `edit`, `close`, `labels`.

Labels: `agent`, `server`, `dashboard`, `wifi`, `infra`, `bug`, `idea`, `hardware-verify`.

### Granularity

File an issue at the level of **one reviewable PR** — a coherent unit with its own tests
and a definable green state. "U4: agent spool + shipper" is right. "Add a function" is too
small; "build the agent" is too big.

Every issue body should carry enough context to act on it **cold**, months later, with no
memory of this conversation:
- What to build, concretely.
- *Why* it is designed that way — especially where the obvious approach is wrong. These
  are the parts nobody can reconstruct from the code.
- A **green when** line: the observable condition that closes it.

### File immediately, don't carry it

The rule that matters: when something surfaces mid-implementation that we decide not to do
now — a false-positive case, a platform quirk, a dashboard idea, a shortcut taken — file it
**at that moment** with `idea` or `bug`. Do not hold it until the end of the task; that is
exactly what gets lost. A one-line issue that exists beats a perfect one that never got
written.

Prefer commenting on an existing issue over opening a near-duplicate. Close issues as the
work merges, with a note on what actually shipped if it diverged from the plan.

## PRs

`./scripts/pr.sh` wraps the whole cycle. **Never push to `main` directly.**

```
./scripts/pr.sh check                          # run the full gate locally, first
git checkout -b u4-agent-spool
# ...work, committing as you go...
./scripts/pr.sh create "U4: agent spool" --closes 4
./scripts/pr.sh merge                          # only if may-i-merge says yes
```

`check` mirrors `.github/workflows/ci.yml` exactly: ruff lint, ruff format, mypy strict,
pytest. Run it before opening a PR — a local red is far cheaper than a CI red. `create`
runs it automatically and refuses to open a PR that fails.

### Gates and failures

The `static-checks` job is a required check. **A failing gate or a failing post-merge
action is debugged immediately, not deferred** — a red main blocks everyone's next merge
and the cause is freshest right now.

After merging, `merge` watches the resulting main run to completion. A merge is not done
until that run is green. If it fails, fix it before starting anything else.

### Verify enforcement by attempting it, not by reading config

`main` is protected with `static-checks` required and `enforce_admins: true`. That last
flag is load-bearing: with it `false`, an admin-scoped token's direct pushes are let
through with a `Bypassed rule violations` *warning* rather than rejected — so the API
returns a protection config that looks correct while nothing is actually blocked.

A correct rejection looks like:

```
remote: error: GH006: Protected branch update failed for refs/heads/main.
 ! [remote rejected] HEAD -> main (protected branch hook declined)
```

The general lesson, which cost a stray commit on `main` to learn: when verifying that a
guard works, **attempt the thing and check the resulting state.** Empty or ambiguous
command output is not evidence of a block. `git rev-parse origin/main` tells the truth.

### Scope

One PR per working chunk — a feature that stands on its own and passes its gate. Do not
bundle unrelated changes; it makes review and any later revert worse.

## Tests are the gate

New code lands with tests. For this project specifically:
- **Parsers** are pure functions tested against committed real-command-output fixtures, so
  platform code is verifiable without that platform. Every parser needs a test proving it
  returns a degraded result rather than raising on malformed input.
- **Detection rules** are tested over synthetic sample sequences, including explicit
  false-positive scenarios asserting an event is *absent* or downgraded.
- **Time handling** is tested against simulated NTP steps and wake-from-sleep.

Anything genuinely requiring hardware gets the `hardware-verify` label and a manual
checklist entry rather than a skipped test.
