---
name: autoreview
description: "Closeout code review with a structured second-model pass. Use after non-trivial changes or when the user asks for autoreview, Codex review, or a review panel."
---

# Auto Review

Run the repo's bundled structured review helper after the nearest owning proof.
Codex is the default reviewer; set `AUTOREVIEW_ENGINE=claude` (or pass
`--engine claude`) when Codex is unavailable. Review findings are advisory; the
task, owning code and contracts, and their nearest checks remain authoritative.

## Closeout

1. Record the baseline: user request, violated invariant, owner boundary,
   intended behavior, and target ref. Completion means a finding can be
   classified without silently broadening the task.
2. Run the nearest focused checks with the repo's own scripts. Completion means
   the pre-review proof is current. Full proof for this repo:

   ```bash
   npm run lint && npm run lint:eslint && npm run format:check && npm run build && npm test
   ```

   - `npm run lint` is the typecheck (`tsc --noEmit`); ESLint is `npm run lint:eslint`.
   - `npm run format:check` covers Markdown and JSON as well as TypeScript.
   - Build before the test suite, as CI does: `npm run build && npm test`. Workspace packages resolve through `dist`, so a stale build hides or invents failures.
   - Focused tests: `npm test -- packages/server/src/routes/data.test.ts`.
   - E2E is separate and slower: `npm run test:e2e`.

3. Select the review target:

   ```bash
   # Dirty staged, unstaged, and untracked work
   .agents/skills/autoreview/scripts/autoreview --mode local

   # Feature/PR branch; PRs in this repo target main
   .agents/skills/autoreview/scripts/autoreview --mode branch --base origin/main

   # One committed change
   .agents/skills/autoreview/scripts/autoreview --mode commit --commit HEAD

   # Exact commit-to-commit diff (no merge-base expansion)
   .agents/skills/autoreview/scripts/autoreview --mode range --base <base> --head <head>
   ```

   For an open PR, use its actual base (the helper asks `gh pr view` when no
   `--base` is given). Branch mode requires a clean worktree; local changes
   belong in local mode. Commit mode reviews merge commits against their first
   parent. A clean local review proves only that no local patch exists.

4. Adjudicate every finding against the real code path, adjacent files,
   dependency contracts, and repo doctrine. Completion means each finding is
   accepted with evidence or rejected with a one-line reason.
5. Classify accepted findings before editing:
   - **In-scope blocker**: same invariant and owner neighborhood; fix it.
   - **Follow-up**: real, but a different owner or bug class; report it.
   - **Stop-and-escalate**: changes protocol, storage, public API, on-chain or
     gateway contract, release process, or another owner's boundary; request
     direction.

6. After an in-scope fix, rerun affected focused proof and autoreview. After two
   review-triggered patch cycles without convergence, pause and reclassify all
   remaining findings. Continue only when every remaining item is still an
   in-scope blocker.
7. Stop on the first clean helper exit. Report the command, proof run,
   accepted/rejected findings, and clean result.

## Finding Threshold

The helper defaults to P0: issues that block the current change because they
materially break its normal flow, outcome, or safety boundary. Broaden only on
explicit request:

```bash
.agents/skills/autoreview/scripts/autoreview --mode branch --base origin/main --max-priority P1
```

P2/P3 polish and speculative hardening are not blockers by default. Security
findings must name a concrete risk or removed safety check; security-adjacent
functionality alone is not a defect.

## Repo Boundaries

- The touched path and owning code select scope; the nearest real oracle proves
  behavior. A clean source review never replaces required runtime, integration,
  e2e, or generated-file proof.
- Fix the root cause across relevant siblings inside the same owner boundary.
  Keep unrelated cleanup out of the landing lane.
- PRs target `main`. `dev`/`develop` and `feat/*` publish canary prereleases. Review never authorizes push, merge, release, or tag
  actions.
- On release, hotfix, or publish work, apply freeze discipline: fix only the
  release blocker, exact backport, crash, data-loss, upgrade breakage, or
  concrete security exposure. Route other findings to follow-up work.
- Prose-only skill/docs changes may skip the model review, but still run their
  nearest lightweight check (Prettier where it covers Markdown). Executable
  examples, scripts, configuration, generated files, and user-facing docs do
  not qualify.

## Panels

Panels are opt-in. Use them only when requested or when the risk justifies the
extra cost:

```bash
.agents/skills/autoreview/scripts/autoreview --mode branch --base origin/main --panel
```

The main agent still adjudicates every merged finding. Never push merely to make
a review possible.

## Self-check

The helper's target-selection logic has unit tests; run them after editing the
script:

```bash
python3 .agents/skills/autoreview/tests/test_autoreview.py
```

`scripts/test-review-harness` builds a throwaway repo with a deliberately unsafe
patch (or a safe security-adjacent one) and checks that a selected engine
reports, or correctly does not report, findings.
