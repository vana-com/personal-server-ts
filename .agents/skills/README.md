# Skills

Tracked skill files under `.agents/skills` are optional technique for repeated,
non-obvious work in personal-server-ts. They are reviewed like any other repo code.
Use one only when the request or exact task matches its description; the code,
tests, and package scripts remain the primary map.

Claude availability: each skill is exposed to Claude Code through a committed
per-skill symlink `.claude/skills/<name> -> ../../.agents/skills/<name>`. Add
the symlink when adding a skill; do not copy skill bodies into `.claude/skills`. `.claude/agents/` holds Claude Code
subagent adapters (currently `test-reviewer`).

Review workflow skills (`autoreview`, `code-review`, `bug-repro-test-first`,
`atomic-commit-slicing`) and the `test-reviewer` agent were ported from
`vana-com/unity-surfaces` and adapted to this repo's npm, ESLint, Prettier, and
Vitest toolchain. Keep them in sync with the upstream intent when editing; keep
the commands in sync with `package.json`.
