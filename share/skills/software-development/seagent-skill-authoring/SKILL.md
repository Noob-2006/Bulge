---
upstream: "hermes-agent/skills/software-development/hermes-agent-skill-authoring (MIT) — adapted for seagent"
name: seagent-skill-authoring
description: "Write SKILL.md files for seagent: frontmatter, tiers, structure."
version: 1.0.0
author: SE Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [skills, authoring, conventions, skill-md, seagent]
    category: software-development
---

# Authoring SE Agent skills

## Overview

There are two places a `SKILL.md` can live, and they have different rules:

1. **User-local** — `<data>/skills/<name>/SKILL.md` (on a default install: `~/.local/share/seagent/skills/…`, see `crates/seagent-skills/src/skill.rs::user_dir`). Personal, never shipped. Written by the `skill` tool (`action=create`), by `seagent skills install`, or by `seagent skills sync` (which copies bundled skills here); `/learn` writes into the workspace's `.seagent/skills` instead.
2. **In-repo** — `share/skills/<category>/<name>/SKILL.md` (bundled with the binary) or the optional catalog `share/optional-skills/index.json` (fetched on demand from upstream). Committed, reviewed, shipped. The `skill` tool never writes here.

This skill is about the in-repo case. Skills are discovered from `<ws>/.seagent/skills`, `<ws>/.claude/skills`, `<ws>/.agents/skills`, `<data>/skills`, then `share/skills`, then extra dirs (`[skills] external_dirs`); the first root that defines a name wins, and the category is whatever directory sits between the root and the skill dir (nested up to four levels deep).

## When to Use

- The user asks you to add, port or fix a skill in this repo, or to "make this workflow reusable".
- You are moving a procedure out of a conversation into something a future session can load.
- You are reviewing a skill PR against the repo's authoring standards.

Don't use for: personal notes-to-self in `<data>/skills` — just call the `skill` tool and let the linter stay out of it.

## Decide the Tier First: Bundled vs Optional

- **Bundled (`share/skills/<category>/`)** — daily-driver behaviour, broadly useful, low context cost. Hard bar: you can say "a user will load this in 5+ sessions per month" with a straight face.
- **Optional (`share/optional-skills/index.json` + upstream)** — niche, vertical-specific, one-app, heavy, or a recurring job. These are not vendored: the catalog ships only `index.json`, whose entries carry `name`, `path`, `description`, `tags`, `files`; install is `seagent skills install official/<path>` where `<path>` is the entry's `path` field (`<category>/<name>`), and the content is fetched from the upstream repo on demand (`crates/seagent-skills/src/hub/sources.rs`).

**When in doubt, optional.** Promoting later is cheap; demoting is churn. "Useful to anyone who ever needs it" is an optional-tier argument, not a bundled one.

Pick the category by what the tool IS, not by what it feels like — an agent CLI goes in `autonomous-ai-agents/` even if it "feels productivity". Existing categories in this tree: apple, autonomous-ai-agents, creative, custodian, devops, email, media, note-taking, openclaw, productivity, research, social-media, software-development, web. Confirm with `seagent skills list` before inventing one.

**No router / index / hub skills.** If the body would be a routing table pointing at sibling skills, don't write it: the prompt's skill index and each sibling's own triggers already do that job. Same for a skill that only restates another skill with a tweak — extend the original.

## Required Frontmatter

The parser is `crates/seagent-skills/src/yaml.rs`: a YAML *subset* — block mappings and sequences, flow `[..]`/`{..}`, quoted and plain scalars, `|`/`>` block scalars, comments, a single document. **No anchors, no tags, no multi-document streams.** Keep frontmatter to scalars, flow lists and one nested mapping.

```yaml
---
name: my-skill-name            # lowercase; must equal the directory name
description: Concise capability statement, under sixty chars.
version: 1.0.0
author: Real Name (github-handle), seagent
license: MIT
platforms: [linux, macos, windows]
metadata:
  seagent:
    tags: [Short, Descriptive, Tags]
---
```

Hard requirements, in order of how badly they bite:

- The file must start with `---` as its first bytes, and the block must close with a line that is exactly `---` (or `...`). `split_frontmatter` finds the first such line; anything else and the whole file becomes the body.
- The block must parse to a **mapping**. If it does not, `frontmatter()` silently returns an empty object and the file is treated as body-only — a typo costs you `name`, `description` and every gate below, with no error. Validate after every edit.
- `name` — otherwise the directory name is used. `skill.rs::valid_name` allows lowercase letters, digits, `-`, `_`, `.`, at most 64 chars, and no leading `.` or `-`. The linter is stricter: `^[a-z0-9][a-z0-9_-]*$` (no dot, no underscore start) and it errors when `name` ≠ directory name.
- `description` — kept to 1024 chars in the index (`MAX_DESCRIPTION`), but see below.
- Non-empty body.

### `description` rules (HARDLINE — 1024 is not the standard)

- **≤ 60 characters, one sentence, ends with a period.** The prompt's skill index cuts at 60 chars plus `...` (`core/index.rs::DESC_LIMIT`), and the linter warns at 60 — the trigger must survive inside that window.
- State the capability, not the implementation, and don't repeat the skill name.
- No marketing words — the linter has a list (`powerful`, `comprehensive`, `seamless`, `advanced`, `cutting-edge`, `state-of-the-art`, `revolutionary`, `robust`).
- A `:` inside the value needs double quotes or YAML reads a mapping. Quotes don't count toward the 60.

### `author` and metadata rules

- Credit the **human first**, then the tool: `Ben Barclay (benbarclay), seagent`. Never `author: seagent` alone on a contributed skill.
- `version`, `author`, `license` and `metadata.{seagent,hermes}.tags` are expected; the linter warns for each missing one. Ported skills keep `metadata.hermes` (upstream frontmatter is preserved verbatim, with `upstream:` prepended by `tools/port/port_skills.py`); seagent-only skills use `metadata.seagent`. Both are accepted by `lint.rs` and by the hub's tag reader.
- Ported skills must keep the `upstream:` line naming the source repo and `(MIT)`.

## Platform Gating: audit, don't trust

`platforms:` is metadata, not enforcement: SE Agent loads a skill on any OS, and the linter only checks the values are in `[linux, macos, windows, darwin]` and that scripts using POSIX primitives (`fcntl`, `termios`, `os.setsid`, `signal.SIGKILL`, `osascript`, `/proc/`, `apt-get`, `systemctl`) declare `platforms:` at all. So set it from what the prose and scripts actually invoke, and gate at run time in the body:

| Skill uses only… | `platforms:` |
|---|---|
| seagent tools, cross-platform CLIs | `[linux, macos, windows]` |
| bash pipelines, heredocs, `/proc`, `systemctl` | `[linux, macos]` |
| `osascript`, `defaults`, `pmset` | `[macos]` |
| `apt`, `systemd`, `/proc` | `[linux]` |

Default posture: fix cross-platform first (temp dirs, path libraries, pid checks); narrow the gate only when the dependency is genuinely platform-bound, and say why in `## Pitfalls`.

## Size Limits

- The `skill` tool refuses a body over 20,000 chars and a description over 300 chars or spanning lines; it stores one line of frontmatter (`name`, `description`) and nothing else — richer frontmatter means editing the file directly.
- The linter warns above 24,000 chars of body (`BODY_SOFT_BUDGET_CHARS`): loading a skill puts all of it in context for the rest of the session. Target ~100 lines for a simple skill, ~200 for a complex one.
- Bulky or branch-specific material goes in `references/*.md`, `templates/` or `scripts/` next to `SKILL.md`, pointed to by relative path — not inlined. The linter warns on `references/<path>` that does not exist, and on more than 60 files under `references/`.
- Don't expect the model to inline-write parsers each call: ship a helper in `scripts/` and reference it by path.

## Body Structure

```
# <Skill> Skill
2-3 sentence intro: what it does, what it doesn't do, dependency stance.

## When to Use          — bulleted triggers (+ "Don't use for:" counter-triggers)
## Prerequisites        — exact env vars, installs, credential sourcing
## How to Run           — canonical invocation through seagent's tools
## Quick Reference      — flat command list, no narration
## Procedure            — numbered steps, each with a checkable completion criterion
## Pitfalls             — known limits, things that look broken but aren't
## Verification         — how to prove the skill worked
```

Missing `## When to Use` is a lint warning; the rest is judgement. When to Use + actionable body + Pitfalls + Verification is the minimum. Cut marketing intros and re-explanations of what Prerequisites already says.

### Reference seagent's tools, not raw shell

Name the tool the agent actually has, in backticks — `read`, `write`, `edit`, `patch`, `glob`, `shell`, `job`, `web_fetch`, `memory`, `skill`, `spawn`, `todo`. The linter flags prose that names a shell utility instead:

```
grep, rg        → grep tool
cat, head, tail → read
sed, awk        → edit / patch
find, ls        → glob
```

A CLI-wrapper skill frames invocations as `shell(command="foo --version")`, not "run `foo --version`". If the skill needs an MCP server, name it and document setup in Prerequisites (`seagent mcp add …`).

### Never use machine-local paths

Write repo-relative paths (`share/skills/...`, `crates/seagent-skills/src/skill.rs`) or describe the location (`<data>/skills`, `$SEAGENT_SHARE_DIR`). A `/home/<you>/…` path baked into a committed skill is an instant review flag.

## Writing Quality Principles

1. **Optimize for process predictability.** If a line does not change behaviour, cut it.
2. **Choose the right context load.** The description is paid every turn; depth goes in the body or a linked reference.
3. **End steps with completion criteria.** "every modified file accounted for" beats "summarize changes".
4. **Co-locate rules with the concept they govern.**
5. **Use strong leading words** ("tight loop", "root cause", "regression test") over long explanations.
6. **Prune duplication and no-ops.** "Be careful" and "best practices" don't change model behaviour — replace with a checkable criterion or delete.
7. **No invented commands.** Every command, flag, endpoint and config key must appear verbatim in this tree. If it isn't there, it doesn't go in the skill.

## Tests and Docs

- There is no docs generator and no required per-skill test file. The gate is the linter plus a reviewer: `seagent skills lint <path>` must be free of `ERROR` findings (it exits non-zero only on errors; warnings are the review conversation).
- `cargo test -p seagent-skills` covers the frontmatter parser, the linter and the sync/install paths — run it if you touched frontmatter parsing or added a new frontmatter shape.
- The bundled tree is **generated**: `tools/port/port_skills.py <hermes> <openclaw> <share>` rebuilds `share/skills` from the upstream checkouts and prepends `upstream:` to each SKILL.md. A hand-added seagent-only skill under `share/skills` will be deleted by the next regen unless the script keeps it — confirm that before you rely on it, and prefer fixing the generator over hand-patching its output.

## Workflow

1. **Survey peers** in the target category (`glob share/skills/<category>/*/SKILL.md`) and read two or three to match tone and structure. Prefer extending a skill over adding a narrow sibling.
2. **Decide tier and category** (above). When in doubt, optional — and ask before pushing rather than defaulting.
3. **Draft** the file at `share/skills/<category>/<name>/SKILL.md` (or the optional source tree), with a body that starts at the first `#` heading.
4. **Validate**:
   ```bash
   seagent skills lint share/skills/<category>/<name>
   seagent skills view <name>          # frontmatter parsed, body intact
   seagent skills list --source builtin
   ```
   `seagent skills view` printing an empty description or a body that starts with `name:` means the frontmatter did not parse.
5. **Confirm discovery**: the new skill appears in the list above with the expected source. A running daemon picks it up without a restart — the prompt carries a per-turn delta note announcing skills that appeared after the prompt was built.
6. **Commit** the new directory only; check the diff contains no unrelated skill churn.

## Editing Existing Skills

- **Small fix** — `edit`/`patch` the file on disk; in-repo skills are source.
- **Your own user-local skill** — the `skill` tool `action=update` rewrites the body and description; `action=archive` retires it (it moves the directory aside, never deletes).
- **A bundled skill you customised** — user copies live in `<data>/skills`; `seagent skills sync` updates only copies you haven't edited, `seagent skills diff <name>` shows the drift, `seagent skills reset <name>` restores the shipped version. Editing the bundled copy in `share/skills` changes it for every user.
- **Always commit** in-repo changes; re-run the linter after any frontmatter edit.

## Common Pitfalls

1. **Using the `skill` tool for an in-repo skill.** It writes to `<data>/skills`, never to `share/skills`.
2. **Trusting the parser's silence.** Invalid frontmatter degrades to an empty object with no error; the symptom is a skill whose description is blank in the index.
3. **Trusting 1024 as the description standard.** The index keeps 60; the rest is invisible to routing.
4. **`author: seagent` on a contributed skill.** Credit the human first.
5. **Description too generic, or the trigger buried past char 60.**
6. **A `name` that differs from the directory name** — an error in the linter, and the index will disagree with the path.
7. **Duplicating a peer.** Survey the category first.
8. **Hand-editing generated output** and losing it to the next `tools/port/port_skills.py` run.
9. **Assuming `platforms:` stops loading.** It is advisory; guard in the body.
10. **Letting a skill accumulate sediment.** When adding a rule, remove the wording it replaces.

## Verification Checklist

- [ ] Tier decided deliberately (bundled bar: 5+ sessions/month; else optional)
- [ ] File at `share/skills/<category>/<name>/SKILL.md`, `name` == directory
- [ ] Frontmatter starts at byte 0 with `---` and closes with `\n---\n`
- [ ] Frontmatter is a plain mapping (no anchors, tags or multi-doc)
- [ ] `name`, `description`, `version`, `author`, `license`, `platforms`, tags all present
- [ ] Description ≤ 60 chars, one sentence, ends with a period, no marketing words
- [ ] `author` credits the human first; ported skills keep the `upstream:` line
- [ ] `platforms:` audited against the actual prose and scripts
- [ ] Body follows the section order and has `## When to Use`
- [ ] Every command, flag and key appears verbatim in this tree
- [ ] Tools named, not shell utilities; no machine-local paths
- [ ] Each ordered step has a checkable completion criterion
- [ ] `seagent skills lint <path>` has no ERROR findings
- [ ] Regeneration impact checked if the skill lives in generated `share/skills`

## Adaptation note

Adapted from Hermes' `hermes-agent-skill-authoring` skill (MIT); the reasoning, the hardline rules (when in doubt optional, category by what the tool is, no invented commands, ≤60-char descriptions, no router skills) and the section order are upstream's. The mechanics were re-targeted and verified here:

- **Paths** — upstream `~/.hermes/skills` / `skills/` / `optional-skills/` become `<data>/skills` (`skill.rs::user_dir`), `share/skills/<category>/<name>/SKILL.md`, and `share/optional-skills/index.json`; install identifiers are `official/<path>` (`hub/sources.rs`).
- **CLI verbs** — upstream `hermes skills install official/…` and `search_files` become the verbs that exist in `crates/seagent-skills/src/hub/cli.rs`: list, view, search, browse, inspect, install, uninstall, check, update, audit, lint, setup, sync, reset, list-modified, diff, opt-out, opt-in, repair-official, publish, snapshot, tap, config, trust, usage, blueprint, ledger, rollback.
- **Validator** — upstream's `_validate_frontmatter` is replaced by `skill.rs` + `yaml.rs` (name/description limits, subset parser, silent degradation) and `core/lint.rs` (the advisory rules cited above).
- **Extras with no upstream analogue** — the `skill` tool's 20k body cap, the live skills-index delta note, and the generated bundled tree (`tools/port/port_skills.py`).
