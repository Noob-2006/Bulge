---
upstream: "openclaw/skills/coding-agent (MIT)"
name: coding-agent
description: "Delegate coding work to Codex, Claude Code, or OpenCode as background workers; not simple edits or read-only code lookup."
homepage: https://github.com/openclaw/openclaw
metadata:
  {
    "openclaw":
      {
        "emoji": "🧩",
        "requires": { "anyBins": ["claude", "codex", "opencode"] },
        "install":
          [
            {
              "id": "node-claude",
              "kind": "node",
              "package": "@anthropic-ai/claude-code",
              "bins": ["claude"],
              "label": "Install Claude Code CLI (npm)",
            },
            {
              "id": "node-codex",
              "kind": "node",
              "package": "@openai/codex",
              "bins": ["codex"],
              "label": "Install Codex CLI (npm)",
            },
          ],
      },
  }
---

# Coding Agent

Use for background feature builds, PR reviews, large refactors, and issue-to-PR loops. Do not use
for simple edits, read-only lookup, ACP thread-bound work, or any run inside the agent's own state
directory (`$ARK_HOME`, the configured data dir, or an active session's tree).

## Hard rules

- Always launch with `job action=start` (background), never a blocking `shell` call.
- Codex and OpenCode: add `pty=true`; their TUIs need a terminal.
- Codex: never inherit ambient `CODEX_HOME` or the default `~/.codex`. Use a separately
  authenticated coding-agent home and scope it to each Codex command.
- Claude Code: no PTY; use `claude --permission-mode bypassPermissions --print`.
- Capture a real notification route before spawning: `job action=start notify=true` reports the
  exit, and the worker's final line states what changed and where.
- Do not rely on heartbeats, system events, or notify-on-exit hooks that are not enabled.
- Monitor with `process` (list/poll/log); do not kill slow workers without cause.
- If the user asked for a specific agent, use that agent.
- If the worker fails or hangs, respawn it or ask; do not silently hand-code the work yourself.
- Never check out branches or run background coding agents in a shared primary checkout; use an
  isolated worktree.
- Classify the source ref as trusted or untrusted before any checkout or worktree creation. Never
  materialize a contributor-controlled ref outside the repository's approved untrusted-PR sandbox
  or review workflow, and never launch a permission-bypassed worker in it.
- For tasks that modify a Git-backed project, prepare and verify the worktree before launch, then
  include the exact preparation block below in the worker prompt.

## Mandatory Git preparation

Before launching Codex, Claude Code, or OpenCode for work that modifies a Git-backed project:

1. Establish the intended target repository, then select its canonical remote. Prefer `upstream`
   when it exists and matches that target; otherwise verify `origin`. Resolve the selected remote's
   default branch dynamically. Determine the target base from an explicit task branch or
   authoritative existing-PR metadata; for other shared branches, prove the configured/tracked
   base or ask. Use the canonical default only for new work with no other specified base. Stop if
   the repository, remote, or target base cannot be proven.
2. Classify the source ref as trusted or untrusted before any checkout or worktree creation. For
   contributor-controlled refs, use the repository's approved untrusted-PR sandbox/review
   workflow, which must own ref materialization inside the sandbox, or stop. The remaining steps
   and launch forms are for trusted refs only.
3. For trusted new work, run `git fetch --prune <canonical>` immediately before creating a new
   isolated worktree and branch from `<canonical>/<targetBaseBranch>`.
4. For trusted new work, verify the worktree's initial `HEAD` equals the fetched target-base SHA.
   Record the canonical remote, canonical default branch, target base branch, base SHA, worktree
   path, and branch.
5. For a trusted existing PR or shared branch, fetch the canonical target base and source branch
   immediately before creating an isolated worktree from the fetched source branch. Record that
   source ref and starting SHA, report its divergence from the refreshed target base, and do not
   automatically rebase, merge, reset, force-push, or otherwise rewrite shared history.
6. Launch the worker in the isolated worktree, never the primary checkout.

For tasks that modify a Git-backed project, append this block to the worker prompt with real values:

```text
Git preparation (mandatory before edits):
- canonical remote: <canonicalRemote>
- canonical default branch: <canonicalDefaultBranch>
- target base branch: <targetBaseBranch>
- fetched target base SHA: <targetBaseSha>
- preparation mode: <new work | existing PR/shared branch>
- checkout trust: trusted
- prepared source ref: <canonicalRemote/targetBaseBranch | fetched trusted source ref>
- prepared start SHA: <preparedStartSha>
- isolated worktree: <worktreePath>
- working branch: <branch>
- preparation receipt: <new work: `git fetch --prune <canonicalRemote>` ran immediately before creation from `<canonicalRemote>/<targetBaseBranch>` | existing branch: the canonical target base and trusted source ref were fetched immediately before the worktree was created from `<preparedSourceRef>` at `<preparedStartSha>`>

Before editing, verify the current directory is the isolated worktree and its initial HEAD equals <preparedStartSha>. For new work, that SHA must equal <targetBaseSha>. Never edit the primary checkout. For existing PR/shared-branch work, report divergence and do not rebase, merge, reset, force-push, or otherwise rewrite shared history unless explicitly asked.
Immediately before the final push or PR for newly authored work, run `git fetch --prune <canonicalRemote>` and `git merge-base --is-ancestor <canonicalRemote>/<targetBaseBranch> HEAD`. If the ancestry check fails, update the new branch onto the latest target base, rerun the relevant proof, and only then push without force. For existing PR/shared-branch work, report a failed ancestry check and follow the repository workflow without rewriting the branch.
```

For trusted refs, the launcher must create and verify the worktree before starting the editing
worker; do not delegate worktree creation to that worker. The approved untrusted-PR workflow must
instead own checkout and worktree materialization inside its sandbox. Read-only tasks and
non-project scratch work do not require the Git preparation block.

## Notification block

Append this shape to every worker prompt with real values, so the completion report lands in the
conversation that asked for it:

```text
Notification:
- job id: <jobId from job action=start>
- notify: true
- report to: <this session / the channel that asked>

When finished, end your reply with one line stating: what changed (files, branch, PR URL), the
proof you ran (tests, lint, build), and anything still blocked. Do not poll a heartbeat or a system
event; the job's exit is the notification.
```

If no trustworthy route exists, say completion auto-notify is unavailable and poll
`process action=log` instead.

## Launch forms

Write the worker prompt to a file first. This avoids shell quoting bugs when the required
notification block contains quotes or newlines.

```bash
PROMPT=$(mktemp -t ark-worker-prompt.XXXXXX)
cat >"$PROMPT" <<'EOF'
Task.
<mandatory Git preparation block>
<notification block>
EOF
printf 'prompt file: %s\n' "$PROMPT"
```

Use `$PROMPT` when launching from the same shell or a later job call. The launch forms below are
for trusted checkouts only; untrusted contributor refs require the repository's approved
sandbox/review workflow.

Before the first Codex worker on a host, prepare a dedicated auth home in the foreground. Do not
copy `auth.json` or other credentials from ambient `~/.codex`; authorize this home separately.
Codex scopes both file and keyring credentials by `CODEX_HOME`.

```bash
CODEX_WORKER_HOME="$HOME/.codex-coding-agent"
mkdir -p "$CODEX_WORKER_HOME"
if ! env -u CODEX_API_KEY -u CODEX_ACCESS_TOKEN -u OPENAI_API_KEY \
  CODEX_HOME="$CODEX_WORKER_HOME" codex login status >/dev/null 2>&1; then
  printf 'Codex coding-agent login required for %s\n' "$CODEX_WORKER_HOME"
  env -u CODEX_API_KEY -u CODEX_ACCESS_TOKEN -u OPENAI_API_KEY \
    CODEX_HOME="$CODEX_WORKER_HOME" codex login --device-auth
fi
printf 'Codex worker home: %s\n' "$CODEX_WORKER_HOME"
```

The login is an interactive foreground setup step, not a background worker. The launch command
repeats the fixed, quoted home and removes ambient Codex and OpenAI auth overrides. Never export
the worker home into the agent's own service environment.

Codex:

```bash
job action=start pty=true notify=true cwd:/path/isolated-worktree \
  command:"env -u CODEX_API_KEY -u CODEX_ACCESS_TOKEN -u OPENAI_API_KEY CODEX_HOME=\"$HOME/.codex-coding-agent\" codex exec - < \"$PROMPT\""
```

Claude Code:

```bash
job action=start notify=true cwd:/path/isolated-worktree \
  command:"claude --permission-mode bypassPermissions --print < \"$PROMPT\""
```

OpenCode:

```bash
job action=start pty=true notify=true cwd:/path/isolated-worktree \
  command:"opencode run < \"$PROMPT\""
```

## Long issue-to-PR work

1. Create or reuse an issue as the durable spec.
2. Include the issue URL, repo, canonical remote/default branch, target base branch/SHA, isolated
   worktree, working branch, expected PR, proof, and notification route in the worker prompt.
3. Include the mandatory Git preparation block, then tell the worker to implement, test, run review
   until no accepted actionable findings remain, and open the PR.
4. Report the issue URL and the job id back to the user immediately.
5. Monitor with `process`; cancel a runaway worker with `job action=kill`.

## Scratch Codex

Codex needs a trusted git repo. A throwaway scaffold is not project work and has no canonical
remote, so the Git preparation block does not apply:

```bash
SCRATCH=$(mktemp -d)
git -C "$SCRATCH" init
PROMPT=$(mktemp -t ark-worker-prompt.XXXXXX)
cat >"$PROMPT" <<'EOF'
Build X.
<notification block>
EOF
printf 'prompt file: %s\n' "$PROMPT"
job action=start pty=true notify=true cwd:$SCRATCH \
  command:"env -u CODEX_API_KEY -u CODEX_ACCESS_TOKEN -u OPENAI_API_KEY CODEX_HOME=\"$HOME/.codex-coding-agent\" codex exec - < \"$PROMPT\""
```

## Process actions

- `list`: running and recent jobs.
- `poll`: exit status.
- `log`: output.
- `send-keys` / `write`: input for a PTY worker.
- `paste`: paste text into a PTY worker.
- `close` / `kill`: terminate, only with cause.

## Status to the user

- Say what started, where, and the job id.
- Update only on a milestone, a worker question, an error, needed user action, or completion.
- If killed, say why.

---

Transcribed from OpenClaw `skills/coding-agent/SKILL.md` (MIT, © OpenClaw contributors); the
launch surfaces are adapted from OpenClaw's `bash pty:true background:true` form to ark's `job`
and `process` tools.
