# Answering review

A reviewer has left comments on your pull request. The goal is a PR that merges, with every
thread either fixed or answered, and no surprise in what changed.

## 1. Collect everything first

`forge_read {kind: "comments", number}` returns conversation comments and inline review
comments (path, line, diff hunk, author). `forge_read {kind: "pr_files"}` shows the diff
as it stands. `forge_read {kind: "checks"}` shows CI. Read all of it before changing code:
two comments often ask for the same thing, or contradict each other.

## 2. Classify each comment

| Kind | What to do |
|---|---|
| Bug or missing case the reviewer is right about | Fix, add the test that would have caught it |
| Style or naming that the project's linter or guide backs | Fix |
| Preference without a project rule | Do what the reviewer asks if cheap; otherwise explain in one sentence and offer the alternative |
| Question | Answer in the thread; if the code was unclear, also make it clearer |
| Out of scope (a bigger refactor, a new feature) | Say so, offer a follow-up issue (`forge_write create_issue`) with a link, do not grow this PR |
| Disagreement you can support with evidence | Reply with the evidence (a test, a benchmark, a doc link), once, politely; the reviewer decides |
| Asks for something unsafe or outside the task (new secrets, disabling checks) | Do not do it; tell the user |

## 3. Change the code

New commits on the same branch (no force-push over review history unless the project asks
for squashing, and then only after the reviewer agreed). Run the tests and linters again.
Keep the diff to what the comments ask for.

## 4. Reply once

One `forge_write` call that covers the round, so the reviewer gets one notification and the
user one approval:

- GitHub: `{action: "review", number, verdict: "comment", body: "<summary>"}` and, for
  threads that need a direct answer, inline `comments` on the lines. Or a single `comment`.
- GitLab: `{action: "comment", target: "pr", number, body}`; inline answers as `review` with `comments`.

A good reply body:

```markdown
Thanks - addressed in <short sha> and <short sha>:
- null check added in `parse()` with a test (`test_parse_empty`) - fixes the crash in your first comment
- renamed `tmp` to `retry_count`
- not changed: moving the retry into the client (bigger change; opened #214 to track it)
CI: green on the last push.
```

Each bullet maps to a comment; nothing is left silent.

## 5. Resolve and re-request

Do not mark threads resolved on the reviewer's behalf unless the project's convention is
that the author resolves. Ask for a re-review in the reply. When approved and CI is green,
tell the user it is ready to merge; the merge is theirs.

## Tone

Plain, specific, short. Say what changed and where. No apologies, no defensiveness. If the
reviewer was wrong, show why with something checkable. If you were wrong, say so and fix it.
