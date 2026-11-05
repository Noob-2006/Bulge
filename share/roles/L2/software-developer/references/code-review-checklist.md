# Code review checklist (pull request)

Use when asked to review a change. Report findings by severity; praise last, if at all.

## Correctness
- Does the change do what its description says? Run it or its tests; do not infer.
- Edge cases: empty input, maximum size, concurrent callers, error paths, retries.
- Are invariants and contracts of touched routines still true? Are callers updated?

## Safety
- Untrusted input reaches a shell, a query, a path or a template only through an escape.
- Secrets never logged, never committed; new dependencies pinned and justified.
- Data migrations reversible or explicitly approved as one-way.

## Tests
- A test fails without the change and passes with it.
- No test disabled, skipped or weakened to make the build green.

## Maintainability
- Names say what things are; no dead code; comments explain why, not what.
- The change extends the existing design instead of adding a parallel mechanism.

## Output format
- `file:line — severity (blocker / should fix / nit) — problem — suggested fix`.
