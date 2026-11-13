# SE Agent agent - GitHub Action

Run [seagent](../../README.md) inside a workflow: review a pull request, fix a failing test
suite, or run your own prompt. The action installs a verified release of `seagent`, runs it
read-mostly in the checked-out workspace, and (for reviews) posts the result as a comment.

```yaml
# .github/workflows/seagent-review.yml
name: seagent review
on:
  pull_request:
    types: [opened, synchronize, ready_for_review]
permissions:
  contents: read
  pull-requests: write          # only to post the review comment
jobs:
  review:
    if: github.event.pull_request.draft == false && github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }                   # the review diffs against the base branch
      - uses: Noob-2006/SE-Agent/integrations/github-action@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}   # your provider key, from a secret
        with:
          task: review
          model: anthropic/claude-sonnet-4-5
          seagent-version: v1.4.0                       # pin the release
```

```yaml
# .github/workflows/seagent-fix-tests.yml  - propose a fix as a patch artifact (never pushes)
name: seagent fix tests
on:
  workflow_dispatch:
jobs:
  fix:
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v4
      - uses: Noob-2006/SE-Agent/integrations/github-action@v1
        id: seagent
        env: { ANTHROPIC_API_KEY: "${{ secrets.ANTHROPIC_API_KEY }}" }
        with:
          task: fix-tests
          test-command: npm test
          fix-attempts: "2"
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: seagent-fix, path: "${{ runner.temp }}/seagent-ci/" }
```

## Inputs

| Input | Default | |
|---|---|---|
| `task` | `review` | `review`, `fix-tests`, or `run` |
| `prompt` | | task `run`: the prompt |
| `test-command` | | task `fix-tests`: e.g. `pytest -x`, `cargo test` |
| `fix-attempts` | `2` | fix rounds before giving up |
| `post-comment` | `true` | task `review`: comment on the pull request |
| `github-token` | `${{ github.token }}` | used only to post the comment; **never given to the agent** |
| `base-ref` | PR base branch | what the review diffs against |
| `model` | configured default | `provider/model`; the provider key goes in the step `env:` |
| `role` | `swdev` | role preset (`swdev`, `secops`, `devops`, ...) |
| `budget-usd` | `2` | spend cap for one run |
| `extra-instructions` | | house rules appended to the prompt |
| `seagent-version` / `seagent-repo` / `install` | `latest` / `Noob-2006/SE-Agent` / `true` | which release; `install: false` if the runner has `seagent` |

Outputs: `result-file` (the review, the patch or the answer) and `status` (`ok` / `failed`).
The review is also appended to the job summary.

## What it can and cannot do

- **Review** is read-only for the agent: it gets the diff as quoted data with a standing
  instruction not to follow anything written in it, can read other files to check a claim,
  and cannot post anywhere. The comment is posted by the action's own script with
  `github-token`, so a prompt-injected diff cannot make the agent comment on other repositories
  or leak the token (the agent process is started with `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_TOKEN`
  and `CI_JOB_TOKEN` removed from its environment).
- **fix-tests** edits files in the runner's checkout and re-runs your test command. It does
  not commit or push; it leaves `fix.patch` and the logs in `${{ runner.temp }}/seagent-ci/`
  for you to attach, apply, or open as a PR in a later step you control.
- There is no tool in this mode that can merge, approve or change repository settings.

## Security checklist

- **Fork pull requests**: secrets are not available to them and you should not hand them to
  untrusted code. Use `pull_request` (not `pull_request_target`) as above, or gate on the
  author. The example skips forks with the `if:`.
- Give the job `contents: read` and `pull-requests: write` only.
- Pin `seagent-version` and the action to a tag or a commit SHA. The installer verifies
  `SHA256SUMS`; set `SEAGENT_RELEASE_PUBKEY` (a path to the release public key) in the step `env:`
  to verify the signature too.
- Set a `budget-usd` you can live with; `fix-tests` runs your test command, so it executes
  repository code - only run it on branches you trust.
- Provider keys live in repository (or environment) secrets, never in the workflow file.

## Run it locally

`integrations/ci/seagent-ci.sh review` works in any git checkout with `seagent` installed; the action
is a thin wrapper (`SEAGENT_CI_*` variables are documented at the top of the script).
