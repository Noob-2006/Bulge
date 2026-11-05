# ark - GitLab CI template

`ark.gitlab-ci.yml` adds two jobs:

- `ark-review` runs on merge request pipelines of the same project (not forks), diffs against
  the target branch, asks ark for a review and posts it as a merge request note.
- `ark-fix-tests` is manual: runs `$ARK_CI_TEST_CMD`, lets ark fix failures (two rounds by
  default) and leaves `.ark-ci/fix.patch` as an artifact. It never pushes.

Set the variables listed at the top of the template: the model provider key, and
`GITLAB_TOKEN` (project access token, `api` scope) for posting. Self-managed instances work as
they are (`$CI_API_V4_URL`). Behaviour and the safety model are the same as the GitHub Action's
(see `../github-action/README.md`): the agent gets the diff as quoted data, cannot post, and
runs without `GITLAB_TOKEN` or `CI_JOB_TOKEN` in its environment.

To use the agent as a reviewer that answers on the merge request (rather than a one-shot job),
run ark as a daemon with the `forge_read` / `forge_write` tools and a webhook route; see
`share/skills/software-development/forge-issue-to-pr/references/webhook-trigger.md`.
