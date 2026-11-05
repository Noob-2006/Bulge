# SE Agent - Jenkins example

`Jenkinsfile` is a declarative pipeline for a multibranch (pull request) job:

1. installs a pinned `seagent` release (verified by the installer),
2. reviews the change (`seagent-ci.sh review`) with the provider key as the only credential SE Agent sees,
3. posts the review with a separate token (`seagent-ci.sh post`) - the agent never has it,
4. optionally (`FIX_TESTS`) lets SE Agent fix a red test suite and archives `fix.patch`.

Create the two credentials named in the file, point a multibranch job at the repository
and set `GITHUB_REPOSITORY` (or switch the post stage to GitLab with `SEAGENT_CI_PROVIDER=gitlab`,
`GITLAB_TOKEN`, `CI_API_V4_URL`, `CI_PROJECT_ID`). The safety model is the same as for the
GitHub Action: see `../github-action/README.md`.
