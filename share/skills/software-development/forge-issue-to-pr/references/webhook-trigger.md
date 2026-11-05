# Starting the loop from a webhook

The webhook channel (`kind = "webhook"`) accepts signed events from GitHub and GitLab and
turns them into agent runs. Each route verifies the signature first, drops events that do
not match its filters, renders a prompt, and hands the run to an agent. Nothing here needs
the forge token to be reachable from the internet; only the webhook listener is exposed.

## GitHub: issue labeled `seagent`, or a PR comment starting with `/seagent`

```toml
[channels.forgehooks]
kind = "webhook"
listen = "127.0.0.1:8644"                    # put a reverse proxy with TLS in front
secret = "{{secret:FORGE_WEBHOOK_SECRET}}"   # the same string you enter on the forge

[channels.forgehooks.routes.github-issue]
events = ["issues"]
prompt = "Issue {issue.number} in {repository.full_name} was labeled 'seagent': {issue.title}. Use the forge-issue-to-pr skill. Read the issue with forge_read first."
filters = [
  { field = "action", in = ["labeled"] },
  { field = "label.name", in = ["seagent"] },
]
coalesce = { key = "issue.number", window_seconds = 30, max_wait_seconds = 300 }

[channels.forgehooks.routes.github-review]
events = ["pull_request_review", "pull_request_review_comment", "issue_comment"]
prompt = "New review activity on {repository.full_name} PR {pull_request.number}{issue.number}. Use the forge-issue-to-pr skill, step 'Answer review'. Read the comments with forge_read first."
filters = [{ field = "action", in = ["created", "submitted"] }]
coalesce = { key = "repository.full_name", window_seconds = 60, max_wait_seconds = 600 }
```

Add the webhook on GitHub (repository settings, Webhooks): payload URL
`https://hooks.example.com/webhooks/github-issue`, content type `application/json`, the
secret, and the events listed. The route verifies `X-Hub-Signature-256`.

## GitLab: issue label, MR note

```toml
[channels.forgehooks.routes.gitlab-issue]
events = ["Issue Hook"]                      # X-Gitlab-Event
prompt = "Issue !{object_attributes.iid} in {project.path_with_namespace}: {object_attributes.title}. Use the forge-issue-to-pr skill."
filters = [{ field = "object_attributes.action", in = ["open", "update"] }, { field = "labels.0.title", in = ["seagent"] }]

[channels.forgehooks.routes.gitlab-mr-note]
events = ["Note Hook"]
prompt = "New note on a merge request in {project.path_with_namespace}. Use the forge-issue-to-pr skill, step 'Answer review'."
filters = [{ field = "object_attributes.noteable_type", in = ["MergeRequest"] }]
```

Create the webhook in the project (Settings, Webhooks) with the secret token; the route
checks `X-Gitlab-Token`. Self-managed GitLab: allow the webhook host under Admin, Network,
outbound requests if it is on a private network.

## Which agent runs it

Bind the route's session to a named agent that has the software-development role and the
forge tools (`seagent agents add forge-dev --role swdev`, then the channel binding in
`agents.toml`). The `swdev` tool profile includes `forge_read` and `forge_write`.

## Safety notes

- **The webhook is the trigger, not the authority.** Anyone who can label an issue or comment
  on a PR can start a run. Restrict the filters to labels and commands only maintainers can
  apply (GitHub: restrict who can label; add a filter on `sender.login`, for example
  `{ field = "sender.login", in = ["maintainer1", "maintainer2"] }`).
- **Comment loops.** The agent's own comments produce events. Filter `sender.type` away from
  `Bot` (or the App's login) so a reply never triggers another run, and keep `coalesce` so a
  burst becomes one run.
- **Untrusted text.** The issue body and comments are attacker-controlled; the skill treats
  them as data. Keep `forge_write` approvals on: a person sees every comment, review and PR
  before it is posted.
- **Credentials.** The token (or the GitHub App key) lives in the vault; give it only the
  repositories and permissions the loop needs (issues, pull requests, contents: read and
  write to a branch namespace, checks: read). It cannot merge unless you grant it, and the
  tools have no merge action anyway.
- **Secret rotation.** Rotate `FORGE_WEBHOOK_SECRET` on both sides together; events signed with
  the old secret are rejected.

## Test it locally

Send a signed sample: compute `sha256=` + HMAC-SHA256 of the body with the secret and
`curl -H 'X-GitHub-Event: issues' -H "X-Hub-Signature-256: $SIG" --data @event.json
http://127.0.0.1:8644/webhooks/github-issue`. A wrong signature must be refused with 401 and a
non-matching event must be dropped; check both before exposing the port.
