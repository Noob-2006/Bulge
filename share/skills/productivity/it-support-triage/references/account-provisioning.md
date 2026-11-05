# Account provisioning (prepare, never execute)

The agent prepares the request; a person with directory rights creates the account. The
agent never sets the initial password: the account is created with a forced change at first
login and the secret is delivered by the process (a reset link, a manager hand-over), not
through the ticket.

## Inputs that must be present

| Field | Source | If missing |
|---|---|---|
| Full legal name, preferred name | HR record / onboarding form | ask the requester |
| Employee ID / contract end date | HR system | contractors need an end date; no end date, no account |
| Department, manager, location | HR record | ask |
| Start date | HR | create no earlier than 3 working days before |
| Approver | manager, plus the owner of each privileged group | ask the manager |
| Requested access (groups, mailbox, licences) | role template for the job title | use the template, list deviations |

Requests that arrive only as free text in a chat, with no HR record, are not enough:
ask the requester to open the onboarding form, and say why.

## Steps

1. **Check the person does not exist**: `directory_lookup` kind `user` with the name, the
   e-mail and the employee ID as separate queries. A rehire or a duplicate is a different flow.
2. **Pick a login** following the naming rule (for example first initial + surname,
   numbered on collision). Check it is free with `directory_lookup` kind `user`.
3. **Pick the template**: look at a current colleague in the same role (`directory_lookup`
   kind `groups_of` for that colleague) and propose the same groups, minus privileged
   ones, which need their own approvals.
4. **Write the request** (below) and put it in front of the person who can act with
   `ask_user`, or attach it to the ticket.
5. **After the human confirms**, verify with `directory_lookup` that the account exists, is
   enabled, and is in exactly the groups approved; report discrepancies, do not fix them.
6. **Tell the requester** what was done and what they must do next (first login steps, MFA
   enrollment), without any secret.

## The request

```markdown
## Account request - <ticket id>
- Person: <name>, employee ID <id>, <department>, manager <name>
- Start date: <date>   End date (contractors): <date>
- Login: <proposed>  (free: checked <time> in <provider>)
- Mailbox / licences: <list>
- Groups (from template of <colleague's role>): <list>
- Privileged access requested: <none | list, with owner approval attached>
- Approved by: <manager> at <time> (<where the approval is recorded>)
- Initial password: NOT SET BY SUPPORT - create with forced change at first login
- Nothing has been changed yet.
```

## Offboarding

Same discipline, reversed: the trigger is HR, not the user's manager in chat. Prepare: disable
sign-in, remove from groups (list them first with `groups_of`), forward mail per policy,
reassign owned resources, retain data per policy. A human executes and records the time.
Never delete in the same step as disabling; deletion happens after the retention period.

## Things to refuse politely

- "Create it now, the paperwork follows." -> Create-before-approval is how shadow accounts happen.
- "Use the same password as for X." -> Support never chooses a password.
- "Add them to Domain Admins temporarily." -> Privileged group, owner approval, time-boxed.
