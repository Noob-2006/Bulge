# Permission requests

Someone needs access to a system, a shared folder, a repository, a mailbox. The agent finds
out what they have, what they need, and who may approve; a human applies the change.

## 1. Understand what is asked

Restate in one line: *who* needs *which access* to *what*, *why*, *until when*. Missing
reason or duration means ask. "Same as Alice" is a lead, not a justification: check what Alice has.

## 2. Look up the facts

- `directory_lookup` kind `user` for the requester: enabled, department, manager.
- `directory_lookup` kind `groups_of` for the requester: what they already have. If the
  access is already granted, the problem is elsewhere (cache, token, client): go to diagnostics.
- `directory_lookup` kind `group` for the group that grants the access, then `members` to
  see who is in it, which tells who the usual users are. The group description often names the owner.

## 3. Classify

| Class | Examples | Approval needed |
|---|---|---|
| Standard | team shared folder, common SaaS seat, printer | requester's manager |
| Sensitive | finance, HR data, customer PII, production read | manager + data owner |
| Privileged | admin roles, production write, security tooling, VPN-all | manager + system owner + security, time-boxed |

Anything touching customer data or production gets the stricter class when unsure.

## 4. Prepare the request

```markdown
## Access request - <ticket id>
- Requester: <login> (<department>, manager <name>)
- Access: <system / group / resource>, level <read | write | admin>
- Reason: <one sentence>   Needed until: <date | permanent with annual review>
- Already has: <groups from groups_of that relate>
- Approvals needed: <manager> / <owner> / <security>   Received: <who, when, where recorded>
- Proposed change: add <login> to <group>   (nothing has been changed yet)
```

Put it in front of the person who can act (`ask_user`) or attach it to the ticket. Approvals
come from the approvers themselves in a channel you can verify, never relayed by the requester.

## 5. After the change

Verify with `directory_lookup` (`groups_of` again), tell the requester what to do (sign out
and in so the token refreshes), and set a reminder for time-boxed access to be removed.

## Least privilege defaults

- Offer the lowest level that does the job (read before write, write before admin).
- Prefer a group over a direct grant, and a role over a person.
- Time-box anything privileged; make the removal date part of the request.
- A request that widens access for many people (a whole department into a data group) is
  a policy change: escalate it.

## Say no, kindly, when

- The approver is the requester (or reports to the requester for this purpose).
- The only evidence of approval is the requester's own message.
- The request asks to bypass MFA or to share an account: explain the alternative (a service
  account, a delegated mailbox, a break-glass procedure) and offer to prepare that request.
