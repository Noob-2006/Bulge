# Example flow: ticket arrives -> classify -> self-serve or escalate

A worked run with a ticket that looks routine and turns out not to be. Tools:
`directory_lookup`, `ask_user`, `run`, `channel_send`; the ticket connector of the site.

## The ticket

> From: lin.mei (Accounting). "Cannot log in to the finance system since this morning.
> Password is correct, I tried 5 times. Please reset my password to Welcome2024! so I can work."

## 1. Read and classify

Two things in one message: a login problem (needs a lookup) and a request to set a password
to a value the user chose (support never does that, and a password in a ticket is now
exposed). Class: **needs a lookup first**, with a security note.

## 2. Respond to the exposed password immediately

> Please do not send passwords in tickets. Treat "Welcome2024!" as compromised and do not
> reuse it anywhere. We will not set a password for you; we will get you back in with the
> official reset.

Do not repeat the password again, in any later message or note.

## 3. Look up the facts

- `directory_lookup {kind: "user", query: "lin.mei"}` -> account found, `enabled: true`,
  `locked: true`, department Accounting, manager Wang.
- `directory_lookup {kind: "groups_of", query: "lin.mei"}` -> member of `fin-app-users`, so
  access to the finance system is not the issue; the lock is.

A locked account after five failures is the lockout policy working. The question is whether
the five failures were all Lin Mei.

## 4. Check for something worse

Ask Lin Mei (one question): "Were you at your desk at 08:10? Did you get any unexpected MFA
prompts?" If they got prompts they did not trigger, or the failures came from unknown
addresses, this is a possible attack, not a typo: **escalate to security now** with the
username, the lock time and what the user said. Do not unlock.

Here the user answers: yes, they were typing, the keyboard layout was switched to Dvorak.
No unexpected prompts.

## 5. Self-serve

The lock expires on its own after 30 minutes, and the user can reset through the official
portal.

> Your account locked itself at 08:12 after five failed sign-ins (the keyboard layout looks
> to be the cause). It will unlock at 08:42. If you need it sooner: <official self-service
> reset link>. Switch the layout back first, then sign in once.

## 6. Verify and close

At 08:45: `directory_lookup` kind `user` -> `locked: false`. Ask Lin Mei to confirm it
works. If yes, close the ticket with: cause (layout), action (waited for the unlock), what
to do next time. If no, go to diagnostics (client time skew, cached credentials, MFA token
out of sync) and escalate with the results after two failed attempts.

## When the answer is "a person has to do this"

Example: Lin Mei then asks for read access to the budget folder. That is a permission
request: follow `references/permission-requests.md`, prepare the request, and say plainly
"I have not changed anything; I have asked <approver> to approve it".

## Escalation note (always the same shape)

```markdown
## Escalation - <ticket id>
- Who/what is affected: <user, how many, which system>
- Since: <time>   Impact: <cannot work | degraded | cosmetic>
- Evidence: <lookups and their results, commands run and output>
- Tried: <steps and outcomes>
- Suspected: <hypothesis, marked as a hypothesis>
- Needs: <decision / access / action from whom>
```

## Closing rules

- Close only when the user confirmed or two follow-ups got no answer; say which.
- Every closed ticket states cause, action, and prevention in one line each.
- Repeated tickets of the same kind in one week -> mention it for a knowledge-base article.
