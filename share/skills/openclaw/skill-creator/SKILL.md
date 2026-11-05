---
upstream: "openclaw/skills/skill-creator (MIT)"
name: skill-creator
description: "Author or review AgentSkills: create, repair, validate, or restructure SKILL.md files and bundled resources."
homepage: https://github.com/openclaw/openclaw
metadata:
  seagent:
    tags: [authoring, skills]
---

# Skill Creator

Use when a skill must be authored, repaired, validated, or restructured: a new class of task comes
up that the library does not cover, an existing skill misled a run, or a pile of narrow skills
should become one umbrella. Not for saving a single fact (that is memory) and not for one-off
tasks.

## Workflow

1. Establish the contract.
   - Read the existing skill and its resources, or collect concrete requests for a new skill.
   - Separate actual workflow branches from synonyms for the same branch.
   - **Done when:** every branch has a concrete trigger, expected outcome, and persistence target.

2. Choose invocation.
   - Model-discoverable: write a model-facing `description`; omit `disable-model-invocation`.
   - Manual-only: set `disable-model-invocation: true`; write a human-facing summary.
   - Direct tool command: add `command-dispatch: tool`, `command-tool`, and `command-arg-mode` only
     when the command bypasses the model.
   - **Done when:** frontmatter matches how the skill will actually be reached.

3. Structure the skill.
   - Map the shared ordered procedure to `SKILL.md`; end every step with a checkable completion
     criterion and finish with verification.
   - Keep routing conditions in `description`; start the body with execution.
   - Map branch-only detail to `references/`, repeatable helpers to `scripts/`, output resources to
     `assets/`, and optional UI metadata to `agents/`.
   - **Done when:** every planned resource has one purpose and a direct pointer from `SKILL.md`.

4. Draft and persist.
   - Live workspace skill: draft with `skill action=workshop operation=draft goal=<…> steps=[…]`,
     or refine an existing skill with `operation=refine`; the draft is a proposal, so the files stay
     unchanged until it is applied.
   - Repository-owned skill source: use the repository's normal edit and review workflow.
   - **Done when:** the proposal or source diff implements every branch from step 1 and contains
     every resource from step 3.

5. Validate.
   - Run `skill action=workshop operation=validate content=<the SKILL.md>` (or
     `seagent skills lint <name>`) and execute every touched helper's focused test.
   - **Done when:** frontmatter passes, resource pointers resolve, and every touched helper passes
     its focused test.

## Frontmatter

Required: `name`, `description`.

SE Agent also reads `metadata.seagent` (`tags`, `related_skills`, `config`), `homepage`, `license`,
`allowed-tools`, `user-invocable`, `disable-model-invocation`, `requires` (`bins`, `anyBins`, `env`,
`config`, `os`) and Hermes' `platforms`. Add optional fields only when they change runtime behavior
or discovery: `requires` hides a skill from the index when this host cannot run it.

## Standards

- Each rule is an imperative plus one clause of why, attached to the step it affects.
- Fix the misleading sentence in place; no "UPDATE:" notes, dates, or ticket ids.
- `description`: trigger first, then what the skill produces (aim for ≤160 bytes).

---

Transcribed from OpenClaw `skills/skill-creator/SKILL.md` (MIT, © OpenClaw contributors). Its
upstream `scripts/quick_validate.py` and `scripts/package_skill.py` are Apache-2.0 and are not
shipped here; `seagent skills lint` and `skill action=workshop operation=validate` replace them.
