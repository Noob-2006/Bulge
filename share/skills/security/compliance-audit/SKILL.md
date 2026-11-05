---
upstream: "seagent/skills original to SE Agent (MIT)"
name: compliance-audit
description: "Run executable compliance checklists (CIS-style Linux, 資通安全管理法 對照) and turn results into evidence and a remediation plan."
version: 1.0.0
author: SE Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [security, compliance, cis, benchmark, audit, taiwan, 資通安全管理法, hardening]
    category: security
    related_skills: [vuln-triage]
---

# Compliance checks and audit evidence

Use this skill to answer "does this host meet our baseline", to prepare evidence for an
internal or external audit, or to map technical controls to 資通安全管理法 obligations. The
`compliance_check` tool runs each check with a fixed read-only command (cat, grep, stat,
sysctl, findmnt, pgrep, getent); nothing is changed and nothing is elevated. A check whose
input is unreadable without root reports `skip`, never a guessed `pass`.

## Checklists

- `cis-linux` — a CIS-style Linux host baseline (Level 1 server subset): filesystem mounts,
  kernel hardening, network parameters, firewall, auditing and logging, time sync, services,
  SSH, password and lockout policy, file permissions, accounts.
- `tw-csma` — 資通安全管理法 對照: technical items grouped under the seven 資通系統防護基準
  families (存取控制、事件日誌與可歸責性、營運持續計畫、識別與鑑別、系統與服務獲得、系統與通訊保護、
  系統與資訊完整性), reusing the CIS checks, plus organisational evidence items (維護計畫、
  資安長與專責人員、ISMS、資安健診、教育訓練、事件通報時限、演練) reported as `manual`.
- Custom lists: a TOML file in the same format, registered under
  `[integrations.secops] checklists = ["policies/our-baseline.toml"]` or passed by path.

## Procedure

1. **Scope.** Which hosts, which checklist, which benchmark version or legal basis the
   organisation adopted. This tool checks the host it runs on; for other hosts, run SE Agent there
   (or a node) rather than reaching over SSH with broad credentials.
2. **Run.** `compliance_check checklist=["cis-linux","tw-csma"] output=reports/compliance-<host>.md`.
   Use `section=` to re-run one area after a fix, `only_failed=true` for a short list.
3. **Read results.**
   - `fail` items carry the fix text; check whether a documented exception applies (for
     example IP forwarding on a container host).
   - `skip` items need a root-level check by an administrator, or the input is absent.
   - `manual` items need documents, not commands: list who must provide which evidence.
4. **Plan remediation.** Group failures by owner and change type (sysctl drop-in, sshd config,
   PAM, packages). Each change goes through normal change control; fixes are not applied by
   this skill. Offer tickets (`jira` / `servicenow`) after the human approves the list.
5. **Evidence pack.** Keep the Markdown or JSON report with the date, host, checklist id and
   the exact commands (they are in the report through the check ids). Re-run after fixes and
   keep both reports.

## Notes on 資通安全管理法

- The act binds 公務機關 and designated 特定非公務機關; obligations scale with the 責任等級
  (A–E) and each system's 防護需求等級 (普／中／高). Confirm both before treating a `fail` as
  non-compliance.
- Incident notification has a short clock (公務機關 within one hour of becoming aware, per
  資通安全事件通報及應變辦法). Check the current text published by the competent authority
  (數位發展部) before relying on any deadline here.
- This checklist is a starting point for mapping, not legal advice and not an audit opinion.

## References

- `references/cis-tw-mapping.md` — how the checks map between CIS sections and the 防護基準
  families, writing custom checklists, and running in CI or on a schedule.
