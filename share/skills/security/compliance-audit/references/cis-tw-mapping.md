# CIS ⇄ 資通系統防護基準 mapping and custom checklists

## Mapping used by `tw-csma`
| 防護基準構面 | checks (cis-linux ids) | manual evidence |
|---|---|---|
| 存取控制 | 5.2.16, 5.5.5 (idle timeout), 5.2.10 (root login), 6.2.2 (UID 0) | 帳號清查紀錄 |
| 事件日誌與可歸責性 | 4.1.1 (auditd), 4.2.1 (syslog), 2.1.1 (time sync) | 日誌保存期限、容量告警、存取限制 |
| 識別與鑑別 | 5.3.1 (minlen), 5.4.1.1 (max days), 5.3.2 (lockout), 6.2.1, 5.2.11 | — |
| 系統與通訊保護 | 3.5 (firewall), 3.2.2 (redirects) | 傳輸加密、儲存加密 |
| 系統與資訊完整性 | 1.9 (auto updates), 2.2.x (services) | 弱點掃描追蹤（scan_report）、監控 |
| 營運持續計畫 | — | 備份與還原測試 |
| 系統與服務獲得 | — | 生命週期資安檢核、委外條款 |

## Writing a custom checklist
```toml
[meta]
id = "our-baseline"
title = "Our Linux baseline v3"

[[check]]
id = "OB-01"
section = "SSH"
title = "Only key-based SSH logins"
severity = "high"
cmd = ["grep", "-rhiE", '^\s*PasswordAuthentication\s', "/etc/ssh/sshd_config.d", "/etc/ssh/sshd_config"]
ok_exit = [0, 1, 2]
first_line = true
match = '(?i)PasswordAuthentication\s+no'
fix = "PasswordAuthentication no; reload sshd."

[[check]]
id = "OB-02"
section = "Kernel"
title = "Same as CIS ASLR"
same_as = "cis-linux:1.5.2"

[[check]]
id = "OB-90"
section = "Organisation"
title = "Quarterly access review"
manual = true
evidence = "signed access review for each production system"
```
Allowed programs: cat, grep, stat, sysctl (read form), findmnt, pgrep, getent, timedatectl
(show/status), ls, dpkg-query, rpm -q, uname, id. Anything else is rejected when the list loads.

## Scheduling
Run monthly per host with a cron job or the automation scheduler, writing
`reports/compliance-<host>-<date>.json`; compare the summaries month to month.
