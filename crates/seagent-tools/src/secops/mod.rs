//! Security-operations tools (BATCH-next §三 pro-026 / pro-030 / pro-031): scanner report
//! parsing with de-duplication and exploitability ranking (`scan_report`), general OSV
//! vulnerability lookups (`osv_query`), SIEM / AppSec alert sources (`siem_alerts`: Wazuh,
//! Elastic Security, Splunk, Semgrep) and executable compliance checklists
//! (`compliance_check`: CIS-style Linux baseline, 資通安全管理法 對照). All read-only; the
//! ticket side of the vulnerability workflow is `jira` / `servicenow` in [`crate::ops`].
//!
//! Configuration: `[integrations.secops]` (`kev_file`, `checklists`, `check_timeout_seconds`),
//! `[integrations.osv] url`, and one section per SIEM source (`[integrations.wazuh]` indexer
//! URL + read-only user, `[integrations.splunk]` management URL + token, `[integrations.semgrep]`
//! token + `deployment`; Elastic shares `[integrations.elastic]` with `elastic_search`).

pub mod compliance;
pub mod osvq;
pub mod report;
pub mod siem;
pub mod winprobe;

use crate::ops::Integrations;
use seagent_core::Tool;
use std::sync::Arc;

pub fn tools(cfg: Arc<Integrations>) -> Vec<Arc<dyn Tool>> {
    let mut out: Vec<Arc<dyn Tool>> = vec![
        Arc::new(report::ScanReport { cfg: cfg.clone() }),
        Arc::new(osvq::OsvQuery { cfg: cfg.clone() }),
        Arc::new(compliance::ComplianceCheck { cfg: cfg.clone() }),
    ];
    if !siem::SiemAlerts::configured(&cfg).is_empty() {
        out.push(Arc::new(siem::SiemAlerts { cfg }));
    }
    out
}
