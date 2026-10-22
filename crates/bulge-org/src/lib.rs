//! bulge-org: the pure-logic core of the flat AI organization.
//!
//! The crate defines role charters (Markdown with a small frontmatter block),
//! the ticket board and its transition rules, the org message bus with
//! quarantine and a model-free situation report, the performance book, and
//! reviewer-answer parsing. It contains no runtime and no model calls; the only
//! side effects are persistence for the board, bus, and performance book.
//! Wiring those pieces into agents and tools lives in `bulge-cli`; this crate
//! stays deterministic and independently testable.

pub mod board;
pub mod bus;
pub mod governance;
pub mod perf;
pub mod review;
pub mod role;

pub use board::{Board, BoardError, BoardEvent, BoardLog, MAX_REJECTIONS, Ticket, TicketStatus};
pub use bus::{Bus, Delivery, LedgerView, MessageKind, OrgMessage, situation_report};
pub use governance::{
    MAX_PROPOSED_SHARE, PROPOSABLE_TOOLS, Violation, append_decision, as_trial, audit_task,
    check_proposal, vetoed_names,
};
pub use perf::{PerformanceBook, Record, Verdict};
pub use review::{Review, parse_review, review_task, rework_message};
pub use role::{
    RoleCharter, RoleKind, RoleLibrary, RoleProblem, TRIAL_BUDGET_SHARE, TRIAL_GRADUATION,
    builtin_roles, parse_charter,
};
