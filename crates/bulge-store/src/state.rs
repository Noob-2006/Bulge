//! Rebuild job state from its event log.

use std::collections::BTreeMap;

use bulge_llm::{Message, TokenUsage};
use serde_json::Value;

use crate::events::{Contract, Envelope, JobEvent, JobSpec, JobStatus, PlanItem};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum StateError {
    #[error("first event must be `created`")]
    MissingCreated,
    #[error("sequence must increase strictly: {prev} then {next}")]
    Sequence { prev: u64, next: u64 },
    #[error("tool call {0} completed without being claimed")]
    UnclaimedCompletion(String),
    #[error("tool call {0} claimed twice")]
    DuplicateClaim(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compaction {
    pub kept_from: usize,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JobState {
    pub spec: JobSpec,
    pub contract: Option<Contract>,
    pub plan: Vec<PlanItem>,
    /// Latest context checkpoint, if any.
    pub compaction: Option<Compaction>,
    /// Model-visible history in order.
    pub history: Vec<Message>,
    /// Claimed but not completed tool calls (in-flight, or interrupted by a crash).
    pub pending_calls: BTreeMap<String, PendingCall>,
    pub usage: TokenUsage,
    pub steps: u64,
    pub status: JobStatus,
    pub summary: Option<String>,
    pub created_ms: u64,
    pub last_seq: u64,
    pub last_ms: u64,
}

impl JobState {
    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a Envelope>) -> Result<Self, StateError> {
        let mut events = events.into_iter();
        let first = events.next().ok_or(StateError::MissingCreated)?;
        let JobEvent::Created { spec } = &first.event else { return Err(StateError::MissingCreated) };
        let mut state = Self {
            spec: spec.clone(),
            contract: None,
            plan: Vec::new(),
            compaction: None,
            history: Vec::new(),
            pending_calls: BTreeMap::new(),
            usage: TokenUsage::default(),
            steps: 0,
            status: JobStatus::Running,
            summary: None,
            created_ms: first.at_ms,
            last_seq: first.seq,
            last_ms: first.at_ms,
        };
        for envelope in events {
            state.apply(envelope)?;
        }
        Ok(state)
    }

    /// Fold one event. Used both for replay and for live appends.
    pub fn apply(&mut self, envelope: &Envelope) -> Result<(), StateError> {
        if envelope.seq <= self.last_seq {
            return Err(StateError::Sequence { prev: self.last_seq, next: envelope.seq });
        }
        match &envelope.event {
            JobEvent::Created { .. } => return Err(StateError::MissingCreated),
            JobEvent::Contract { contract } => self.contract = Some(contract.clone()),
            JobEvent::Plan { items } => self.plan = items.clone(),
            JobEvent::Compacted { kept_from, summary } => self.compaction = Some(Compaction { kept_from: *kept_from, summary: summary.clone() }),
            JobEvent::StepStarted { step } => self.steps = self.steps.max(*step),
            JobEvent::Message { message } => self.history.push(message.clone()),
            JobEvent::ToolClaimed { call_id, name, arguments } => {
                if self.pending_calls.contains_key(call_id) {
                    return Err(StateError::DuplicateClaim(call_id.clone()));
                }
                self.pending_calls.insert(call_id.clone(), PendingCall { name: name.clone(), arguments: arguments.clone() });
            }
            JobEvent::ToolCompleted { call_id, .. } => {
                if self.pending_calls.remove(call_id).is_none() {
                    return Err(StateError::UnclaimedCompletion(call_id.clone()));
                }
            }
            JobEvent::Usage { usage, .. } => {
                self.usage.input_tokens += usage.input_tokens;
                self.usage.output_tokens += usage.output_tokens;
                self.usage.cache_read_tokens += usage.cache_read_tokens;
                self.usage.cache_write_tokens += usage.cache_write_tokens;
                self.usage.reasoning_tokens += usage.reasoning_tokens;
            }
            JobEvent::StatusChanged { status, summary } => {
                self.status = *status;
                self.summary.clone_from(summary);
            }
            JobEvent::ApprovalAsked { .. }
            | JobEvent::ApprovalDecided { .. }
            | JobEvent::NetDomain { .. }
            | JobEvent::CacheBreak { .. }
            | JobEvent::BudgetWarning { .. }
            | JobEvent::VmStarted { .. }
            | JobEvent::VmStopped { .. }
            | JobEvent::Recovered { .. } => {}
        }
        self.last_seq = envelope.seq;
        self.last_ms = envelope.at_ms;
        Ok(())
    }
}
