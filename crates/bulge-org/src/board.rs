//! The ticket board: tickets, legal transitions, and append-only JSONL replay.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Rejections allowed before a ticket must be reassigned instead of retried.
pub const MAX_REJECTIONS: u32 = 2;

/// The lifecycle state of a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    /// Published by a lead; waiting for an owner.
    Posted,
    /// An owner has claimed the ticket.
    Claimed,
    /// The owner is actively working.
    Working,
    /// The owner is blocked and needs help.
    Blocked,
    /// The owner submitted a deliverable for review.
    Submitted,
    /// A reviewer accepted the deliverable.
    Accepted,
    /// A reviewer rejected the deliverable with feedback.
    Rejected,
    /// The ticket was reassigned after repeated rejection.
    Reassigned,
    /// The accepted deliverable was integrated.
    Merged,
    /// The ticket was cancelled before completion.
    Cancelled,
    /// The ticket failed and will not be retried.
    Failed,
}

impl TicketStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Merged | Self::Cancelled | Self::Failed)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Claimed => "claimed",
            Self::Working => "working",
            Self::Blocked => "blocked",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Reassigned => "reassigned",
            Self::Merged => "merged",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for TicketStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A unit of work with one owner, acceptance criteria, and a token budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    /// Stable ticket identifier.
    pub id: String,
    /// Parent ticket, if this ticket is part of a breakdown.
    pub parent: Option<String>,
    /// Role name that should own the ticket.
    pub role: String,
    /// What the ticket is trying to achieve.
    pub goal: String,
    /// Criteria a reviewer uses to accept or reject the deliverable.
    pub acceptance: Vec<String>,
    /// Token budget allocated to the ticket.
    pub budget_tokens: u64,
    /// Identifier of the agent instance that owns the ticket.
    pub owner: Option<String>,
    /// Current lifecycle state.
    pub status: TicketStatus,
    /// Number of times a deliverable was rejected.
    pub rejections: u32,
    /// Free-form progress, feedback, and reassignment notes.
    pub notes: Vec<String>,
    /// Creation time in Unix milliseconds.
    pub created_ms: u64,
    /// Last update time in Unix milliseconds.
    pub updated_ms: u64,
}

/// An event that advances a ticket. Every variant carries `at_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BoardEvent {
    /// Publish a new ticket.
    Posted {
        /// The new ticket.
        ticket: Ticket,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Claim a posted or reassigned ticket.
    Claimed {
        /// Ticket identifier.
        id: String,
        /// Claiming owner.
        owner: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Start work on a claimed ticket, or retry a rejected one.
    Started {
        /// Ticket identifier.
        id: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Mark work as blocked.
    Blocked {
        /// Ticket identifier.
        id: String,
        /// Why work is blocked.
        reason: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Resume work after a block.
    Unblocked {
        /// Ticket identifier.
        id: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Submit a deliverable for review.
    Submitted {
        /// Ticket identifier.
        id: String,
        /// Short description of the deliverable.
        summary: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Accept a submitted deliverable.
    Accepted {
        /// Ticket identifier.
        id: String,
        /// Reviewer identifier.
        reviewer: String,
        /// Review note.
        note: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Reject a submitted deliverable with feedback.
    Rejected {
        /// Ticket identifier.
        id: String,
        /// Reviewer identifier.
        reviewer: String,
        /// Concrete feedback for the owner.
        feedback: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Move the ticket to another role after repeated rejection.
    Reassigned {
        /// Ticket identifier.
        id: String,
        /// New role name.
        role: String,
        /// Why the ticket was reassigned.
        reason: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Integrate an accepted deliverable.
    Merged {
        /// Ticket identifier.
        id: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Cancel a ticket from any non-terminal state.
    Cancelled {
        /// Ticket identifier.
        id: String,
        /// Why the ticket was cancelled.
        reason: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
    /// Fail a ticket from any non-terminal state.
    Failed {
        /// Ticket identifier.
        id: String,
        /// Why the ticket failed.
        reason: String,
        /// Event time in Unix milliseconds.
        at_ms: u64,
    },
}

impl BoardEvent {
    fn name(&self) -> &'static str {
        match self {
            Self::Posted { .. } => "posted",
            Self::Claimed { .. } => "claimed",
            Self::Started { .. } => "started",
            Self::Blocked { .. } => "blocked",
            Self::Unblocked { .. } => "unblocked",
            Self::Submitted { .. } => "submitted",
            Self::Accepted { .. } => "accepted",
            Self::Rejected { .. } => "rejected",
            Self::Reassigned { .. } => "reassigned",
            Self::Merged { .. } => "merged",
            Self::Cancelled { .. } => "cancelled",
            Self::Failed { .. } => "failed",
        }
    }
}

/// A board operation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardError {
    /// The referenced ticket does not exist.
    UnknownTicket(String),
    /// A ticket with this identifier was already posted.
    DuplicateTicket(String),
    /// The referenced parent ticket does not exist.
    UnknownParent(String),
    /// The event is not legal from the ticket's current status.
    InvalidTransition {
        /// Ticket identifier.
        id: String,
        /// The status the ticket was in.
        from: TicketStatus,
        /// The event that was refused, as a stable snake_case name.
        event: &'static str,
    },
    /// Filesystem or serialization failure.
    Io(String),
    /// The event log contains a line that is not a valid board event.
    Malformed(String),
}

impl fmt::Display for BoardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTicket(id) => write!(formatter, "unknown ticket `{id}`"),
            Self::DuplicateTicket(id) => write!(formatter, "duplicate ticket `{id}`"),
            Self::UnknownParent(id) => write!(formatter, "unknown parent ticket `{id}`"),
            Self::InvalidTransition { id, from, event } => {
                write!(
                    formatter,
                    "cannot apply `{event}` to ticket `{id}` from status `{from}`"
                )
            }
            Self::Io(message) => write!(formatter, "board io error: {message}"),
            Self::Malformed(message) => write!(formatter, "malformed board log: {message}"),
        }
    }
}

impl std::error::Error for BoardError {}

/// The in-memory ticket board, keyed by ticket identifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Board {
    tickets: BTreeMap<String, Ticket>,
}

fn invalid(ticket: &Ticket, event: &'static str) -> BoardError {
    BoardError::InvalidTransition {
        id: ticket.id.clone(),
        from: ticket.status,
        event,
    }
}

impl Board {
    /// Create an empty board.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one event, updating the board only when the transition is legal.
    pub fn apply(&mut self, event: &BoardEvent) -> Result<(), BoardError> {
        let event_name = event.name();
        match event {
            BoardEvent::Posted { ticket, at_ms } => {
                if self.tickets.contains_key(&ticket.id) {
                    return Err(BoardError::DuplicateTicket(ticket.id.clone()));
                }
                if let Some(parent) = &ticket.parent
                    && !self.tickets.contains_key(parent)
                {
                    return Err(BoardError::UnknownParent(parent.clone()));
                }
                let mut posted = ticket.clone();
                posted.updated_ms = *at_ms;
                self.tickets.insert(posted.id.clone(), posted);
            }
            BoardEvent::Claimed { id, owner, at_ms } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if !matches!(
                    ticket.status,
                    TicketStatus::Posted | TicketStatus::Reassigned
                ) {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Claimed;
                ticket.owner = Some(owner.clone());
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Started { id, at_ms } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                match ticket.status {
                    TicketStatus::Claimed => {}
                    TicketStatus::Rejected if ticket.rejections <= MAX_REJECTIONS => {}
                    _ => return Err(invalid(ticket, event_name)),
                }
                ticket.status = TicketStatus::Working;
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Blocked { id, at_ms, .. } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status != TicketStatus::Working {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Blocked;
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Unblocked { id, at_ms } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status != TicketStatus::Blocked {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Working;
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Submitted { id, at_ms, .. } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status != TicketStatus::Working {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Submitted;
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Accepted { id, at_ms, .. } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status != TicketStatus::Submitted {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Accepted;
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Rejected {
                id,
                feedback,
                at_ms,
                ..
            } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status != TicketStatus::Submitted {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Rejected;
                ticket.rejections += 1;
                ticket.notes.push(feedback.clone());
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Reassigned {
                id,
                role,
                reason,
                at_ms,
            } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status != TicketStatus::Rejected {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Reassigned;
                ticket.role = role.clone();
                ticket.owner = None;
                ticket.notes.push(reason.clone());
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Merged { id, at_ms } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status != TicketStatus::Accepted {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Merged;
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Cancelled { id, at_ms, .. } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status.is_terminal() {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Cancelled;
                ticket.updated_ms = *at_ms;
            }
            BoardEvent::Failed { id, at_ms, .. } => {
                let ticket = self
                    .tickets
                    .get_mut(id)
                    .ok_or_else(|| BoardError::UnknownTicket(id.clone()))?;
                if ticket.status.is_terminal() {
                    return Err(invalid(ticket, event_name));
                }
                ticket.status = TicketStatus::Failed;
                ticket.updated_ms = *at_ms;
            }
        }
        Ok(())
    }

    /// Look a ticket up by identifier.
    pub fn get(&self, id: &str) -> Option<&Ticket> {
        self.tickets.get(id)
    }

    /// All tickets, sorted by `(created_ms, id)`.
    pub fn tickets(&self) -> Vec<&Ticket> {
        let mut tickets: Vec<&Ticket> = self.tickets.values().collect();
        tickets.sort_by(|left, right| {
            left.created_ms
                .cmp(&right.created_ms)
                .then_with(|| left.id.cmp(&right.id))
        });
        tickets
    }

    /// Direct children of `id`, sorted by `(created_ms, id)`.
    pub fn children(&self, id: &str) -> Vec<&Ticket> {
        let mut children: Vec<&Ticket> = self
            .tickets
            .values()
            .filter(|ticket| ticket.parent.as_deref() == Some(id))
            .collect();
        children.sort_by(|left, right| {
            left.created_ms
                .cmp(&right.created_ms)
                .then_with(|| left.id.cmp(&right.id))
        });
        children
    }

    /// Non-terminal tickets (not accepted, merged, cancelled, or failed),
    /// sorted by `(created_ms, id)`.
    pub fn open(&self) -> Vec<&Ticket> {
        let mut open: Vec<&Ticket> = self
            .tickets
            .values()
            .filter(|ticket| {
                !matches!(
                    ticket.status,
                    TicketStatus::Accepted
                        | TicketStatus::Merged
                        | TicketStatus::Cancelled
                        | TicketStatus::Failed
                )
            })
            .collect();
        open.sort_by(|left, right| {
            left.created_ms
                .cmp(&right.created_ms)
                .then_with(|| left.id.cmp(&right.id))
        });
        open
    }
}

/// Append-only JSONL board persistence. Each line is one [`BoardEvent`].
#[derive(Debug)]
pub struct BoardLog {
    path: PathBuf,
    file: File,
}

impl BoardLog {
    /// Open (or create) a board log, creating parent directories, replaying
    /// every existing line into a fresh board, and positioning for appends.
    pub fn open(path: &Path) -> Result<(BoardLog, Board), BoardError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| BoardError::Io(format!("create {}: {error}", parent.display())))?;
        }
        let mut board = Board::new();
        let mut needs_newline = false;
        if path.exists() {
            let contents = std::fs::read_to_string(path)
                .map_err(|error| BoardError::Io(format!("read {}: {error}", path.display())))?;
            for (index, line) in contents.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let event: BoardEvent = serde_json::from_str(line).map_err(|error| {
                    BoardError::Malformed(format!("{}:{}: {error}", path.display(), index + 1))
                })?;
                board.apply(&event)?;
            }
            needs_newline = !contents.is_empty() && !contents.ends_with('\n');
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| BoardError::Io(format!("open {}: {error}", path.display())))?;
        if needs_newline {
            file.write_all(b"\n")
                .map_err(|error| BoardError::Io(format!("write {}: {error}", path.display())))?;
            file.flush()
                .map_err(|error| BoardError::Io(format!("flush {}: {error}", path.display())))?;
        }
        Ok((
            Self {
                path: path.to_path_buf(),
                file,
            },
            board,
        ))
    }

    /// Apply `event` to `board` first; only if that succeeds, append its JSON
    /// line and flush.
    pub fn append(&mut self, board: &mut Board, event: BoardEvent) -> Result<(), BoardError> {
        board.apply(&event)?;
        let line = serde_json::to_string(&event)
            .map_err(|error| BoardError::Malformed(format!("encode event: {error}")))?;
        writeln!(self.file, "{line}")
            .and_then(|()| self.file.flush())
            .map_err(|error| BoardError::Io(format!("append {}: {error}", self.path.display())))
    }
}

#[cfg(test)]
#[path = "board_tests.rs"]
mod tests;
