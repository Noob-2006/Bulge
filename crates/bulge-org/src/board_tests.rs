use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(label: &str) -> TempDir {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bulge-org-board-{label}-{}-{sequence}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create temp dir");
    TempDir(path)
}

fn ticket(id: &str, parent: Option<&str>) -> Ticket {
    Ticket {
        id: id.to_string(),
        parent: parent.map(str::to_string),
        role: "implementer".to_string(),
        goal: format!("goal for {id}"),
        acceptance: vec!["tests pass".to_string()],
        budget_tokens: 10_000,
        owner: None,
        status: TicketStatus::Posted,
        rejections: 0,
        notes: Vec::new(),
        created_ms: 1_000,
        updated_ms: 1_000,
    }
}

fn post(board: &mut Board, id: &str, at_ms: u64) {
    board
        .apply(&BoardEvent::Posted {
            ticket: ticket(id, None),
            at_ms,
        })
        .expect("post");
}

fn to_working(board: &mut Board, id: &str, now: &mut u64) {
    *now += 1;
    board
        .apply(&BoardEvent::Claimed {
            id: id.to_string(),
            owner: "agent-1".to_string(),
            at_ms: *now,
        })
        .expect("claim");
    *now += 1;
    board
        .apply(&BoardEvent::Started {
            id: id.to_string(),
            at_ms: *now,
        })
        .expect("start");
}

#[test]
fn happy_path_post_through_merge() {
    let mut board = Board::new();
    let mut now = 100;
    post(&mut board, "t1", now);
    to_working(&mut board, "t1", &mut now);
    now += 1;
    board
        .apply(&BoardEvent::Submitted {
            id: "t1".to_string(),
            summary: "done".to_string(),
            at_ms: now,
        })
        .expect("submit");
    now += 1;
    board
        .apply(&BoardEvent::Accepted {
            id: "t1".to_string(),
            reviewer: "reviewer-1".to_string(),
            note: "looks good".to_string(),
            at_ms: now,
        })
        .expect("accept");
    now += 1;
    board
        .apply(&BoardEvent::Merged {
            id: "t1".to_string(),
            at_ms: now,
        })
        .expect("merge");
    let ticket = board.get("t1").expect("ticket");
    assert_eq!(ticket.status, TicketStatus::Merged);
    assert_eq!(ticket.owner.as_deref(), Some("agent-1"));
    assert_eq!(ticket.updated_ms, now);
}

#[test]
fn invalid_transition_leaves_board_unchanged() {
    let mut board = Board::new();
    post(&mut board, "t1", 100);
    let before = board.get("t1").cloned().expect("ticket");
    let error = board
        .apply(&BoardEvent::Started {
            id: "t1".to_string(),
            at_ms: 200,
        })
        .expect_err("cannot start posted ticket");
    assert_eq!(
        error,
        BoardError::InvalidTransition {
            id: "t1".to_string(),
            from: TicketStatus::Posted,
            event: "started",
        }
    );
    assert_eq!(board.get("t1"), Some(&before));
}

#[test]
fn rejections_increment_and_third_rejection_cannot_retry() {
    let mut board = Board::new();
    let mut now = 100;
    post(&mut board, "t1", now);
    to_working(&mut board, "t1", &mut now);
    for round in 0..3 {
        now += 1;
        board
            .apply(&BoardEvent::Submitted {
                id: "t1".to_string(),
                summary: format!("attempt {round}"),
                at_ms: now,
            })
            .expect("submit");
        now += 1;
        board
            .apply(&BoardEvent::Rejected {
                id: "t1".to_string(),
                reviewer: "reviewer-1".to_string(),
                feedback: format!("feedback {round}"),
                at_ms: now,
            })
            .expect("reject");
        assert_eq!(board.get("t1").expect("ticket").rejections, round + 1);
        if round < 2 {
            now += 1;
            board
                .apply(&BoardEvent::Started {
                    id: "t1".to_string(),
                    at_ms: now,
                })
                .expect("retry allowed");
        }
    }
    assert_eq!(board.get("t1").expect("ticket").rejections, 3);
    let error = board
        .apply(&BoardEvent::Started {
            id: "t1".to_string(),
            at_ms: now + 1,
        })
        .expect_err("third rejection must reassign");
    assert!(matches!(
        error,
        BoardError::InvalidTransition {
            event: "started",
            ..
        }
    ));
    assert_eq!(board.get("t1").expect("ticket").notes.len(), 3);
}

#[test]
fn reassignment_clears_owner_sets_role_and_appends_reason() {
    let mut board = Board::new();
    let mut now = 100;
    post(&mut board, "t1", now);
    to_working(&mut board, "t1", &mut now);
    now += 1;
    board
        .apply(&BoardEvent::Submitted {
            id: "t1".to_string(),
            summary: "done".to_string(),
            at_ms: now,
        })
        .expect("submit");
    now += 1;
    board
        .apply(&BoardEvent::Rejected {
            id: "t1".to_string(),
            reviewer: "reviewer-1".to_string(),
            feedback: "not enough tests".to_string(),
            at_ms: now,
        })
        .expect("reject");
    now += 1;
    board
        .apply(&BoardEvent::Reassigned {
            id: "t1".to_string(),
            role: "analyst".to_string(),
            reason: "swap in a specialist".to_string(),
            at_ms: now,
        })
        .expect("reassign");
    let ticket = board.get("t1").expect("ticket");
    assert_eq!(ticket.status, TicketStatus::Reassigned);
    assert_eq!(ticket.role, "analyst");
    assert!(ticket.owner.is_none());
    assert_eq!(
        ticket.notes,
        [
            "not enough tests".to_string(),
            "swap in a specialist".to_string()
        ]
    );
    now += 1;
    board
        .apply(&BoardEvent::Claimed {
            id: "t1".to_string(),
            owner: "agent-2".to_string(),
            at_ms: now,
        })
        .expect("claim reassigned");
    assert_eq!(
        board.get("t1").expect("ticket").owner.as_deref(),
        Some("agent-2")
    );
}

#[test]
fn duplicate_id_and_unknown_parent_are_rejected() {
    let mut board = Board::new();
    post(&mut board, "t1", 100);
    assert_eq!(
        board
            .apply(&BoardEvent::Posted {
                ticket: ticket("t1", None),
                at_ms: 200,
            })
            .expect_err("duplicate"),
        BoardError::DuplicateTicket("t1".to_string())
    );
    assert_eq!(
        board
            .apply(&BoardEvent::Posted {
                ticket: ticket("child", Some("missing")),
                at_ms: 300,
            })
            .expect_err("unknown parent"),
        BoardError::UnknownParent("missing".to_string())
    );
    assert!(board.get("child").is_none());
}

#[test]
fn children_and_open_queries() {
    let mut board = Board::new();
    let mut parent = ticket("parent", None);
    parent.created_ms = 10;
    board
        .apply(&BoardEvent::Posted {
            ticket: parent,
            at_ms: 10,
        })
        .expect("post parent");
    let mut child = ticket("child", Some("parent"));
    child.created_ms = 20;
    board
        .apply(&BoardEvent::Posted {
            ticket: child,
            at_ms: 20,
        })
        .expect("post child");
    let mut done = ticket("done", Some("parent"));
    done.created_ms = 30;
    board
        .apply(&BoardEvent::Posted {
            ticket: done,
            at_ms: 30,
        })
        .expect("post done");
    board
        .apply(&BoardEvent::Cancelled {
            id: "done".to_string(),
            reason: "not needed".to_string(),
            at_ms: 40,
        })
        .expect("cancel");
    assert_eq!(
        board
            .children("parent")
            .iter()
            .map(|ticket| ticket.id.as_str())
            .collect::<Vec<_>>(),
        ["child", "done"]
    );
    assert_eq!(
        board
            .open()
            .iter()
            .map(|ticket| ticket.id.as_str())
            .collect::<Vec<_>>(),
        ["parent", "child"]
    );
    assert_eq!(
        board
            .tickets()
            .iter()
            .map(|ticket| ticket.id.as_str())
            .collect::<Vec<_>>(),
        ["parent", "child", "done"]
    );
}

#[test]
fn log_replay_reproduces_the_same_board() {
    let dir = temp_dir("replay");
    let path = dir.0.join("nested").join("board.jsonl");
    let mut now = 100;
    {
        let (mut log, mut board) = BoardLog::open(&path).expect("open log");
        log.append(
            &mut board,
            BoardEvent::Posted {
                ticket: ticket("t1", None),
                at_ms: now,
            },
        )
        .expect("post");
        now += 1;
        log.append(
            &mut board,
            BoardEvent::Claimed {
                id: "t1".to_string(),
                owner: "agent-1".to_string(),
                at_ms: now,
            },
        )
        .expect("claim");
        now += 1;
        log.append(
            &mut board,
            BoardEvent::Started {
                id: "t1".to_string(),
                at_ms: now,
            },
        )
        .expect("start");
        now += 1;
        log.append(
            &mut board,
            BoardEvent::Blocked {
                id: "t1".to_string(),
                reason: "waiting".to_string(),
                at_ms: now,
            },
        )
        .expect("block");
        assert_eq!(
            board.get("t1").expect("ticket").status,
            TicketStatus::Blocked
        );
    }
    let (_log, replayed) = BoardLog::open(&path).expect("reopen log");
    let ticket = replayed.get("t1").expect("ticket");
    assert_eq!(ticket.status, TicketStatus::Blocked);
    assert_eq!(ticket.owner.as_deref(), Some("agent-1"));
    assert_eq!(ticket.updated_ms, now);
}

#[test]
fn failed_apply_writes_nothing() {
    let dir = temp_dir("no-write");
    let path = dir.0.join("board.jsonl");
    let (mut log, mut board) = BoardLog::open(&path).expect("open log");
    let length = std::fs::metadata(&path).expect("metadata").len();
    let error = log
        .append(
            &mut board,
            BoardEvent::Claimed {
                id: "missing".to_string(),
                owner: "agent-1".to_string(),
                at_ms: 100,
            },
        )
        .expect_err("unknown ticket");
    assert_eq!(error, BoardError::UnknownTicket("missing".to_string()));
    assert_eq!(std::fs::metadata(&path).expect("metadata").len(), length);
    assert!(board.tickets().is_empty());
}
