//! One ticket from posting to report: the worker → review → rework or
//! replacement loop, model choice, and the board and performance records.

use bulge_util::now_ms;
use bulge_core::driver::DelegateReport;
use bulge_org::{BoardEvent, TicketStatus, Verdict};
use bulge_store::JobEvent;
use tokio_util::sync::CancellationToken;
use super::{ChildFactory, NO_REVIEWER, NextStep, OrgState, TicketPlan, Worker, failure_step, first_model, format_conflicts, merge_conflict_note, next_step, replacement_task, rework_attempt};

impl ChildFactory {
    /// The ticket loop: worker attempt, independent review, then merge, rework or
    /// replacement. All terminal board writes happen here; the outer cleanup only
    /// fills in a missing failure/cancellation and closes any open slot.
    pub(crate) async fn ticket_loop(
        &self,
        plan: &TicketPlan,
        cancel: &CancellationToken,
        worker: &mut Option<Worker>,
    ) -> Result<DelegateReport, String> {
        let mut model = self.choose_first(plan.requested_model.as_deref(), &plan.role_name, &plan.candidates);
        let mut task = plan.base_task.clone();
        let mut attempts: u32 = 0;
        let mut models: Vec<String> = Vec::new();
        let mut tried: Vec<String> = Vec::new();
        let mut rejections: u32 = 0;
        let mut feedback = String::new();

        'outer: loop {
            let mut current = self.start_worker(plan, &task, &model, cancel).await?;
            loop {
                let before = current.ledger.spent();
                let run = self.run_worker(&mut current, plan, cancel).await?;
                let worker_tokens = current.ledger.spent().saturating_sub(before);
                let job_id = current.job_id.clone();
                attempts += 1;
                models.push(model.clone());
                if !tried.contains(&model) {
                    tried.push(model.clone());
                }

                if cancel.is_cancelled() || run.status == "cancelled" || run.outcome == "cancelled" {
                    self.record_board(BoardEvent::Cancelled {
                        id: plan.ticket_id.clone(),
                        reason: "cancelled by the parent".into(),
                        at_ms: now_ms(),
                    });
                    *worker = Some(current);
                    return Err("CANCELLED: the delegation was cancelled".into());
                }

                if !run.succeeded {
                    self.record_perf(&plan.role_name, &model, Verdict::Failed, worker_tokens);
                    let run_reason = format!("worker run did not succeed: {}/{}", run.status, run.outcome);
                    match self.next_after_failure(&plan.role_name, &plan.candidates, &tried) {
                        NextStep::Replace(next) => {
                            // A failed run has no review, so make the replacement
                            // transition legal: Submitted -> Rejected -> Reassigned.
                            self.record_board(BoardEvent::Submitted {
                                id: plan.ticket_id.clone(),
                                summary: run.summary.clone(),
                                at_ms: now_ms(),
                            });
                            self.record_board(BoardEvent::Rejected {
                                id: plan.ticket_id.clone(),
                                reviewer: "system".into(),
                                feedback: run_reason.clone(),
                                at_ms: now_ms(),
                            });
                            self.record_board(BoardEvent::Reassigned {
                                id: plan.ticket_id.clone(),
                                role: plan.role_name.clone(),
                                reason: format!("replaced after a failed run: {model} → {next}"),
                                at_ms: now_ms(),
                            });
                            self.finish_worker(current).await;
                            model = next;
                            task = plan.base_task.clone();
                            continue 'outer;
                        }
                        NextStep::Fail(reason) => {
                            self.record_board(BoardEvent::Failed {
                                id: plan.ticket_id.clone(),
                                reason: reason.clone(),
                                at_ms: now_ms(),
                            });
                            self.finish_worker(current).await;
                            return Ok(self.finalize(
                                plan,
                                &run,
                                &job_id,
                                false,
                                None,
                                &feedback,
                                attempts,
                                models,
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                                Some(&reason),
                            ));
                        }
                        NextStep::Merge | NextStep::Rework => unreachable!("failure cannot merge or rework"),
                    }
                }

                let (changed, lost) = self.collect_changes(current.slot).await;
                let lost_paths: Vec<String> = lost.iter().map(|conflict| conflict.path.clone()).collect();
                let conflicts = format_conflicts(&lost);
                let board_summary = match merge_conflict_note(&lost_paths) {
                    Some(note) => format!("{note}\n\n{}", run.summary),
                    None => run.summary.clone(),
                };

                if changed.is_empty() {
                    self.record_board(BoardEvent::Submitted {
                        id: plan.ticket_id.clone(),
                        summary: board_summary,
                        at_ms: now_ms(),
                    });
                    self.finish_worker(current).await;
                    return Ok(self.finalize(
                        plan,
                        &run,
                        &job_id,
                        false,
                        None,
                        &feedback,
                        attempts,
                        models,
                        changed,
                        Vec::new(),
                        conflicts,
                        None,
                    ));
                }

                let Some(reviewer) = &plan.reviewer else {
                    self.record_board(BoardEvent::Submitted {
                        id: plan.ticket_id.clone(),
                        summary: board_summary,
                        at_ms: now_ms(),
                    });
                    self.record_board(BoardEvent::Failed {
                        id: plan.ticket_id.clone(),
                        reason: NO_REVIEWER.into(),
                        at_ms: now_ms(),
                    });
                    self.finish_worker(current).await;
                    return Ok(self.finalize(
                        plan,
                        &run,
                        &job_id,
                        false,
                        None,
                        "",
                        attempts,
                        models,
                        changed,
                        Vec::new(),
                        conflicts,
                        Some(NO_REVIEWER),
                    ));
                };

                self.record_board(BoardEvent::Submitted {
                    id: plan.ticket_id.clone(),
                    summary: board_summary,
                    at_ms: now_ms(),
                });

                let review = match self.review(plan, reviewer, &run.summary, &changed, current.slot, cancel).await {
                    Ok(review) => review,
                    Err(error) => {
                        *worker = Some(current);
                        return Err(error);
                    }
                };
                if cancel.is_cancelled() {
                    self.record_board(BoardEvent::Cancelled {
                        id: plan.ticket_id.clone(),
                        reason: "cancelled by the parent".into(),
                        at_ms: now_ms(),
                    });
                    *worker = Some(current);
                    return Err("CANCELLED: the delegation was cancelled".into());
                }
                feedback = review.feedback.clone();

                let Some(verdict) = review.accepted else {
                    self.record_board(BoardEvent::Failed {
                        id: plan.ticket_id.clone(),
                        reason: "review produced no verdict".into(),
                        at_ms: now_ms(),
                    });
                    self.finish_worker(current).await;
                    let mut final_run = run.clone();
                    final_run.summary = format!("{}\n\nreview produced no verdict", run.summary);
                    return Ok(self.finalize(
                        plan,
                        &final_run,
                        &job_id,
                        review.reviewed,
                        None,
                        &feedback,
                        attempts,
                        models,
                        changed,
                        Vec::new(),
                        conflicts,
                        None,
                    ));
                };

                if verdict {
                    self.record_board(BoardEvent::Accepted {
                        id: plan.ticket_id.clone(),
                        reviewer: review.job_id.clone(),
                        note: review.feedback.clone(),
                        at_ms: now_ms(),
                    });
                    self.record_perf(&plan.role_name, &model, Verdict::Accepted, worker_tokens);
                    let merge = self.merge_slot(current.slot, &changed, lost).await;
                    let merged = merge.merged;
                    let conflicts = format_conflicts(&merge.conflicts);
                    if merge.conflicts.is_empty() {
                        self.record_board(BoardEvent::Merged {
                            id: plan.ticket_id.clone(),
                            at_ms: now_ms(),
                        });
                    }
                    self.finish_worker(current).await;
                    return Ok(self.finalize(
                        plan,
                        &run,
                        &job_id,
                        true,
                        Some(true),
                        &review.feedback,
                        attempts,
                        models,
                        changed,
                        merged,
                        conflicts,
                        None,
                    ));
                }

                self.record_board(BoardEvent::Rejected {
                    id: plan.ticket_id.clone(),
                    reviewer: review.job_id.clone(),
                    feedback: review.feedback.clone(),
                    at_ms: now_ms(),
                });
                self.record_perf(&plan.role_name, &model, Verdict::Rejected, worker_tokens);
                rejections += 1;
                match self.next_after_review(false, rejections, &plan.role_name, &plan.candidates, &tried) {
                    NextStep::Merge => unreachable!("a rejection cannot merge"),
                    NextStep::Rework => {
                        let message = rework_attempt(&review.feedback, rejections);
                        if let Err(error) = current.job.append(vec![JobEvent::Message {
                            message: bulge_core::driver::harness_note(message),
                        }]) {
                            *worker = Some(current);
                            return Err(format!("append rework message: {error}"));
                        }
                        self.record_board(BoardEvent::Started {
                            id: plan.ticket_id.clone(),
                            at_ms: now_ms(),
                        });
                        continue;
                    }
                    NextStep::Replace(next) => {
                        self.finish_worker(current).await;
                        self.record_board(BoardEvent::Reassigned {
                            id: plan.ticket_id.clone(),
                            role: plan.role_name.clone(),
                            reason: format!("replaced after {rejections} rejections: {model} → {next}"),
                            at_ms: now_ms(),
                        });
                        model = next;
                        task = replacement_task(&plan.base_task, &review.feedback);
                        continue 'outer;
                    }
                    NextStep::Fail(reason) => {
                        self.record_board(BoardEvent::Failed {
                            id: plan.ticket_id.clone(),
                            reason: reason.clone(),
                            at_ms: now_ms(),
                        });
                        self.finish_worker(current).await;
                        return Ok(self.finalize(
                            plan,
                            &run,
                            &job_id,
                            true,
                            Some(false),
                            &review.feedback,
                            attempts,
                            models,
                            changed,
                            Vec::new(),
                            conflicts,
                            Some(&reason),
                        ));
                    }
                }
            }
        }
    }

    pub(crate) fn choose_first(&self, requested: Option<&str>, role: &str, candidates: &[String]) -> String {
        let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        first_model(requested, &book, role, candidates, &self.model)
    }

    pub(crate) fn next_after_review(&self, accepted: bool, rejections: u32, role: &str, candidates: &[String], tried: &[String]) -> NextStep {
        let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        next_step(accepted, rejections, &book, role, candidates, tried)
    }

    pub(crate) fn next_after_failure(&self, role: &str, candidates: &[String], tried: &[String]) -> NextStep {
        let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        failure_step(&book, role, candidates, tried)
    }

    /// Record one outcome and persist the book immediately. The lock is never
    /// held across an await (this method is synchronous).
    pub(crate) fn record_perf(&self, role: &str, model: &str, verdict: Verdict, tokens: u64) {
        let mut book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        book.record(role, model, verdict, tokens, now_ms());
        if let Err(error) = book.save(&self.perf_path) {
            eprintln!("org: save performance book {}: {error}", self.perf_path.display());
        }
    }

    pub(crate) fn record_board(&self, event: BoardEvent) {
        let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let OrgState { board, log, .. } = &mut *org;
        if let Err(error) = log.append(board, event) {
            eprintln!("org: board write failed: {error}");
        }
    }

    /// Mark a still-open ticket failed or cancelled. Terminal tickets are left
    /// alone, so an error after a deliberate Failed/Merged never double-writes.
    pub(crate) fn fail_if_open(&self, ticket: &str, reason: &str, cancelled: bool) {
        let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = org.board.get(ticket).map(|ticket| ticket.status);
        if matches!(
            status,
            Some(TicketStatus::Merged | TicketStatus::Cancelled | TicketStatus::Failed)
        ) {
            return;
        }
        let event = if cancelled {
            BoardEvent::Cancelled {
                id: ticket.to_string(),
                reason: reason.to_string(),
                at_ms: now_ms(),
            }
        } else {
            BoardEvent::Failed {
                id: ticket.to_string(),
                reason: reason.to_string(),
                at_ms: now_ms(),
            }
        };
        let OrgState { board, log, .. } = &mut *org;
        if let Err(error) = log.append(board, event) {
            eprintln!("org: terminal board write for ticket {ticket} failed: {error}");
        }
    }
}
