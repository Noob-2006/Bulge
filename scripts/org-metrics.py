#!/usr/bin/env python3
"""Aggregate Bessemer-L6 capability metrics across many bulge organization runs.

Every org run leaves durable, append-only logs: <job>/org/board.jsonl (the ticket
state machine), <job>/org/bus.jsonl (Rep-Link reports), and the head job.jsonl
(delegate tool results with per-ticket tokens/models). This reads a set of job
stores and reports, in aggregate, how often each L6 verb actually fired —
measurement from logs, not anecdote.

usage: org-metrics.py <jobs-dir-or-board.jsonl> ...
"""
import json, sys, glob, os
from collections import defaultdict

def load_board(path):
    tickets = {}
    order = []
    events = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        events.append(e)
        t = e.get("type")
        if t == "posted":
            tk = e["ticket"]
            tickets[tk["id"]] = dict(tk)
            tickets[tk["id"]]["_events"] = []
            order.append(tk["id"])
        tid = e.get("id") or (e.get("ticket", {}) or {}).get("id")
        if tid in tickets:
            tickets[tid]["_events"].append(t)
            if t == "claimed" and e.get("owner"):
                tickets[tid]["owner"] = e["owner"]
            if t == "reassigned" and e.get("role"):
                tickets[tid]["role"] = e["role"]
            if t in ("posted","claimed","started","submitted","accepted","rejected","reassigned","merged","failed","cancelled","blocked","unblocked"):
                tickets[tid]["status"] = t
    return tickets, order, events

def head_reports(job_jsonl):
    """delegate tool results on the head: role/ticket/tokens/models/reviewed/accepted."""
    out = []
    if not os.path.exists(job_jsonl):
        return out
    for line in open(job_jsonl):
        if '"tool_completed"' not in line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        r = e.get("result")
        if isinstance(r, dict) and r.get("ticket") and r.get("role"):
            out.append(r)
    return out

def depth_of(tid, tickets):
    d = 0
    seen = set()
    while tid and tid in tickets and tid not in seen:
        seen.add(tid)
        p = tickets[tid].get("parent")
        if not p:
            break
        d += 1
        tid = p
    return d

def main():
    boards = []
    for arg in sys.argv[1:]:
        if arg.endswith("board.jsonl"):
            boards.append(arg)
        else:
            boards += glob.glob(os.path.join(arg, "**", "org", "board.jsonl"), recursive=True)
    boards = sorted(set(boards))
    agg = defaultdict(int)
    role_model = set()
    roles_used = set()
    runs = 0
    per_run = []
    for b in boards:
        tickets, order, events = load_board(b)
        if not tickets:
            continue
        runs += 1
        job_dir = os.path.dirname(os.path.dirname(b))
        reports = head_reports(os.path.join(job_dir, "job.jsonl"))
        rep_by = {}
        for r in reports:
            rep_by[r["ticket"]] = r
        maxdepth = max((depth_of(t, tickets) for t in tickets), default=0)
        # parallel fan-out: largest set of siblings all started before any of them submitted
        starts = [e for e in events if e.get("type") == "started"]
        submits = {e["id"]: i for i, e in enumerate(events) if e.get("type") == "submitted"}
        by_parent = defaultdict(list)
        for tid, tk in tickets.items():
            by_parent[tk.get("parent")].append(tid)
        fanout = 0
        start_idx = {e["id"]: i for i, e in enumerate(events) if e.get("type") == "started" and "id" in e}
        for parent, kids in by_parent.items():
            # kids started before the first of them submitted = concurrent
            kid_starts = sorted((start_idx[k], k) for k in kids if k in start_idx)
            if not kid_starts:
                continue
            first_submit = min((submits[k] for k in kids if k in submits), default=10**9)
            concurrent = sum(1 for i, k in kid_starts if i < first_submit)
            fanout = max(fanout, concurrent)
        reviewed = sum(1 for r in reports if r.get("reviewed"))
        changed_tickets = sum(1 for r in reports if r.get("changed"))
        reworks = sum(1 for tk in tickets.values() if tk["_events"].count("started") > 1 and "rejected" in tk["_events"])
        rejects = sum(1 for tk in tickets.values() if "rejected" in tk["_events"])
        replacements = sum(1 for tk in tickets.values() if "reassigned" in tk["_events"]) + sum(1 for r in reports if len(r.get("models") or []) > 1)
        for tk in tickets.values():
            roles_used.add(tk.get("role"))
        for r in reports:
            for m in (r.get("models") or [r.get("model")] or []):
                if m:
                    role_model.add((r["role"], m))
        agg["tickets"] += len(tickets)
        agg["reviewed"] += reviewed
        agg["changed_tickets"] += changed_tickets
        agg["reworks"] += reworks
        agg["rejects"] += rejects
        agg["replacements"] += replacements
        agg["maxdepth"] = max(agg["maxdepth"], maxdepth)
        agg["fanout_runs"] += 1 if fanout >= 2 else 0
        agg["max_fanout"] = max(agg["max_fanout"], fanout)
        per_run.append((os.path.relpath(job_dir), len(tickets), maxdepth, fanout, reviewed, reworks, replacements))

    print(f"=== Bessemer L6 capability metrics across {runs} real organization runs ===\n")
    print(f"total tickets delegated           {agg['tickets']}")
    print(f"distinct roles recruited          {sorted(r for r in roles_used if r)}")
    print(f"distinct (role,model) pairs used  {len(role_model)}  {sorted(role_model)}")
    print(f"max org levels reached            {agg['maxdepth'] + 2}  (head + {agg['maxdepth'] + 1} delegated levels; e.g. CEO -> dept lead -> worker = 3)")
    print(f"runs with parallel fan-out >=2    {agg['fanout_runs']}  (max concurrent siblings in one run: {agg['max_fanout']})")
    print(f"tickets that changed files        {agg['changed_tickets']}")
    print(f"  of those, independently reviewed {agg['reviewed']}  ({100*agg['reviewed']//max(agg['changed_tickets'],1)}%)")
    print(f"rejection->rework cycles          {agg['reworks']}  (total rejections: {agg['rejects']})")
    print(f"worker replacements (reassign/model-swap) {agg['replacements']}")
    print()
    print(f"{'run':44} {'tk':>3} {'depth':>5} {'fan':>3} {'rev':>3} {'rwk':>3} {'rpl':>3}")
    for name, tk, d, f, rv, rw, rp in sorted(per_run):
        print(f"{name[-44:]:44} {tk:>3} {d:>5} {f:>3} {rv:>3} {rw:>3} {rp:>3}")

main()
