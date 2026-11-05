#!/usr/bin/env python3
"""Validate layered role skill packs (L0/L1/L2) in this directory.

Checks, per share/roles/<layer>/<slug>/SKILL.md:
  1. frontmatter present, parseable, required keys, slug == directory name
  2. layer is L0/L1/L2; `extends` present exactly when layer != L0, and points
     to a pack that exists one layer up with a compatible isco code
  3. isco format: L0 = "all", L1 = one digit 0-9, L2 = four digits
  4. token budget (characters / 4): L0 <= 300, L1 <= 300, L2 <= 400
  5. no person name from audit/personas/MASTER.json appears anywhere in the file
  6. provenance/<slug>.json exists, covers every rule, and repeats its text
     (rules taken from the persona sections; the governance sections "Scope"
     and "Scope and boundaries" are sourced from boundaries.toml, not from
     personas, so they carry no persona record. A record left behind by a rule
     that was trimmed away is reported, not treated as a violation.)
  7. L0 carries the professional-scope rule
  8. L2 declares `regulated`; regulated packs declare `boundary: [<act ids>]`,
     every id exists in boundaries.toml, and the pack carries a short
     "## Scope and boundaries" section (<= 60 tokens). Unregulated packs carry
     neither a boundary list nor that section.
  9. boundaries.toml itself: every area names its acts, all defined; every area
     has may_do, hand_to, escalation, Taiwan statutes with URLs and notes, a
     mainland-China note.

Exit status is non-zero when any violation is found.

Usage: python3 check.py [--budget-margin N] [--quiet]
"""
from __future__ import annotations

import json
import os
import re
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - python < 3.11
    tomllib = None

HERE = os.path.dirname(os.path.abspath(__file__))
BOUNDARIES = os.path.join(HERE, "boundaries.toml")


def find_root():
    """Nearest ancestor holding audit/personas/MASTER.json, else three levels up."""
    cur = HERE
    for _ in range(6):
        if os.path.isfile(os.path.join(cur, "audit", "personas", "MASTER.json")):
            return cur
        cur = os.path.dirname(cur)
    return os.path.abspath(os.path.join(HERE, "..", "..", ".."))


ROOT = find_root()
MASTER = os.path.join(ROOT, "audit", "personas", "MASTER.json")
PROV = os.path.join(ROOT, "audit", "personas", "provenance")
LAYERS = ["L0", "L1", "L2"]
BUDGET = {"L0": 300, "L1": 300, "L2": 400}
REQUIRED = ["name", "title_zh", "layer", "isco", "description"]
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

SCOPE_HEADINGS = {"## Scope", "## Scope and boundaries"}
SECTION_LIMIT = 60          # tokens, for the L2 "## Scope and boundaries" section
L0_SCOPE_PROOF = [          # phrases the L0 scope rule must contain
    "role's scope",
    "reserves",
    "licensed",
    "professional of record",
    "emergency services",
]


def strip_comments(s: str) -> str:
    return "\n".join(l for l in s.splitlines() if not l.lstrip().startswith("#"))


def parse_frontmatter(text: str):
    """Return (meta dict, body str, error str|None)."""
    if not text.startswith("---\n"):
        return {}, text, "missing opening '---'"
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text, "missing closing '---'"
    raw = text[4:end]
    body = text[end + 5:]
    meta = {}
    for line in strip_comments(raw).splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            return {}, body, f"unparseable frontmatter line: {line!r}"
        k, v = line.split(":", 1)
        meta[k.strip()] = v.strip().strip('"').strip("'")
    return meta, body, None


def load_names():
    """Person names (Latin and CJK) that must never appear in a shipped pack."""
    if not os.path.exists(MASTER):
        return [], []
    with open(MASTER, encoding="utf-8") as f:
        master = json.load(f)
    latin, cjk = set(), set()
    for role in master.get("roles", []):
        for cand in role.get("candidates", []):
            for key in ("name", "name_zh", "name_en"):
                n = (cand.get(key) or "").strip()
                if not n:
                    continue
                # "Surname (alias)" -> also guard the short form
                variants = {n}
                m = re.match(r"^(.+?)\s*\((.+)\)$", n)
                if m:
                    variants |= {m.group(1).strip(), m.group(2).strip()}
                for v in variants:
                    if re.search(r"[\u3400-\u9fff\u3040-\u30ff\uac00-\ud7af]", v):
                        if len(v) >= 2:
                            cjk.add(v)
                    elif len(v) >= 4:
                        latin.add(v)
    return sorted(latin), sorted(cjk)


def name_hits(text: str, latin, cjk):
    hits = set()
    lowered = text.lower()
    for n in latin:
        if n.lower() not in lowered:
            continue
        if re.search(r"(?<![\w])" + re.escape(n.lower()) + r"(?![\w])", lowered):
            hits.add(n)
    for n in cjk:
        if n in text:
            hits.add(n)
    return hits


def token_estimate(text: str) -> float:
    """Characters / 4, as specified for the budgets."""
    return len(text) / 4.0


def split_rules(body: str):
    """Return (persona_rules, governance_rules): [(section, text)] each."""
    persona, governance = [], []
    heading = ""
    for line in body.splitlines():
        if line.startswith("## "):
            heading = line.strip()
            continue
        if line.startswith("- "):
            (governance if heading in SCOPE_HEADINGS else persona).append(
                (heading, line[2:].strip()))
    return persona, governance


def section_text(body: str, heading: str) -> str | None:
    """Return the text under `heading` (without the heading), or None."""
    lines = body.splitlines()
    out, inside = [], False
    for line in lines:
        if line.startswith("## "):
            inside = line.strip() == heading
            continue
        if inside:
            out.append(line)
    return "\n".join(out).strip() if out else None


def load_boundaries(problems):
    """Load boundaries.toml -> (act ids, area ids); validate the file itself."""
    if tomllib is None:
        problems.append("boundaries.toml: python < 3.11 cannot parse TOML")
        return set(), set()
    if not os.path.exists(BOUNDARIES):
        problems.append(f"{BOUNDARIES}: missing")
        return set(), set()
    try:
        with open(BOUNDARIES, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:  # noqa: BLE001
        problems.append(f"{BOUNDARIES}: invalid TOML: {e}")
        return set(), set()
    acts = data.get("acts", [])
    areas = data.get("areas", [])
    act_ids = set()
    for a in acts:
        for key in ("id", "zh", "en", "area"):
            if not a.get(key):
                problems.append(f"boundaries.toml: act {a.get('id', '?')} missing '{key}'")
        if a.get("id") in act_ids:
            problems.append(f"boundaries.toml: duplicate act id {a.get('id')!r}")
        act_ids.add(a.get("id"))
    area_ids = set()
    for area in areas:
        aid = area.get("id")
        area_ids.add(aid)
        for key in ("name_zh", "acts", "may_do", "hand_to", "escalation", "section", "tw", "cn"):
            if not area.get(key):
                problems.append(f"boundaries.toml: area {aid!r} missing '{key}'")
        for act in area.get("acts", []):
            if act not in act_ids:
                problems.append(f"boundaries.toml: area {aid!r} uses unknown act {act!r}")
        tw = area.get("tw") or {}
        if len(tw.get("statutes", [])) != len(tw.get("urls", [])):
            problems.append(f"boundaries.toml: area {aid!r} statute/URL counts differ")
        for url in tw.get("urls", []):
            if not url.startswith("https://law.moj.gov.tw/"):
                problems.append(f"boundaries.toml: area {aid!r} URL not on law.moj.gov.tw: {url}")
        if not tw.get("note"):
            problems.append(f"boundaries.toml: area {aid!r} has no Taiwan note")
    if not data.get("jurisdictions", {}).get("cn"):
        problems.append("boundaries.toml: no mainland-China note in [jurisdictions]")
    if not data.get("jurisdictions", {}).get("intl"):
        problems.append("boundaries.toml: no international note in [jurisdictions]")
    return act_ids, area_ids


def parse_boundary(value, path, problems):
    if value is None:
        problems.append(f"{path}: regulated pack has no 'boundary' list")
        return []
    raw = value.strip()
    if not (raw.startswith("[") and raw.endswith("]")):
        problems.append(f"{path}: boundary must be written as [a, b, c], got {raw!r}")
        return []
    ids = [x.strip().strip('"').strip("'") for x in raw[1:-1].split(",") if x.strip()]
    if not ids:
        problems.append(f"{path}: boundary list is empty")
    return ids


def collect():
    packs = {}
    for layer in LAYERS:
        base = os.path.join(HERE, layer)
        if not os.path.isdir(base):
            continue
        for slug in sorted(os.listdir(base)):
            path = os.path.join(base, slug, "SKILL.md")
            if os.path.isfile(path):
                packs[slug] = path
    return packs


def main(argv):
    quiet = "--quiet" in argv
    margin = 0
    if "--budget-margin" in argv:
        margin = int(argv[argv.index("--budget-margin") + 1])
    latin, cjk = load_names()
    packs = collect()
    problems = []
    notes = []

    if not packs:
        print("no packs found")
        return 1

    act_ids, area_ids = load_boundaries(problems)

    meta_by_slug = {}
    files = {}
    for slug, path in packs.items():
        text = open(path, encoding="utf-8").read()
        files[slug] = (path, text)
        meta, body, err = parse_frontmatter(text)
        meta_by_slug[slug] = (meta, body, path)
        if err:
            problems.append(f"{path}: {err}")
            continue
        for key in REQUIRED:
            if not meta.get(key):
                problems.append(f"{path}: missing frontmatter key '{key}'")
        if meta.get("layer") not in LAYERS:
            problems.append(f"{path}: layer must be one of {LAYERS}")
        if meta.get("name") != slug:
            problems.append(f"{path}: name '{meta.get('name')}' != directory '{slug}'")
        if not SLUG_RE.match(meta.get("name", "")):
            problems.append(f"{path}: name is not a kebab-case slug")
        desc = meta.get("description", "")
        if len(desc.split()) > 25:
            problems.append(f"{path}: description is {len(desc.split())} words (max 25)")

    for slug, (meta, body, path) in meta_by_slug.items():
        if not meta or "layer" not in meta:
            continue
        layer = meta["layer"]
        isco = meta.get("isco", "")
        if layer == "L0":
            if "extends" in meta:
                problems.append(f"{path}: L0 must not declare 'extends'")
            if isco not in ("all", "none"):
                problems.append(f"{path}: L0 isco must be 'all'")
        elif layer == "L1":
            if not re.fullmatch(r"[0-9]", isco):
                problems.append(f"{path}: L1 isco must be a single digit, got {isco!r}")
            parent = meta.get("extends")
            if not parent:
                problems.append(f"{path}: L1 must declare 'extends'")
            elif parent not in meta_by_slug:
                problems.append(f"{path}: extends unknown pack {parent!r}")
            else:
                pmeta = meta_by_slug[parent][0]
                if pmeta.get("layer") != "L0":
                    problems.append(f"{path}: L1 parent {parent!r} is not L0")
        else:  # L2
            if not re.fullmatch(r"[0-9]{4}", isco):
                problems.append(f"{path}: L2 isco must be a 4-digit unit-group code, got {isco!r}")
            parent = meta.get("extends")
            if not parent:
                problems.append(f"{path}: L2 must declare 'extends'")
            elif parent not in meta_by_slug:
                problems.append(f"{path}: extends unknown pack {parent!r}")
            else:
                pmeta = meta_by_slug[parent][0]
                if pmeta.get("layer") != "L1":
                    problems.append(f"{path}: L2 parent {parent!r} is not L1")
                elif pmeta.get("isco") != isco[0]:
                    problems.append(
                        f"{path}: parent {parent!r} is group {pmeta.get('isco')}, "
                        f"not group {isco[0]} of {isco}")

            # professional-scope boundaries
            flag = meta.get("regulated")
            if flag not in ("true", "false", "True", "False"):
                problems.append(f"{path}: L2 must declare 'regulated: true' or 'false'")
            elif flag.lower() == "true":
                ids = parse_boundary(meta.get("boundary"), path, problems)
                for i in ids:
                    if i not in act_ids:
                        problems.append(f"{path}: boundary id {i!r} is not in boundaries.toml")
                sec = section_text(body, "## Scope and boundaries")
                if sec is None:
                    problems.append(f"{path}: regulated pack lacks '## Scope and boundaries'")
                elif token_estimate(sec) > SECTION_LIMIT:
                    problems.append(f"{path}: scope section is {token_estimate(sec):.0f} tokens "
                                    f"(max {SECTION_LIMIT})")
            else:
                if "boundary" in meta:
                    problems.append(f"{path}: unregulated pack must not declare 'boundary'")
                if section_text(body, "## Scope and boundaries") is not None:
                    problems.append(f"{path}: unregulated pack must not carry a scope section")

        text = files[slug][1]
        tok = token_estimate(text)
        limit = BUDGET[layer] - margin
        if tok > limit:
            problems.append(f"{path}: {tok:.0f} tokens (chars/4) over budget {limit}")

        hits = name_hits(text, latin, cjk)
        for h in sorted(hits):
            problems.append(f"{path}: person name leaked: {h!r}")

        persona_rules, gov_rules = split_rules(body)

        if layer == "L0":
            scope = [r for _, r in gov_rules]
            joined = " ".join(scope).lower()
            if not scope:
                problems.append(f"{path}: L0 lacks the professional-scope rule")
            else:
                for phrase in L0_SCOPE_PROOF:
                    if phrase not in joined:
                        problems.append(f"{path}: L0 scope rule does not mention {phrase!r}")

        # provenance integrity
        prov_path = os.path.join(PROV, slug + ".json")
        if not os.path.exists(prov_path):
            problems.append(f"{prov_path}: missing provenance file")
        else:
            try:
                prov = json.load(open(prov_path, encoding="utf-8"))
            except json.JSONDecodeError as e:
                problems.append(f"{prov_path}: invalid JSON: {e}")
                continue
            for p in prov:
                if not p.get("from"):
                    problems.append(f"{prov_path}: rule {p.get('rule_index')} has no sources")
                for src in p.get("from", []):
                    if not src.get("name") or not src.get("method") or not src.get("sources"):
                        problems.append(
                            f"{prov_path}: rule {p.get('rule_index')} has an incomplete entry")
            texts = [" ".join(str(p.get("rule", "")).split()) for p in prov]
            used = set()
            pos = 0
            missing = 0
            for _, rule in persona_rules:
                want = " ".join(rule.split())
                try:
                    at = texts.index(want, pos)
                except ValueError:
                    missing += 1
                    problems.append(f"{prov_path}: rule has no provenance record: {rule[:60]!r}")
                    continue
                used.add(at)
                pos = at + 1
            retired = len(texts) - len(used)
            if retired:
                notes.append((slug, retired))

    # coverage: exactly one L1 per ISCO major group
    l1 = {}
    for slug, (meta, body, path) in meta_by_slug.items():
        if meta.get("layer") == "L1":
            l1.setdefault(meta.get("isco"), []).append(slug)
    missing = [d for d in "0123456789" if d not in l1]
    if missing:
        problems.append("L1 coverage: no pack for ISCO major group(s) " + ", ".join(missing))
    for isco, slugs in l1.items():
        if len(slugs) > 1:
            problems.append(f"L1 coverage: group {isco} has several packs {slugs}")

    regulated = sum(1 for _, (meta, _, _) in meta_by_slug.items()
                    if str(meta.get("regulated", "")).lower() == "true")
    if not quiet:
        for slug in sorted(meta_by_slug):
            meta, body, path = meta_by_slug[slug]
            tok = token_estimate(files[slug][1])
            n_rules = len(split_rules(body)[0])
            reg = ""
            if meta.get("layer") == "L2":
                reg = " regulated" if str(meta.get("regulated", "")).lower() == "true" else ""
            print(f"{meta.get('layer', '?'):3s} {slug:24s} isco={meta.get('isco', '?'):5s} "
                  f"tok≈{tok:5.1f}/{BUDGET.get(meta.get('layer'), 0):3d} rules={n_rules}{reg}")
    if problems:
        print(f"\n{len(problems)} violation(s):")
        for p in problems:
            print("  - " + p)
        return 1
    if not quiet and notes:
        total = sum(n for _, n in notes)
        print(f"note: {total} provenance record(s) retired across {len(notes)} pack(s), "
              f"from rules trimmed to fit the token budget")
    print(f"\nOK: {len(packs)} packs valid, {regulated} regulated L2 packs, "
          f"{len(act_ids)} reserved acts in boundaries.toml, no leaked names, budgets respected.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
