#!/usr/bin/env python3
"""Regenerate ark's bundled skills and hub catalogs from the Hermes and OpenClaw checkouts
(both MIT). Usage: port_skills.py <hermes-agent> <openclaw> <ark-share-dir>

- share/skills/<category>/<name>/   Hermes skills/ (minus Hermes-internal ones) and OpenClaw
  skills/ + custodian-skills/ (category "openclaw" / "custodian"); when both ship a skill of the
  same name the Hermes one is primary and the upstream OpenClaw procedure is appended verbatim
  under `## OpenClaw procedure (upstream openclaw/skills/<name>, MIT, verbatim)`.
  Hand-maintained skills (see PRESERVE) are copied aside and restored after the rebuild, so
  `ark-agent`, `ark-skill-authoring` and the hand-placed macOS ports survive a regeneration.
- share/optional-skills/index.json  catalog of Hermes optional-skills/ (installed via the hub
  "official" source, fetched from the upstream repo on demand; not vendored).
- share/plugin-catalog/index.json   Hermes plugin-catalog/*.yaml.
- share/optional-mcps/index.json    Hermes optional-mcps/*/manifest.yaml.
- share/blueprints.json             Hermes cron/blueprint_catalog.py CATALOG.
"""
import json, os, re, shutil, sys, tempfile
import yaml

hermes, openclaw, share = sys.argv[1], sys.argv[2], sys.argv[3]
# Hermes-internal product docs: `hermes-agent` and `hermes-agent-skill-authoring` ship here as the
# adapted ark ports (see PRESERVE); `inspecting-hermes-desktop-dom` is N/A (Hermes Electron app).
HERMES_SKIP = {"hermes-agent", "hermes-agent-skill-authoring", "inspecting-hermes-desktop-dom"}
# macOS-only / OpenClaw-app-only skills and ones ark covers natively. bear-notes/things-mac/peekaboo/
# model-usage are transcribed by hand (PRESERVE) with a `## Platform note`; apple-notes/apple-reminders
# exist as Hermes ports and pick up the OpenClaw procedure through the merge branch (not skipped).
OPENCLAW_SKIP = {"bear-notes", "control-ui", "mcporter", "model-usage", "node-connect", "peekaboo", "things-mac", "coding-agent", "skill-creator"}
SKIP_FILES = {".DS_Store"}
# Hand-maintained skill directories (repo-relative), copied aside before the rebuild and put back
# afterwards; the generator never writes these from upstream. Keep the list in sync with
# `share/skills/**` and `crates/ark-skills/tests/content.rs`.
PRESERVE = [
    "skills/autonomous-ai-agents/ark-agent",          # adapted from hermes-agent
    "skills/software-development/ark-skill-authoring",  # adapted from hermes-agent-skill-authoring
    "skills/apple/bear-notes",
    "skills/apple/things-mac",
    "skills/apple/peekaboo",
    "skills/devops/model-usage",
]

def fm_split(text):
    if not text.startswith("---"):
        return None, text
    m = re.search(r"\n---\s*\n", text[3:])
    if not m:
        return None, text
    return text[3:m.start() + 3], text[m.end() + 3:]

def adapt(text, origin):
    head, body = fm_split(text)
    note = f"upstream: \"{origin} (MIT)\"\n"
    if head is None:
        return f"---\n{note}---\n{text}"
    return f"---\n{note}{head.lstrip(chr(10))}\n---\n{body}"

def copy_skill(src, dest, origin):
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("__pycache__", "node_modules", ".DS_Store", "*.pyc"))
    p = os.path.join(dest, "SKILL.md")
    with open(p, encoding="utf-8-sig") as f:
        t = f.read()
    with open(p, "w", encoding="utf-8") as f:
        f.write(adapt(t, origin))

def merge_openclaw_inline(dest, src, name):
    """Append the upstream OpenClaw procedure to the Hermes skill, verbatim.

    The OpenClaw body keeps every command, flag, prerequisite and safety note; its H1 is dropped
    and the remaining headings are demoted one level so they nest under the section heading (code
    fences are left alone). The section is labelled with both the origin path and the MIT licence.
    """
    dest, src = os.path.join(dest, "SKILL.md"), os.path.join(src, "SKILL.md")
    with open(dest, encoding="utf-8") as f:
        cur = f.read()
    with open(src, encoding="utf-8-sig") as f:
        _, body = fm_split(f.read())
    lines, fence, seen_h1 = [], False, False
    for line in body.split("\n"):
        if line.startswith("```"):
            fence = not fence
        if not fence and line.startswith("# ") and not seen_h1:
            seen_h1 = True
            continue
        if not fence and re.match(r"^#{2,5} ", line):
            line = "#" + line
        lines.append(line)
    text = "\n".join(lines).strip("\n")
    head = f"## OpenClaw procedure (upstream `openclaw/skills/{name}`, MIT, verbatim)"
    tail = (
        f"> Transcribed from `openclaw/skills/{name}/SKILL.md` (MIT, © OpenClaw contributors). "
        "OpenClaw-only runtime hooks (gateway service env, session URLs, OpenClaw node/pairing state) "
        "apply only under OpenClaw; the commands, flags and safety notes are portable."
    )
    with open(dest, "w", encoding="utf-8") as f:
        f.write(cur.rstrip("\n") + "\n\n" + head + "\n\n" + text + "\n\n" + tail + "\n")

out_skills = os.path.join(share, "skills")
# Stash the hand-maintained skills before the rebuild wipes the tree.
stash = tempfile.mkdtemp(prefix="ark-skills-preserve-")
kept = []
for rel in PRESERVE:
    src = os.path.join(share, rel)
    if os.path.isdir(src):
        dst = os.path.join(stash, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copytree(src, dst)
        kept.append(rel)
if os.path.exists(out_skills):
    shutil.rmtree(out_skills)
os.makedirs(out_skills)
names = {}
for root, dirs, files in os.walk(os.path.join(hermes, "skills")):
    dirs[:] = sorted(d for d in dirs if d not in ("index-cache", "__pycache__"))
    if "SKILL.md" in files:
        name = os.path.basename(root)
        rel = os.path.relpath(root, os.path.join(hermes, "skills"))
        dirs[:] = []
        if name in HERMES_SKIP:
            continue
        dest = os.path.join(out_skills, rel)
        copy_skill(root, dest, f"hermes-agent/skills/{rel}")
        names[name] = dest
for cat in ("skills", "custodian-skills"):
    base = os.path.join(openclaw, cat)
    for name in sorted(os.listdir(base)):
        src = os.path.join(base, name)
        if not os.path.isfile(os.path.join(src, "SKILL.md")) or name in OPENCLAW_SKIP:
            continue
        origin = f"openclaw/{cat}/{name}"
        if name in names:
            merge_openclaw_inline(names[name], src, name)
            continue
        dest = os.path.join(out_skills, "openclaw" if cat == "skills" else "custodian", name)
        copy_skill(src, dest, origin)
        names[name] = dest
for d in ("DESCRIPTION.md",):
    pass

# Restore the hand-maintained skills (never overwritten by upstream content).
for rel in kept:
    src, dst = os.path.join(stash, rel), os.path.join(share, rel)
    if os.path.exists(dst):
        shutil.rmtree(dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copytree(src, dst)
shutil.rmtree(stash, ignore_errors=True)

# optional-skills catalog
idx = []
base = os.path.join(hermes, "optional-skills")
for root, dirs, files in os.walk(base):
    dirs[:] = sorted(dirs)
    if "SKILL.md" in files:
        dirs[:] = []
        rel = os.path.relpath(root, base)
        with open(os.path.join(root, "SKILL.md"), encoding="utf-8-sig") as f:
            head, _ = fm_split(f.read())
        try:
            fm = yaml.safe_load(head or "") or {}
        except yaml.YAMLError:
            fm = {}
        meta = (fm.get("metadata") or {}).get("hermes") or {} if isinstance(fm.get("metadata"), dict) else {}
        tags = meta.get("tags") if isinstance(meta, dict) else []
        files_list = sorted(os.path.relpath(os.path.join(r, x), root) for r, _, fs in os.walk(root) for x in fs if "__pycache__" not in r)
        idx.append({"name": str(fm.get("name") or os.path.basename(root)), "path": rel, "description": str(fm.get("description") or "").strip(), "tags": tags if isinstance(tags, list) else [], "files": files_list})
os.makedirs(os.path.join(share, "optional-skills"), exist_ok=True)
json.dump({"repo": "NousResearch/hermes-agent", "prefix": "optional-skills", "skills": idx}, open(os.path.join(share, "optional-skills/index.json"), "w"), indent=1, ensure_ascii=False)

# plugin catalog
plugins = []
for fn in sorted(os.listdir(os.path.join(hermes, "plugin-catalog"))):
    if not fn.endswith(".yaml") or fn == "removed.yaml":
        continue
    try:
        e = yaml.safe_load(open(os.path.join(hermes, "plugin-catalog", fn), encoding="utf-8")) or {}
    except yaml.YAMLError:
        continue
    if not isinstance(e, dict) or not e.get("name") or not e.get("repo"):
        continue
    caps = e.get("capabilities") or {}
    plugins.append({k: e.get(k) for k in ("name", "repo", "sha", "description", "maintainer", "tier", "category", "docs_url", "version", "platforms", "subdir")} | {"requires_env": caps.get("requires_env") or []})
os.makedirs(os.path.join(share, "plugin-catalog"), exist_ok=True)
json.dump({"plugins": plugins}, open(os.path.join(share, "plugin-catalog/index.json"), "w"), indent=1, ensure_ascii=False)

# optional MCPs
mcps = []
base = os.path.join(hermes, "optional-mcps")
for name in sorted(os.listdir(base)):
    p = os.path.join(base, name, "manifest.yaml")
    if os.path.isfile(p):
        m = yaml.safe_load(open(p, encoding="utf-8")) or {}
        mcps.append({"name": m.get("name") or name, "description": (m.get("description") or "").strip(), "source": m.get("source"), "transport": m.get("transport") or {}, "auth": m.get("auth") or {}, "post_install": (m.get("post_install") or "").strip(), "keywords": ((m.get("suggest") or {}).get("keywords") or [])})
os.makedirs(os.path.join(share, "optional-mcps"), exist_ok=True)
json.dump({"mcps": mcps}, open(os.path.join(share, "optional-mcps/index.json"), "w"), indent=1, ensure_ascii=False)

# blueprint catalog (pure data module)
import importlib.util
_spec = importlib.util.spec_from_file_location("blueprint_catalog", os.path.join(hermes, "cron/blueprint_catalog.py"))
_mod = importlib.util.module_from_spec(_spec)
sys.modules["blueprint_catalog"] = _mod
_spec.loader.exec_module(_mod)
CATALOG = _mod.CATALOG
bps = []
for b in CATALOG:
    bps.append({"key": b.key, "title": b.title, "description": b.description, "category": b.category, "schedule_template": b.schedule_template, "prompt_template": b.prompt_template, "deliver_default": b.deliver_default, "skills": list(b.skills), "tags": list(b.tags), "slots": [{"name": s.name, "type": s.type, "label": s.label, "default": s.default, "options": list(s.options), "optional": s.optional, "help": s.help, "strict": s.strict} for s in b.slots]})
json.dump({"blueprints": bps}, open(os.path.join(share, "blueprints.json"), "w"), indent=1, ensure_ascii=False)
print(f"skills={sum(1 for _ in os.popen(f'find {out_skills} -name SKILL.md'))} optional={len(idx)} plugins={len(plugins)} mcps={len(mcps)} blueprints={len(bps)}")
