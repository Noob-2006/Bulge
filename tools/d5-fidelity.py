#!/usr/bin/env python3
"""d5 fidelity check: compare a ported SKILL.md body against its upstream body.

Usage: python3 tools/d5-fidelity.py [--json out.json]
Reports, per skill, how many upstream body lines (>=3 words) are missing from the port.
"""
import re, os, glob, json, sys

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERMES = '/home/noob/hermes-agent'
OPENCLAW = '/home/noob/openclaw'

def split(p):
    t = open(p, encoding='utf-8').read()
    m = re.match(r'^---\n(.*?)\n---\n', t, re.S)
    return (m.group(1), t[len(m.group(0)):]) if m else ('', t)

def norm(s):
    return re.sub(r'\s+', ' ', s).strip()

NAMED = ("1password blogwatcher blucli camsnap clawhub diagram-maker eightctl gemini gh-issues "
         "gifgrep github gog goplaces healthcheck himalaya meme-maker nano-pdf node-inspect-debugger "
         "notion obsidian openai-whisper openai-whisper-api openhue oracle ordercli python-debugpy sag "
         "sherpa-onnx-tts songsee sonoscli spike spotify-player summarize tmux trello visualize weather xurl").split()
CUSTODIAN = ["add-model-provider", "cloud-image-bake", "configure-channel", "diagnose-gateway"]
NA_MAC = ["apple-notes", "apple-reminders", "bear-notes", "things-mac", "peekaboo", "model-usage"]

ark = {}
for p in glob.glob(os.path.join(W, 'share/skills/**/SKILL.md'), recursive=True):
    ark.setdefault(p.split('/')[-2], p)

rows = []
def check(name, up_path):
    if name not in ark:
        rows.append({'name': name, 'up': up_path, 'ark': None, 'lines': 0, 'missing': [], 'ratio': 0})
        return
    _, up = split(up_path)
    _, a = split(ark[name])
    an = norm(a)
    lines = [l for l in up.split('\n') if len(l.split()) >= 3]
    miss = [l for l in lines if norm(l) not in an]
    rows.append({'name': name, 'up': up_path, 'ark': os.path.relpath(ark[name], W),
                 'lines': len(lines), 'missing': miss,
                 'ratio': round(os.path.getsize(ark[name]) / max(os.path.getsize(up_path), 1), 3)})

for n in NAMED:
    check(n, os.path.join(OPENCLAW, 'skills', n, 'SKILL.md'))
for n in CUSTODIAN:
    check(n, os.path.join(OPENCLAW, 'custodian-skills', n, 'SKILL.md'))
for n in NA_MAC:
    check(n, os.path.join(OPENCLAW, 'skills', n, 'SKILL.md'))

for r in rows:
    if r['ark'] is None:
        print(f"{r['name']:26s} NO ARK FILE")
        continue
    print(f"{r['name']:26s} lines={r['lines']:4d} missing={len(r['missing']):3d} ratio={r['ratio']:.2f} {r['ark']}")
    for l in r['missing'][:5]:
        print('      -', norm(l)[:110])

if '--json' in sys.argv:
    out = sys.argv[sys.argv.index('--json') + 1]
    json.dump(rows, open(out, 'w'), ensure_ascii=False, indent=1)
    print('wrote', out)
