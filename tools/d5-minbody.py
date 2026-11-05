#!/usr/bin/env python3
"""Generate the MIN_BODY table for crates/ark-skills/tests/content.rs.

For every bundled skill the test asserts that the ported body keeps at least 60% of the
character count of the upstream body it claims to carry (adapted ports: 50%), so the
threshold is derived from upstream instead of a made-up constant. Merged skills (Hermes
body + appended verbatim OpenClaw procedure) get 60% of the sum of both upstream bodies.

Usage: python3 tools/d5-minbody.py            # check + print stats
       python3 tools/d5-minbody.py --rust     # emit the Rust const
"""
import re, os, glob, sys

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERMES, OPENCLAW = '/home/noob/hermes-agent', '/home/noob/openclaw'

def body(path):
    t = open(path, encoding='utf-8').read()
    m = re.match(r'^---\n(.*?)\n---\n', t, re.S)
    return t[len(m.group(0)):] if m else t

ARK = {}
for p in glob.glob(os.path.join(W, 'share/skills/**/SKILL.md'), recursive=True):
    ARK.setdefault(p.split('/')[-2], p)

# ark renamed two Hermes-internal skills when adapting them for ark.
UPSTREAM_NAME = {'ark-agent': 'hermes-agent', 'ark-skill-authoring': 'hermes-agent-skill-authoring'}

rows = []
for name, path in sorted(ARK.items()):
    h = os.path.join(HERMES, 'skills')
    hits = glob.glob(f'{h}/**/{UPSTREAM_NAME.get(name, name)}/SKILL.md', recursive=True)
    o = f'{OPENCLAW}/skills/{name}/SKILL.md'
    oc = f'{OPENCLAW}/custodian-skills/{name}/SKILL.md'
    merged = '## OpenClaw procedure' in open(path, encoding='utf-8').read()
    sizes = []
    if hits:
        sizes.append(len(body(hits[0])))
    if os.path.exists(o):
        sizes.append(len(body(o)))
    if os.path.exists(oc):
        sizes.append(len(body(oc)))
    # merged ports carry both upstreams inline → sum; single-variant ports only have to beat the
    # larger of the two upstreams they stand in for.
    up = sum(sizes) if merged else max(sizes, default=0)
    cur = len(body(path))
    frac = 0.6
    if name in ('ark-agent', 'ark-skill-authoring'):
        frac = 0.5
    if up == 0:
        # no upstream (none currently): fixed floor
        rows.append((name, cur, 350, cur / 350 if cur else 0))
        continue
    rows.append((name, cur, int(up * frac), cur / (up * frac) if up else 0))

bad = [r for r in rows if r[1] < r[2]]
print(f"{len(rows)} skills; failing {len(bad)}")
for r in rows:
    flag = 'FAIL' if r[1] < r[2] else ''
    if flag or r[3] < 1.25:
        print(f"  {r[0]:26s} body={r[1]:6d} min={r[2]:6d} headroom={r[3]:.2f} {flag}")
if bad:
    print("?? skills below the derived minimum:", [b[0] for b in bad])
if '--rust' in sys.argv:
    out = ['/// Per-skill floor: 60% of the upstream body it claims to carry (50% for the two',
           '/// adapted ports). Derived by `tools/d5-minbody.py`; never lower a value here.',
           'const MIN_BODY_CHARS: &[(&str, usize)] = &[']
    for name, cur, mn, _ in rows:
        out.append(f'    ("{name}", {mn}),')
    out.append('];')
    print('\n'.join(out))
