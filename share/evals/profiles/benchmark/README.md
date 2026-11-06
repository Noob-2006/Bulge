# Minimal benchmark profile

A small, deterministic surface for model-to-model comparisons: `shell`, `read` (images
included) and `run` (code mode), plus a short identity. No write/edit, skills, subagents,
messaging or automation.

```bash
seagent profile install share/evals/profiles/benchmark
seagent evals bench --suite builtin:smoke --model deepseek/deepseek-chat \
  --tool-profile benchmark --out evals-out/benchmark
```

`--tool-profile NAME` applies any built-in tool policy (`benchmark`, `minimal`, `coding`, …)
to the in-process kernel attempts; external agents are unaffected.
