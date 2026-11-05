"""Fixture plugin: the shape Hermes loads (a package with register(ctx)).

Its hook returns a Hermes directive (`{"action": "block", ...}`), which the shim
translates to ark's `{"decision": "deny", ...}`, and its tool is exported as
`guard_demo_check`.
"""

PATTERNS = ("pickle.load", "eval(")


def guard_demo_check(text=""):
    hits = [p for p in PATTERNS if p in (text or "")]
    return {"ok": not hits, "hits": hits}


def _on_pre_tool_call(tool_name="", args=None, **_):
    blob = "" if args is None else str(args)
    if any(p in blob for p in PATTERNS):
        return {"action": "block", "message": "guard-demo refused this write"}
    return None


def _on_transform_tool_result(tool_name="", result=None, **_):
    """Hermes transform hook: return the replacement text (or None for unchanged)."""
    if not isinstance(result, str):
        return None
    return result + "\n[guard-demo: reviewed]"


def register(ctx):
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
    ctx.register_command("guard-demo", lambda *a, **k: "guard-demo: ok", description="Show the guard status")
