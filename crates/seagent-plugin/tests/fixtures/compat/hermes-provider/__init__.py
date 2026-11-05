"""Fixture: a Hermes model provider (kind: model-provider)."""


def register(ctx):
    ctx.register_model_provider("anthropic", object())
