"""Release fence for issue #446; this release has no accepted model binding.

This is intentionally not a binding loader or an admission implementation.
Config, environment, caller registries and provider metadata cannot lift the
hold. A future reviewed change must implement authenticated admission before
returning no failure. Importing or querying this module performs no I/O.
"""

BINDING_STATUS = "UNBOUND"
# Canonical, sorted compact ASCII JSON of config/model-bindings/qwen.unbound.json.
BINDING_SHA256 = "6ebb5b746edb09845fc9d63fd5688409f049d8471744732fb55510e21ed29287"
MESSAGE = "Local AI is UNBOUND. Owner model binding and independent acceptance are not recorded."


def binding_failure() -> str | None:
    """No activation path exists in this release, including for other models."""
    return "OWNER_MODEL_BINDING_NOT_RECORDED"
