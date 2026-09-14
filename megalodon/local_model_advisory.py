"""No-network preflight for one bounded local-model advisory request.

This module constructs an immutable prompt plan only.  It never contacts a
provider, loads a model, reads local evidence, or changes host state.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal


POLICY_VERSION = "local-model-advisory-v1"
APPROVED_MODEL_ID = "local:qwen-approved-v1"
MAX_INPUT_BYTES = 4096

_PROJECTION_FIELDS = frozenset(
    {
        "source_kind",
        "adapter_id",
        "terminal_status",
        "accepted_records",
        "rejected_records",
        "candidate_count",
        "question_type",
    }
)
_RECEIPT_FIELDS = frozenset(
    {"provider_class", "model_id", "model_artifact_sha256", "policy_version"}
)
_LIMIT_FIELDS = frozenset(
    {"max_input_bytes", "max_output_bytes", "timeout_seconds", "max_concurrency"}
)
_SOURCE_KINDS = frozenset({"sample", "jsonl", "scapy", "tshark", "zeek-json", "zeek-tsv"})
_TERMINAL_STATUSES = frozenset({"complete", "failed"})
_QUESTION_TYPES = frozenset({"explain_run", "explain_rule_limitations"})
_LOGICAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class AirlockPlan:
    """An immutable, local plan that is not permission to call a model."""

    model_id: str
    model_artifact_sha256: str
    prompt: str


@dataclass(frozen=True)
class PreflightDecision:
    """A finite decision without input echoing or side effects."""

    outcome: Literal["ADMIT", "DENY"]
    code: Literal["PROMPT_CONSTRUCTION_ADMITTED", "POLICY_DENIED"]
    summary: str
    plan: AirlockPlan | None = None


def preflight(request: object) -> PreflightDecision:
    """Validate one closed request and construct a canonical prompt plan.

    An admitted result authorizes prompt construction only.  It does not
    authorize a model request, a provider probe, or a host or network action.
    """

    if type(request) is not dict or set(request) != {
        "projection",
        "model_receipt",
        "limits",
    }:
        return _deny()

    projection = request["projection"]
    receipt = request["model_receipt"]
    limits = request["limits"]
    if not _valid_projection(projection):
        return _deny()
    if not _valid_receipt(receipt):
        return _deny()
    if not _valid_limits(limits):
        return _deny()

    prompt = _canonical_prompt(projection)
    if len(prompt.encode("utf-8")) > MAX_INPUT_BYTES:
        return _deny()

    return PreflightDecision(
        outcome="ADMIT",
        code="PROMPT_CONSTRUCTION_ADMITTED",
        summary="Canonical metadata-only prompt constructed; no model request was made.",
        plan=AirlockPlan(
            model_id=receipt["model_id"],
            model_artifact_sha256=receipt["model_artifact_sha256"],
            prompt=prompt,
        ),
    )


def _valid_projection(value: object) -> bool:
    if type(value) is not dict or set(value) != _PROJECTION_FIELDS:
        return False
    return (
        _one_of(value["source_kind"], _SOURCE_KINDS)
        and _logical_id(value["adapter_id"])
        and _one_of(value["terminal_status"], _TERMINAL_STATUSES)
        and _count(value["accepted_records"])
        and _count(value["rejected_records"])
        and _count(value["candidate_count"])
        and _one_of(value["question_type"], _QUESTION_TYPES)
    )


def _valid_receipt(value: object) -> bool:
    if type(value) is not dict or set(value) != _RECEIPT_FIELDS:
        return False
    return (
        value["provider_class"] == "local_loopback"
        and value["model_id"] == APPROVED_MODEL_ID
        and type(value["model_artifact_sha256"]) is str
        and _SHA256.fullmatch(value["model_artifact_sha256"]) is not None
        and value["policy_version"] == POLICY_VERSION
    )


def _valid_limits(value: object) -> bool:
    return type(value) is dict and value == {
        "max_input_bytes": MAX_INPUT_BYTES,
        "max_output_bytes": 4096,
        "timeout_seconds": 15,
        "max_concurrency": 1,
    }


def _canonical_prompt(projection: dict[str, object]) -> str:
    return "\n".join(
        (
            "MEGALODON_LOCAL_ADVISORY_V1",
            "role=metadata_only_explainer",
            f"question_type={projection['question_type']}",
            f"source_kind={projection['source_kind']}",
            f"adapter_id={projection['adapter_id']}",
            f"terminal_status={projection['terminal_status']}",
            f"accepted_records={projection['accepted_records']}",
            f"rejected_records={projection['rejected_records']}",
            f"candidate_count={projection['candidate_count']}",
            "instruction=Explain only the typed aggregate metadata. Do not infer evidence or actions.",
        )
    )


def _one_of(value: object, choices: frozenset[str]) -> bool:
    return type(value) is str and not _has_control(value) and value in choices


def _logical_id(value: object) -> bool:
    return (
        type(value) is str
        and not _has_control(value)
        and _LOGICAL_ID.fullmatch(value) is not None
    )


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= 1_000_000


def _has_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _deny() -> PreflightDecision:
    return PreflightDecision(
        outcome="DENY",
        code="POLICY_DENIED",
        summary="The advisory request is outside the no-network preflight policy.",
    )
