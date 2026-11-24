"""Dependency-free wire validation for the qualified Claude callback."""

from datetime import datetime
import json
import re

from . import admission

PROFILE = "claude-code.user-prompt-submit.1"
VERSION = "2.1.330"
MODEL_PROFILE = "tidewall.prompt-injection.1"
REV = "c1899de289a04d12100db370d81485cdf75e47ca"
MODEL = dict(
    base="Qwen/Qwen3-0.6B",
    base_revision=REV,
    tokenizer_revision=REV,
    adapter="abedegno/prompt-injection-classifier-qwen3-0p6b",
    adapter_revision="5500c3bef53729ed4661b5cfae1b01adca96ca4c",
    prompt_sha256="3a0e693064509eb24773ba53af4831ecb4c6ca8cf741a28d2d10080384df5041",
    scoring_implementation="qwen3_last_token_logits.1",
    class_token_ids=[38157, 18675, 19860, 6092],
)
RESERVED = tuple(
    "<|" + word + "|>"
    for word in (
        "endoftext im_start im_end object_ref_start object_ref_end box_start box_end "
        "quad_start quad_end vision_start vision_end vision_pad image_pad video_pad"
    ).split()
)
REFUSALS = frozenset(
    (
        "invalid_request unauthorized grant_expired grant_revoked identity_conflict "
        "request_retired deadline_exceeded policy_changed policy_unsupported capacity storage_unavailable"
    ).split()
)
STAGES = frozenset(
    (
        "stdout_flushed allow_no_output stdout_failed native_ack_blocked "
        "effect_allow_marker_verified effect_deny_no_effect_verified unknown"
    ).split()
)
STATUS_REASONS = {
    "assessed": {"clean", "classifier_positive"},
    "not_requested": {
        "access_rule_block",
        "malicious_list",
        "benign_override",
        "capture_disabled",
    },
    "unsupported": {"input_too_large", "input_unsupported"},
    "failed": {"classifier_invalid", "prompt_list_failed"},
    "unavailable": {
        "classifier_unavailable",
        "deadline_exceeded",
        "policy_changed",
        "policy_unsupported",
        "authority_changed",
        "storage_unavailable",
        "request_retired",
    },
}
MAX_GENERATION = admission.MAX_INT
LIMITS = {
    "NativeDecisionReply": 8192,
    "NativePromptRequest": 16384,
    "NativeRefusal": 256,
}


def require(ok):
    if not ok:
        raise ValueError("invalid_native_contract")


integer = admission.integer


def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value, re.ASCII) is not None


def uuid4_text(value):
    return admission.match(admission.UUID4, value)


def fields(value, required, optional=""):
    keys = set(required.split())
    require(
        type(value) is dict and keys <= value.keys() <= keys | set(optional.split())
    )


def encode(obj):
    return json.dumps(
        obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def parse(kind, raw):
    obj = admission.wire_json(raw, LIMITS.get(kind, 2048), allow_float=True)
    try:
        validate(kind, obj)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("invalid_native_contract") from None
    return obj


def input_state(prompt):
    if not isinstance(prompt, str):
        return "unsupported"
    try:
        if len(prompt.encode("utf-8")) > 8000:
            return "input_too_large"
    except UnicodeError:
        return "unsupported"
    if not prompt.strip() or any(token in prompt for token in RESERVED):
        return "unsupported"
    return "complete"


def _decision(obj):
    fields(
        obj,
        "version request_id occurrence_id decision_id event_id session_id grant_id grant_generation "
        "policy_revision mode assessment evaluated_action returned_action reason",
    )
    require(
        integer(obj["grant_generation"], 1, MAX_GENERATION)
        and matches(obj["policy_revision"], "[0-9a-f]{64}")
    )
    assessment = obj["assessment"]
    status, reason = assessment["status"], obj["reason"]
    assessed = status == "assessed"
    fields(
        assessment,
        "status reason profile"
        + (" model_identity unsafe_score score_kind input_tokens" if assessed else ""),
    )
    require(
        assessment["profile"] == MODEL_PROFILE
        and assessment["reason"] in STATUS_REASONS[status]
    )
    if assessed:
        # Canonical comparison also enforces the integer types inside class_token_ids.
        require(
            admission.canonical(assessment["model_identity"])
            == admission.canonical(MODEL)
        )
        score = assessment["unsafe_score"]
        require(
            type(score) in (int, float)
            and 0 <= score <= 1
            and assessment["score_kind"] == "two_class_softmax_uncalibrated"
            and integer(assessment["input_tokens"], 1, 1024)
        )
    ev, ret, mode = obj["evaluated_action"], obj["returned_action"], obj["mode"]
    require(
        mode in ("report", "enforce")
        and ev in ("allow", "deny", "unknown")
        and ret in ("allow", "deny", None)
    )
    require(
        reason == assessment["reason"]
        or reason == "access_rule_block"
        and status == "unsupported"
    )
    if status in ("failed", "unsupported", "unavailable") and ret is not None:
        require((ev, ret) in (("deny", "deny"), ("unknown", "allow")))
    if ret == "deny":
        require(ev == "deny")
    if reason in ("classifier_positive", "malicious_list"):
        require(ev != "unknown" and ret in (None, "allow" if mode == "report" else ev))
    if reason == "access_rule_block":
        require(ev == "deny" and ret != "allow")
    if reason in ("clean", "capture_disabled", "benign_override"):
        require(ev == "allow")
    if reason in (
        "policy_changed",
        "policy_unsupported",
        "authority_changed",
        "storage_unavailable",
        "request_retired",
    ):
        require(ret is None)


def validate(kind, obj):
    require(isinstance(obj, dict))
    if "version" in obj:
        require(integer(obj["version"], 1, 1))
    for key in (
        "request_id",
        "occurrence_id",
        "decision_id",
        "event_id",
        "session_id",
        "grant_id",
        "report_id",
        "device_id",
    ):
        if key in obj:
            nullable = (kind, key) in {
                ("NativeRefusal", "request_id"),
                ("NativeGrantIssued", "session_id"),
            }
            require((nullable and obj[key] is None) or uuid4_text(obj[key]))
    if kind == "NativeDecisionReply":
        _decision(obj)
    elif kind == "NativeMetadata":
        fields(
            obj,
            "version occurrence_id agent native_profile agent_version session_token",
        )
        require(
            obj["agent"] == "claude-code"
            and obj["native_profile"] == PROFILE
            and obj["agent_version"] == VERSION
            and matches(obj["session_token"], "[0-9a-f]{64}")
        )
    elif kind == "NativePromptRequest":
        complete = obj.get("input_state") == "complete"
        fields(
            obj,
            "version request_id observation input_state budget_ms"
            + (" prompt" if complete else ""),
        )
        validate("NativeMetadata", obj["observation"])
        require(integer(obj["budget_ms"], 1, 1800))
        if complete:
            require(input_state(obj["prompt"]) == "complete")
        else:
            require(
                obj["input_state"]
                in ("capture_disabled", "input_too_large", "unsupported")
            )
    elif kind == "NativeGrantIssued":
        fields(
            obj,
            "capability grant_id grant_generation policy_generation policy_id device_id "
            "native_profile session_token session_id capture_allowed expires_at",
        )
        require(
            matches(obj["capability"], "[a-zA-Z0-9_-]{43}")
            and type(obj["capture_allowed"]) is bool
            and obj["capture_allowed"] == (obj["session_id"] is not None)
            and integer(obj["grant_generation"], 1, MAX_GENERATION)
            and integer(obj["policy_generation"], 1, MAX_GENERATION)
            and isinstance(obj["policy_id"], str)
            and obj["native_profile"] == PROFILE
            and matches(obj["session_token"], "[0-9a-f]{64}")
            and matches(
                obj["expires_at"],
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?\+00:00",
            )
        )
        datetime.fromisoformat(obj["expires_at"])
    elif kind == "NativeDeliveryReport":
        fields(
            obj,
            "report_id decision_id request_id occurrence_id evidence_source stage",
            "tool_count token_count marker_present",
        )
        require(
            obj["evidence_source"] in ("hook", "controlled_observer")
            and obj["stage"] in STAGES
        )
        for k in ("tool_count", "token_count"):
            if k in obj:
                require(integer(obj[k], 0, 2_147_483_647))
        if "marker_present" in obj:
            require(type(obj["marker_present"]) is bool)
    elif kind == "NativeRefusal":
        fields(obj, "version request_id code")
        require(obj["code"] in REFUSALS)
    elif kind == "NativeObservationAck":
        fields(obj, "version occurrence_id event_id session_id")
    elif kind == "NativeDeliveryAck":
        fields(obj, "version report_id decision_id")
    else:
        raise ValueError("invalid_native_contract")


def bind_decision(reply, request, auth):
    from .tidewall_backend import BackendError

    grant = auth.grant
    a = reply["assessment"]
    input_kind = request["input_state"]
    if (
        reply["request_id"] != request["request_id"]
        or reply["occurrence_id"] != request["observation"]["occurrence_id"]
        or reply["grant_id"] != grant["grant_id"]
        or reply["grant_generation"] != grant["grant_generation"]
        or auth.selected_session not in (None, reply["session_id"])
        or request["observation"]["session_token"] != auth.session_token
        or input_kind != "complete"
        and a["status"] == "assessed"
        or input_kind == "capture_disabled"
        and a["reason"] not in ("capture_disabled", "access_rule_block")
        or input_kind in ("unsupported", "input_too_large")
        and a["reason"]
        not in (
            "access_rule_block",
            "input_unsupported" if input_kind == "unsupported" else "input_too_large",
        )
    ):
        raise BackendError("invalid_reply")
