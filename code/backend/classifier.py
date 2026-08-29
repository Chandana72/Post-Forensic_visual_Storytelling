from __future__ import annotations

import ipaddress
import re
from typing import Any

from config import (
    EXTERNAL_HINTS,
    REMOTE_PROTOCOL_HINTS,
    SENSITIVE_FILE_HINTS,
    STAGE_PATTERNS,
    WINDOWS_EVENT_HINTS,
)


def _contains(patterns: list[str], text: str) -> list[str]:
    matches: list[str] = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(pattern)
    return matches


def _is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return not ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _heuristic_scores(event: dict[str, Any]) -> dict[str, dict[str, Any]]:
    text = event.get("search_text") or ""
    scores: dict[str, dict[str, Any]] = {}

    for stage, patterns in STAGE_PATTERNS.items():
        matched = _contains(patterns, text)
        if matched:
            scores[stage] = {
                "score": min(0.84, 0.58 + 0.08 * len(matched)),
                "reasons": [f"Matched semantic pattern for {stage.replace('_', ' ')}"],
            }

    # Structured outcome + action support.
    result = (event.get("result") or "").lower()
    action = (event.get("action") or "").lower()

    auth_words = ("login", "logon", "auth", "sign in", "signin", "session")
    if any(word in action for word in auth_words):
        if any(word in result for word in ("success", "allow", "accepted", "granted", "ok")):
            entry = scores.setdefault("authentication_success", {"score": 0.0, "reasons": []})
            entry["score"] = max(entry["score"], 0.78)
            entry["reasons"].append("Authentication-like action has a successful outcome")
        if any(word in result for word in ("fail", "deny", "decline", "reject", "blocked")):
            entry = scores.setdefault("access_declined", {"score": 0.0, "reasons": []})
            entry["score"] = max(entry["score"], 0.80)
            entry["reasons"].append("Authentication-like action has a failed/denied outcome")

    # Behavioural exfiltration signals.
    bytes_out = event.get("bytes_out")
    external_destination = (
        _is_external_ip(event.get("target_ip"))
        or any(hint in text for hint in EXTERNAL_HINTS)
    )
    transfer_action = bool(re.search(r"\b(upload(?:ed|ing)?|cop(?:y|ied|ying)|transfer(?:red|ring)?|send|sent|export(?:ed|ing)?|sync(?:ed|ing)?)\b", text))
    sensitive_object = any(hint in text for hint in SENSITIVE_FILE_HINTS)
    removable = bool(re.search(r"\b(usb|removable|external drive|flash drive)\b", text))

    exfil_score = 0.0
    exfil_reasons: list[str] = []
    if external_destination:
        exfil_score += 0.25
        exfil_reasons.append("Destination appears external")
    if transfer_action:
        exfil_score += 0.25
        exfil_reasons.append("Event describes a file/data transfer")
    if bytes_out is not None and bytes_out >= 10_000_000:
        exfil_score += 0.25
        exfil_reasons.append("Large outbound byte count")
    if sensitive_object:
        exfil_score += 0.15
        exfil_reasons.append("Object name appears sensitive")
    if removable and transfer_action:
        exfil_score += 0.25
        exfil_reasons.append("Transfer targets removable media")

    if exfil_score >= 0.50:
        entry = scores.setdefault("exfiltration", {"score": 0.0, "reasons": []})
        entry["score"] = max(entry["score"], min(0.92, 0.45 + exfil_score))
        entry["reasons"].extend(exfil_reasons)

    # Remote protocol hint.
    if any(hint in text for hint in REMOTE_PROTOCOL_HINTS):
        entry = scores.setdefault("lateral_movement", {"score": 0.0, "reasons": []})
        entry["score"] = max(entry["score"], 0.66)
        entry["reasons"].append("Remote-access/network-share protocol observed")

    # OPTIONAL Windows Event ID hint. This only raises confidence if semantic
    # evidence independently points to the same stage, or provides a fallback.
    event_id = event.get("event_id")
    if event_id in WINDOWS_EVENT_HINTS:
        hint_stage, bonus, reason = WINDOWS_EVENT_HINTS[event_id]
        entry = scores.setdefault(hint_stage, {"score": 0.0, "reasons": []})
        if entry["score"] > 0:
            entry["score"] = min(0.98, entry["score"] + bonus)
        else:
            entry["score"] = min(0.76, 0.48 + bonus)
        entry["reasons"].append(reason + " (optional corroborating signal)")

    return scores


def classify_event(event: dict[str, Any]) -> dict[str, Any]:
    scores = _heuristic_scores(event)

    if not scores:
        return {
            **event,
            "stage": "other",
            "confidence": 0.35,
            "classification_reasons": ["No strong generic semantic/behavioural pattern matched"],
        }

    stage, detail = max(
        scores.items(),
        key=lambda item: (item[1]["score"], len(item[1]["reasons"])),
    )

    return {
        **event,
        "stage": stage,
        "confidence": round(float(detail["score"]), 3),
        "classification_reasons": detail["reasons"][:5],
    }


def classify_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [classify_event(event) for event in events]
