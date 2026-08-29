from __future__ import annotations

from typing import Any

from config import STAGE_INFO
from local_summarizer import summarise_stage


def _unique(events: list[dict[str, Any]], key: str, maximum: int = 3) -> list[str]:
    result: list[str] = []
    for event in events:
        value = event.get(key)
        if value is not None:
            text = str(value).strip()
            if text and text not in result:
                result.append(text)
        if len(result) >= maximum:
            break
    return result


def _evidence_detail(event: dict[str, Any]) -> str:
    parts = [event["timestamp"].isoformat()]
    if event.get("event_id"):
        parts.append(f"event {event['event_id']}")
    if event.get("action"):
        parts.append(str(event["action"]))
    elif event.get("message"):
        parts.append(str(event["message"])[:180])
    if event.get("target_host"):
        parts.append(f"target {event['target_host']}")
    elif event.get("computer"):
        parts.append(f"host {event['computer']}")
    return " — ".join(parts)


def build_evidence(events: list[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    evidence = []
    for event in events[:12]:
        evidence.append({
            "type": "CSV evidence",
            "source": event.get("source") or event.get("computer") or "CSV record",
            "detail": _evidence_detail(event),
            "row_number": event["row_number"],
            "url": (
                f"http://127.0.0.1:8000/api/v1/cases/{case_id}/records"
                f"?offset={event['row_number'] - 1}&limit=1"
            ),
        })
    return evidence


def _observed_text(events: list[dict[str, Any]]) -> str:
    snippets: list[str] = []
    for event in events:
        for key in ("action", "message", "object"):
            value = event.get(key)
            if value:
                text = str(value).strip()
                if text and text not in snippets:
                    snippets.append(text)
                    break
        if len(snippets) >= 4:
            break
    return "; ".join(snippets)


def timeline_from_clusters(
    clusters: list[dict[str, Any]],
    case_id: str,
) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []

    for sequence, cluster in enumerate(clusters, start=1):
        events = cluster["events"]
        stage = cluster["stage"]
        info = STAGE_INFO.get(stage, STAGE_INFO["other"])

        users = _unique(events, "actor")
        targets = (
            _unique(events, "target_host")
            or _unique(events, "computer")
            or _unique(events, "target_ip")
        )
        sources = _unique(events, "source")
        observed = _observed_text(events)

        source_text = (
            f"{len(events)} related forensic records indicate {info['title'].lower()}. "
            f"Observed evidence: {observed or 'structured activity records'}."
        )
        fallback = f"{info['title']}: {observed or f'{len(events)} supporting records'}."
        short_summary, summary_provider = summarise_stage(source_text, fallback)

        reasons: list[str] = []
        for event in events:
            for reason in event.get("classification_reasons", []):
                if reason not in reasons:
                    reasons.append(reason)
                if len(reasons) >= 5:
                    break

        average_confidence = sum(
            float(event.get("confidence", 0.35)) for event in events
        ) / max(1, len(events))

        timeline.append({
            "sequence": sequence,
            "timestamp": events[0]["timestamp"].isoformat(),
            "stage": stage,
            "type": info["type"],
            "title": info["title"],
            "summary": short_summary,
            "summary_provider": summary_provider,
            "description": (
                f"This stage links {len(events)} supporting records between "
                f"{events[0]['timestamp'].isoformat()} and {events[-1]['timestamp'].isoformat()}. "
                f"Observed evidence: {observed or 'structured activity records'}. "
                f"Classification basis: {'; '.join(reasons) or 'generic temporal and semantic grouping'}. "
                "The interpretation remains subject to investigator review."
            ),
            "row_number": events[0]["row_number"],
            "evidence_rows": [event["row_number"] for event in events[:12]],
            "evidence": build_evidence(events, case_id),
            "user": ", ".join(users) or "Unknown account",
            "source_ip": events[0].get("source_ip"),
            "target": ", ".join(targets) or "Unknown target",
            "source": ", ".join(sources) or "CSV evidence",
            "mitre": info["mitre"],
            "confidence": round(average_confidence, 3),
            "score": round(info["weight"] * average_confidence + len(events) * 0.25, 3),
            "classification_reasons": reasons,
        })

    return timeline
