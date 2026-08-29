from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd

from config import MAX_STAGES, STAGE_INFO, STORY_MERGE_SECONDS


def select_incident_window(events: list[dict[str, Any]]) -> tuple[pd.Timestamp, pd.Timestamp]:
    if not events:
        raise ValueError("No normalized events were generated.")

    by_day: defaultdict[pd.Timestamp, dict[str, float]] = defaultdict(lambda: {"score": 0.0, "count": 0.0})
    for event in events:
        day = event["timestamp"].floor("D")
        stage = event.get("stage", "other")
        weight = STAGE_INFO.get(stage, STAGE_INFO["other"])["weight"]
        confidence = float(event.get("confidence", 0.35))
        by_day[day]["score"] += weight * max(0.35, confidence)
        by_day[day]["count"] += 1

    best_day = max(
        by_day.items(),
        key=lambda item: (item[1]["score"] + (item[1]["count"] ** 0.5), item[1]["count"]),
    )[0]
    return best_day, best_day + pd.Timedelta(days=1)


def infer_sequence_behaviour(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda event: (event["timestamp"], event["row_number"]))
    last_by_actor: dict[str, dict[str, Any]] = {}

    for event in ordered:
        actor = (event.get("actor") or "").strip().lower()
        target = (event.get("target_host") or event.get("computer") or event.get("target_ip") or "").strip().lower()
        source = (event.get("source_host") or event.get("source_ip") or "").strip().lower()

        if actor:
            previous = last_by_actor.get(actor)
            if previous:
                previous_target = (
                    previous.get("target_host")
                    or previous.get("computer")
                    or previous.get("target_ip")
                    or ""
                ).strip().lower()
                gap = (event["timestamp"] - previous["timestamp"]).total_seconds()

                remoteish = event.get("stage") in {"authentication_success", "lateral_movement", "credential_use"}
                changed_host = bool(target and previous_target and target != previous_target)

                if 0 <= gap <= 600 and changed_host and remoteish:
                    if event.get("stage") != "exfiltration":
                        event["stage"] = "lateral_movement"
                        event["confidence"] = max(float(event.get("confidence", 0.0)), 0.80)
                        event.setdefault("classification_reasons", []).append(
                            "Same actor reached a different host within 10 minutes"
                        )

            last_by_actor[actor] = event

        # Source -> target pivot is also a lateral signal, but compare like with like:
        # host-to-host or IP-to-IP. Do not compare an IP string to a hostname.
        source_host = (event.get("source_host") or "").strip().lower()
        target_host = (event.get("target_host") or event.get("computer") or "").strip().lower()
        source_ip = (event.get("source_ip") or "").strip().lower()
        target_ip = (event.get("target_ip") or "").strip().lower()

        distinct_hosts = bool(source_host and target_host and source_host != target_host)
        distinct_ips = bool(source_ip and target_ip and source_ip != target_ip)

        if (distinct_hosts or distinct_ips) and event.get("stage") == "authentication_success":
            event["stage"] = "lateral_movement"
            event["confidence"] = max(float(event.get("confidence", 0.0)), 0.76)
            event.setdefault("classification_reasons", []).append(
                "Authentication connects distinct source and target systems"
            )

    return ordered


def _cluster_key(event: dict[str, Any]) -> tuple[str, str]:
    stage = event.get("stage", "other")
    target = (
        event.get("target_host")
        or event.get("computer")
        or event.get("target_ip")
        or "unknown"
    )
    return stage, str(target).lower()


def cluster_events(events: list[dict[str, Any]], gap_seconds: int = STORY_MERGE_SECONDS) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda event: (event["timestamp"], event["row_number"]))
    clusters: list[dict[str, Any]] = []

    for event in ordered:
        if event.get("stage") == "other":
            continue

        if not clusters:
            clusters.append({"stage": event["stage"], "events": [event]})
            continue

        current = clusters[-1]
        last = current["events"][-1]
        gap = (event["timestamp"] - last["timestamp"]).total_seconds()

        if _cluster_key(event) == _cluster_key(last) and 0 <= gap <= gap_seconds:
            current["events"].append(event)
        else:
            clusters.append({"stage": event["stage"], "events": [event]})

    return clusters


def score_cluster(cluster: dict[str, Any]) -> float:
    events = cluster["events"]
    stage = cluster["stage"]
    info = STAGE_INFO.get(stage, STAGE_INFO["other"])
    confidence = sum(float(event.get("confidence", 0.35)) for event in events) / len(events)
    diversity = len({
        event.get("action") or event.get("message") or event.get("event_id")
        for event in events
    })
    return info["weight"] * confidence + min(len(events), 8) * 0.35 + min(diversity, 4) * 0.25


def select_story_clusters(clusters: list[dict[str, Any]], maximum: int = MAX_STAGES) -> list[dict[str, Any]]:
    if len(clusters) <= maximum:
        return sorted(clusters, key=lambda cluster: cluster["events"][0]["timestamp"])

    # Story selection balances confidence/importance with stage diversity and chronology.
    for cluster in clusters:
        cluster["story_score"] = score_cluster(cluster)

    selected: list[dict[str, Any]] = []
    per_stage: defaultdict[str, int] = defaultdict(int)

    # First pass: strongest instance of each meaningful stage.
    for cluster in sorted(clusters, key=lambda c: c["story_score"], reverse=True):
        if per_stage[cluster["stage"]] == 0:
            selected.append(cluster)
            per_stage[cluster["stage"]] += 1
        if len(selected) >= maximum:
            break

    # Second pass: allow repeats, but cap repetition so one stage cannot dominate.
    if len(selected) < maximum:
        for cluster in sorted(clusters, key=lambda c: c["story_score"], reverse=True):
            if cluster in selected:
                continue
            if per_stage[cluster["stage"]] >= 3:
                continue
            selected.append(cluster)
            per_stage[cluster["stage"]] += 1
            if len(selected) >= maximum:
                break

    return sorted(selected, key=lambda cluster: cluster["events"][0]["timestamp"])


def build_story(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    start, end = select_incident_window(events)
    incident_events = [
        event for event in events
        if start <= event["timestamp"] < end
    ]
    incident_events = infer_sequence_behaviour(incident_events)
    clusters = cluster_events(incident_events)
    return select_story_clusters(clusters)
