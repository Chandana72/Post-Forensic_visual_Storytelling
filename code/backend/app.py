import json
import math
import urllib.error
import urllib.request
import re
import sqlite3
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from local_summarizer import summarise_stage

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATABASE_PATH = BASE_DIR / "generic_cases.db"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_BYTES = 250 * 1024 * 1024
MAX_STAGES = 15

app = FastAPI(title="Forensic Incident Replay API", version="4.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
WINDOWS_EVENT_INFO = {
    "1102": {"stage": "defence_evasion", "title": "Audit log clearing", "label": "The Windows audit log was cleared.", "weight": 10, "type": "malicious", "mitre": [{"id": "T1070.001", "name": "Clear Windows Event Logs"}]},
    "4624": {"stage": "authentication", "title": "Successful authentication", "label": "Successful account logons were recorded.", "weight": 2, "type": "user", "mitre": [{"id": "T1078", "name": "Valid Accounts"}]},
    "4625": {"stage": "failed_authentication", "title": "Failed authentication activity", "label": "Failed account logons were recorded.", "weight": 5, "type": "malicious", "mitre": []},
    "4634": {"stage": "session_end", "title": "Session termination", "label": "Account logoff activity was recorded.", "weight": 1, "type": "user", "mitre": []},
    "4648": {"stage": "credential_use", "title": "Explicit credential use", "label": "Credentials were explicitly supplied for authentication.", "weight": 5, "type": "user", "mitre": [{"id": "T1078", "name": "Valid Accounts"}]},
    "4672": {"stage": "privileged_session", "title": "Privileged session established", "label": "Special privileges were assigned to authenticated sessions.", "weight": 6, "type": "system", "mitre": []},
    "4688": {"stage": "process_execution", "title": "Process execution activity", "label": "Windows process creation events were recorded.", "weight": 4, "type": "system", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}]},
    "4697": {"stage": "service_installation", "title": "Service installation activity", "label": "A Windows service was installed.", "weight": 8, "type": "system", "mitre": [{"id": "T1543.003", "name": "Windows Service"}]},
    "4720": {"stage": "account_management", "title": "Account management activity", "label": "A user account was created.", "weight": 8, "type": "system", "mitre": [{"id": "T1136.001", "name": "Create Account: Local Account"}]},
    "4722": {"stage": "account_management", "title": "Account management activity", "label": "A user account was enabled.", "weight": 7, "type": "system", "mitre": []},
    "4724": {"stage": "account_management", "title": "Account management activity", "label": "A password-reset attempt was recorded.", "weight": 7, "type": "system", "mitre": []},
    "4728": {"stage": "group_membership", "title": "Security group modification", "label": "A user was added to a global security group.", "weight": 8, "type": "system", "mitre": [{"id": "T1098", "name": "Account Manipulation"}]},
    "4732": {"stage": "group_membership", "title": "Security group modification", "label": "A user was added to a local security group.", "weight": 8, "type": "system", "mitre": [{"id": "T1098", "name": "Account Manipulation"}]},
    "4771": {"stage": "failed_authentication", "title": "Failed authentication activity", "label": "Kerberos pre-authentication failures were recorded.", "weight": 5, "type": "malicious", "mitre": []},
    "4776": {"stage": "authentication", "title": "Credential validation activity", "label": "Account credentials were validated.", "weight": 3, "type": "user", "mitre": []},
    "5140": {"stage": "network_share_access", "title": "Network share access", "label": "A Windows network share was accessed.", "weight": 7, "type": "system", "mitre": [{"id": "T1021.002", "name": "SMB/Windows Admin Shares"}]},
    "7045": {"stage": "service_installation", "title": "Service installation activity", "label": "Windows recorded an installed system service.", "weight": 8, "type": "system", "mitre": [{"id": "T1543.003", "name": "Windows Service"}]},
}

STAGE_WINDOWS = {
    "account_management": 20,
    "group_membership": 20,
    "authentication": 30,
    "failed_authentication": 120,
    "credential_use": 30,
    "privileged_session": 30,
    "process_execution": 30,
    "network_share_access": 60,
    "service_installation": 120,
    "defence_evasion": 120,
    "session_end": 30,
}

COLUMN_ALIASES = {
    "timestamp": ["datetime", "timestamp", "event_time", "occurred_at", "created_at", "time_created", "date_time", "date", "time"],
    "event_id": ["event_id", "eventid", "event_code", "eventcode", "id_event"],
    "computer": ["computer_name", "hostname", "host", "computer", "device_name", "device", "machine"],
    "user": ["user_sid", "username", "user_name", "user", "account_name", "account", "subject_user_name"],
    "source": ["source_name", "provider_name", "provider", "source", "channel", "log_name"],
    "source_ip": ["source_ip", "src_ip", "client_ip", "remote_ip", "ip_address"],
    "action": ["action", "activity", "event_type", "type", "category", "operation", "task", "status"],
}


def database_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialise_database() -> None:
    connection = database_connection()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                created_at TEXT NOT NULL,
                row_count INTEGER NOT NULL,
                column_count INTEGER NOT NULL,
                timestamp_column TEXT,
                category_column TEXT,
                summary_provider TEXT NOT NULL,
                analysis_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
            """
        )
        connection.commit()
    finally:
        connection.close()


@app.on_event("startup")
def startup() -> None:
    initialise_database()


def clean_column_name(value: Any) -> str:
    text = str(value).strip()
    return re.sub(r"\s+", "_", text) if text else "unnamed_column"


def make_unique_columns(columns: list[Any]) -> list[str]:
    counts: Counter[str] = Counter()
    result = []
    for column in columns:
        base = clean_column_name(column)
        counts[base] += 1
        result.append(base if counts[base] == 1 else f"{base}_{counts[base]}")
    return result


def safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, (pd.Timestamp, datetime)):
        return None if pd.isna(value) else value.isoformat()
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def json_record(record: dict[str, Any]) -> dict[str, Any]:
    return {str(key): safe_value(value) for key, value in record.items()}


def read_csv_file(path: Path) -> pd.DataFrame:
    last_error = None
    for encoding in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
        try:
            dataframe = pd.read_csv(path, sep=None, engine="python", encoding=encoding)
            dataframe.columns = make_unique_columns(list(dataframe.columns))
            return dataframe
        except Exception as error:
            last_error = error
    raise ValueError(f"The file could not be read as a CSV. Last parser error: {last_error}")


def find_column(dataframe: pd.DataFrame, alias_group: str) -> Optional[str]:
    aliases = COLUMN_ALIASES[alias_group]
    lowered = {column.lower(): column for column in dataframe.columns}
    for alias in aliases:
        if alias in lowered:
            return lowered[alias]
    for column in dataframe.columns:
        lowered_column = column.lower()
        for alias in aliases:
            if alias in lowered_column:
                return column
    return None


def detect_timestamp(dataframe: pd.DataFrame) -> tuple[Optional[str], Optional[pd.Series]]:
    preferred = find_column(dataframe, "timestamp")
    candidates = ([preferred] if preferred else []) + [column for column in dataframe.columns if column != preferred]
    best_column = None
    best_series = None
    best_score = 0.0
    sample_size = min(2000, len(dataframe))
    for column in candidates:
        values = dataframe[column].head(sample_size)
        if pd.api.types.is_numeric_dtype(values):
            continue
        non_empty = values.dropna()
        if non_empty.empty:
            continue
        parsed = pd.to_datetime(non_empty, errors="coerce", utc=True)
        ratio = float(parsed.notna().mean())
        score = ratio + (0.3 if column == preferred else 0)
        if ratio >= 0.60 and score > best_score:
            best_column = column
            best_series = pd.to_datetime(dataframe[column], errors="coerce", utc=True)
            best_score = score
    return best_column, best_series


def normalise_text(value: Any) -> Optional[str]:
    value = safe_value(value)
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in {"", "none", "null", "nan", "n/a"} else text


def event_id_value(value: Any) -> Optional[str]:
    text = normalise_text(value)
    if text is None:
        return None
    match = re.search(r"\d+", text)
    return match.group(0) if match else text


def select_incident_window(dataframe: pd.DataFrame, timestamp_series: pd.Series, event_id_column: Optional[str]) -> tuple[pd.Timestamp, pd.Timestamp]:
    working = pd.DataFrame({"timestamp": timestamp_series})
    if event_id_column:
        working["event_id"] = dataframe[event_id_column].map(event_id_value)
        working["weight"] = working["event_id"].map(lambda value: WINDOWS_EVENT_INFO.get(value, {}).get("weight", 0))
    else:
        working["weight"] = 1
    working = working.dropna(subset=["timestamp"])
    if working.empty:
        raise ValueError("No valid timestamps were detected.")
    working["day"] = working["timestamp"].dt.floor("D")
    daily = working.groupby("day").agg(weighted_score=("weight", "sum"), record_count=("timestamp", "count"))
    daily["score"] = daily["weighted_score"] + np.log1p(daily["record_count"])
    best_day = daily["score"].idxmax()
    return best_day, best_day + pd.Timedelta(days=1)


def cluster_rows(rows: list[dict[str, Any]], window_seconds: int) -> list[list[dict[str, Any]]]:
    if not rows:
        return []
    ordered = sorted(rows, key=lambda row: (row["timestamp"], row["row_number"]))
    clusters = []
    current = [ordered[0]]
    for row in ordered[1:]:
        previous = current[-1]
        same_target = (row.get("computer") or "unknown").lower() == (previous.get("computer") or "unknown").lower()
        gap = (row["timestamp"] - previous["timestamp"]).total_seconds()
        if same_target and 0 <= gap <= window_seconds:
            current.append(row)
        else:
            clusters.append(current)
            current = [row]
    clusters.append(current)
    return clusters


def merge_candidate_clusters(candidates: list[dict[str, Any]], maximum_gap_seconds: int = 900) -> list[dict[str, Any]]:
    if not candidates:
        return []
    ordered = sorted(candidates, key=lambda candidate: candidate["rows"][0]["timestamp"])
    merged: list[dict[str, Any]] = []
    for candidate in ordered:
        candidate_rows = sorted(candidate["rows"], key=lambda row: (row["timestamp"], row["row_number"]))
        if not merged:
            merged.append({**candidate, "rows": list(candidate_rows)})
            continue
        previous = merged[-1]
        gap = (candidate_rows[0]["timestamp"] - previous["rows"][-1]["timestamp"]).total_seconds()
        previous_computers = {row.get("computer") for row in previous["rows"] if row.get("computer")}
        candidate_computers = {row.get("computer") for row in candidate_rows if row.get("computer")}
        same_computer = not previous_computers or not candidate_computers or bool(previous_computers & candidate_computers)
        if previous["stage"] == candidate["stage"] and same_computer and 0 <= gap <= maximum_gap_seconds:
            previous["rows"].extend(candidate_rows)
            previous["rows"].sort(key=lambda row: (row["timestamp"], row["row_number"]))
            previous["score"] = max(previous["score"], candidate["score"])
        else:
            merged.append({**candidate, "rows": list(candidate_rows)})
    return merged


def unique_values(rows: list[dict[str, Any]], key: str, maximum: int = 3) -> list[str]:
    values = []
    for row in rows:
        value = normalise_text(row.get(key))
        if value and value not in values:
            values.append(value)
        if len(values) >= maximum:
            break
    return values


def build_evidence(rows: list[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    evidence = []
    for row in rows[:12]:
        event_id = row.get("event_id") or "unknown"
        source = row.get("source") or row.get("computer") or "CSV record"
        details = [f"Event ID {event_id}", row["timestamp"].isoformat()]
        if row.get("computer"):
            details.append(f"computer {row['computer']}")
        evidence.append({
            "type": "CSV evidence",
            "source": source,
            "detail": " — ".join(details),
            "row_number": row["row_number"],
            "url": f"http://127.0.0.1:8000/api/v1/cases/{case_id}/records?offset={row['row_number'] - 1}&limit=1",
        })
    return evidence


def build_windows_timeline(dataframe: pd.DataFrame, timestamps: pd.Series, case_id: str) -> list[dict[str, Any]]:
    event_id_column = find_column(dataframe, "event_id")
    if not event_id_column:
        return []
    computer_column = find_column(dataframe, "computer")
    user_column = find_column(dataframe, "user")
    source_column = find_column(dataframe, "source")
    source_ip_column = find_column(dataframe, "source_ip")
    start, end = select_incident_window(dataframe, timestamps, event_id_column)
    rows_by_stage: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)

    for index, row in dataframe.iterrows():
        timestamp = timestamps.iloc[index]
        if pd.isna(timestamp) or not (start <= timestamp < end):
            continue
        event_id = event_id_value(row.get(event_id_column))
        info = WINDOWS_EVENT_INFO.get(event_id)
        if not info:
            continue
        rows_by_stage[info["stage"]].append({
            "row_number": int(index) + 1,
            "timestamp": timestamp,
            "event_id": event_id,
            "computer": normalise_text(row.get(computer_column)) if computer_column else None,
            "user": normalise_text(row.get(user_column)) if user_column else None,
            "source": normalise_text(row.get(source_column)) if source_column else None,
            "source_ip": normalise_text(row.get(source_ip_column)) if source_ip_column else None,
        })

    candidates = []
    for stage, rows in rows_by_stage.items():
        for cluster in cluster_rows(rows, STAGE_WINDOWS.get(stage, 60)):
            event_counts = Counter(row["event_id"] for row in cluster)
            score = sum(WINDOWS_EVENT_INFO[event_id]["weight"] * count for event_id, count in event_counts.items())
            candidates.append({"stage": stage, "rows": cluster, "score": score})

    if not candidates:
        return []

    candidates = merge_candidate_clusters(candidates, maximum_gap_seconds=900)
    candidates.sort(
        key=lambda candidate: (
            candidate["score"],
            len(candidate["rows"]),
            len({row["event_id"] for row in candidate["rows"]}),
        ),
        reverse=True,
    )
    candidates = candidates[:MAX_STAGES]
    candidates.sort(key=lambda candidate: candidate["rows"][0]["timestamp"])

    timeline = []
    for sequence, candidate in enumerate(candidates, start=1):
        rows = candidate["rows"]
        first_row = rows[0]
        event_counts = Counter(row["event_id"] for row in rows)
        dominant_event_id = event_counts.most_common(1)[0][0]
        info = WINDOWS_EVENT_INFO[dominant_event_id]
        labels = []
        mitre = []
        for event_id in event_counts:
            event_info = WINDOWS_EVENT_INFO[event_id]
            if event_info["label"] not in labels:
                labels.append(event_info["label"])
            for technique in event_info["mitre"]:
                if technique not in mitre:
                    mitre.append(technique)
        computers = unique_values(rows, "computer")
        users = unique_values(rows, "user")
        sources = unique_values(rows, "source")
        computer_text = ", ".join(computers) or "an unidentified computer"
        activity_text = " ".join(labels[:4])
        source_summary_text = f"On {computer_text}, {len(rows)} Windows event records showed the following observed activity: {activity_text}"
        fallback_summary = f"{len(rows)} related records on {computer_text}: {labels[0]}"
        short_summary, summary_provider = summarise_stage(source_summary_text, fallback_summary)
        description = (
            f"This stage groups {len(rows)} CSV records between {rows[0]['timestamp'].isoformat()} "
            f"and {rows[-1]['timestamp'].isoformat()}. Observed activity: {activity_text} "
            "The grouping is evidence-based but still requires investigator review."
        )
        timeline.append({
            "sequence": sequence,
            "timestamp": first_row["timestamp"].isoformat(),
            "stage": candidate["stage"],
            "type": info["type"],
            "title": info["title"],
            "summary": short_summary,
            "summary_provider": summary_provider,
            "description": description,
            "row_number": first_row["row_number"],
            "evidence_rows": [row["row_number"] for row in rows[:12]],
            "evidence": build_evidence(rows, case_id),
            "user": ", ".join(users) or "Unknown account",
            "source_ip": first_row.get("source_ip"),
            "target": computer_text,
            "source": ", ".join(sources) or "Windows Event Log",
            "mitre": mitre,
            "confidence": 0.90,
            "score": candidate["score"],
        })
    return timeline


def build_generic_timeline(dataframe: pd.DataFrame, timestamps: pd.Series, case_id: str) -> list[dict[str, Any]]:
    action_column = find_column(dataframe, "action")
    computer_column = find_column(dataframe, "computer")
    user_column = find_column(dataframe, "user")
    source_column = find_column(dataframe, "source")
    source_ip_column = find_column(dataframe, "source_ip")
    start, end = select_incident_window(dataframe, timestamps, None)
    rows = []
    for index, row in dataframe.iterrows():
        timestamp = timestamps.iloc[index]
        if pd.isna(timestamp) or not (start <= timestamp < end):
            continue
        action = normalise_text(row.get(action_column)) if action_column else None
        computer = normalise_text(row.get(computer_column)) if computer_column else None
        source = normalise_text(row.get(source_column)) if source_column else None
        rows.append({
            "row_number": int(index) + 1,
            "timestamp": timestamp,
            "event_id": None,
            "action": action or source or "Observed activity",
            "computer": computer,
            "user": normalise_text(row.get(user_column)) if user_column else None,
            "source": source,
            "source_ip": normalise_text(row.get(source_ip_column)) if source_ip_column else None,
        })
    grouped: defaultdict[tuple[str, Optional[str]], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["action"], row.get("computer"))].append(row)
    candidates = []
    for (action, computer), matching_rows in grouped.items():
        for cluster in cluster_rows(matching_rows, 120):
            candidates.append({"action": action, "computer": computer, "rows": cluster, "score": len(cluster)})
    candidates.sort(key=lambda candidate: candidate["score"], reverse=True)
    candidates = candidates[:MAX_STAGES]
    candidates.sort(key=lambda candidate: candidate["rows"][0]["timestamp"])
    timeline = []
    for sequence, candidate in enumerate(candidates, start=1):
        matching_rows = candidate["rows"]
        first_row = matching_rows[0]
        action = candidate["action"]
        computer = candidate["computer"] or "an unidentified system"
        stage = re.sub(r"[^a-z0-9]+", "_", action.lower()).strip("_")[:60] or f"stage_{sequence}"
        suspicious = bool(re.search(r"fail|error|denied|delete|remove|attack|malicious|blocked|unauthor", action, re.IGNORECASE))
        source_text = f"{len(matching_rows)} related CSV records described {action} on {computer}."
        fallback = f"{len(matching_rows)} records: {action} on {computer}."
        short_summary, summary_provider = summarise_stage(source_text, fallback)
        timeline.append({
            "sequence": sequence,
            "timestamp": first_row["timestamp"].isoformat(),
            "stage": stage,
            "type": "malicious" if suspicious else "system",
            "title": action[:80],
            "summary": short_summary,
            "summary_provider": summary_provider,
            "description": (
                f"This stage groups CSV records describing {action} between "
                f"{matching_rows[0]['timestamp'].isoformat()} and {matching_rows[-1]['timestamp'].isoformat()}. "
                "Investigator review is required."
            ),
            "row_number": first_row["row_number"],
            "evidence_rows": [row["row_number"] for row in matching_rows[:12]],
            "evidence": build_evidence(matching_rows, case_id),
            "user": first_row.get("user") or "Unknown account",
            "source_ip": first_row.get("source_ip"),
            "target": computer,
            "source": first_row.get("source") or "CSV evidence",
            "mitre": [],
            "confidence": 0.70,
            "score": candidate["score"],
        })
    return timeline


def severity_for_timeline(timeline: list[dict[str, Any]]) -> str:
    unique_stages = {event.get("stage") for event in timeline if event.get("stage")}
    high_signal = {"defence_evasion", "service_installation", "network_share_access", "group_membership", "account_management", "failed_authentication"}
    observed = unique_stages & high_signal
    if "defence_evasion" in unique_stages and len(observed) >= 2:
        return "Critical"
    if len(observed) >= 3:
        return "High"
    if observed:
        return "Medium"
    if unique_stages:
        return "Low"
    return "Unknown"


def profile_columns(dataframe: pd.DataFrame, timestamp_column: Optional[str]) -> list[dict[str, Any]]:
    result = []
    for column in dataframe.columns:
        series = dataframe[column]
        non_empty = series.dropna()
        result.append({
            "name": column,
            "type": "datetime" if column == timestamp_column else ("numeric" if pd.api.types.is_numeric_dtype(series) else "text"),
            "missing_count": int(series.isna().sum()),
            "missing_percentage": round(float(series.isna().mean() * 100), 2),
            "unique_count": int(non_empty.astype(str).nunique()),
            "sample_values": [safe_value(value) for value in non_empty.head(5).tolist()],
        })
    return result


def format_duration(total_seconds: int) -> str:
    hours, remainder = divmod(max(0, int(total_seconds)), 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def analyse_dataframe(case_name: str, case_id: str, dataframe: pd.DataFrame) -> dict[str, Any]:
    timestamp_column, timestamps = detect_timestamp(dataframe)
    if timestamp_column is None or timestamps is None:
        raise ValueError("A usable timestamp column could not be detected.")
    timeline = build_windows_timeline(dataframe, timestamps, case_id)
    analysis_mode = "windows-event-rules"
    if not timeline:
        timeline = build_generic_timeline(dataframe, timestamps, case_id)
        analysis_mode = "generic-time-clustering"
    if not timeline:
        raise ValueError("No meaningful time-based event clusters could be generated.")
    timeline = timeline[:MAX_STAGES]
    first_timestamp = pd.Timestamp(timeline[0]["timestamp"])
    last_timestamp = pd.Timestamp(timeline[-1]["timestamp"])
    duration_seconds = max(0, int((last_timestamp - first_timestamp).total_seconds()))
    severity = severity_for_timeline(timeline)
    one_line = (
        f"{len(timeline)} evidence-backed stages were reconstructed from {len(dataframe):,} CSV records "
        f"within a {format_duration(duration_seconds)} activity window."
    )
    detailed = (
        f"The system analysed {len(dataframe):,} records and selected a coherent activity window rather than the complete dataset date range. "
        f"Related records were grouped into no more than {MAX_STAGES} replay stages. Each stage remains linked to supporting CSV rows and requires investigator review."
    )
    return {
        "row_count": len(dataframe),
        "column_count": len(dataframe.columns),
        "columns": list(dataframe.columns),
        "timestamp_column": timestamp_column,
        "category_column": find_column(dataframe, "event_id") or find_column(dataframe, "action"),
        "analysis_mode": analysis_mode,
        "severity": severity,
        "duration_seconds": duration_seconds,
        "summary": {
            "one_line_summary": one_line,
            "detailed_summary": detailed,
            "key_findings": [
                f"{len(timeline)} reconstructed stages were selected.",
                f"The reconstructed window is {format_duration(duration_seconds)}.",
                f"Analysis mode: {analysis_mode}.",
                "Every stage remains linked to original CSV evidence.",
            ],
            "provider": "rules-plus-local-huggingface",
        },
        "timeline": timeline,
        "column_profiles": profile_columns(dataframe, timestamp_column),
        "preview": [json_record(record) for record in dataframe.head(100).to_dict(orient="records")],
    }


def get_case_row(case_id: str) -> sqlite3.Row:
    connection = database_connection()
    try:
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    finally:
        connection.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return row


@app.get("/")
def root() -> dict[str, Any]:
    return {"message": "Forensic Incident Replay API", "docs": "/docs"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/cases/import")
async def import_case(file: UploadFile = File(...), case_name: Optional[str] = Form(default=None)) -> dict[str, Any]:
    original_name = file.filename or "uploaded.csv"
    if not original_name.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded CSV is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="The CSV is larger than 250 MB.")
    case_id = str(uuid.uuid4())
    stored_filename = f"{case_id}.csv"
    stored_path = UPLOAD_DIR / stored_filename
    stored_path.write_bytes(content)
    resolved_name = case_name.strip() if case_name and case_name.strip() else Path(original_name).stem.replace("_", " ")
    try:
        dataframe = read_csv_file(stored_path)
        if dataframe.empty:
            raise ValueError("The CSV contains no data rows.")
        analysis = analyse_dataframe(resolved_name, case_id, dataframe)
        created_at = datetime.utcnow().isoformat()
        connection = database_connection()
        try:
            connection.execute(
                """
                INSERT INTO cases (
                    id, name, original_filename, stored_filename, created_at,
                    row_count, column_count, timestamp_column, category_column,
                    summary_provider, analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id, resolved_name, original_name, stored_filename, created_at,
                    analysis["row_count"], analysis["column_count"], analysis["timestamp_column"],
                    analysis["category_column"], analysis["summary"]["provider"],
                    json.dumps(analysis, ensure_ascii=False),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        return {"id": case_id, "name": resolved_name, "created_at": created_at, "analysis": analysis}
    except Exception as error:
        stored_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/v1/cases")
def list_cases() -> list[dict[str, Any]]:
    connection = database_connection()
    try:
        rows = connection.execute(
            """
            SELECT id, name, original_filename, created_at, row_count, column_count,
                   timestamp_column, category_column, summary_provider
            FROM cases ORDER BY created_at DESC
            """
        ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


@app.get("/api/v1/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    row = get_case_row(case_id)
    result = dict(row)
    result["analysis"] = json.loads(result.pop("analysis_json"))
    result.pop("stored_filename", None)
    return result


@app.get("/api/v1/cases/{case_id}/records")
def get_records(
    case_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    case = get_case_row(case_id)
    dataframe = read_csv_file(UPLOAD_DIR / case["stored_filename"])
    page = dataframe.iloc[offset:offset + limit]
    return {
        "total": len(dataframe),
        "offset": offset,
        "limit": limit,
        "records": [json_record(record) for record in page.to_dict(orient="records")],
    }



def build_local_ai_case_context(case_row: sqlite3.Row) -> dict[str, Any]:
    analysis = json.loads(case_row["analysis_json"])
    timeline = analysis.get("timeline") or []

    events = []
    for event in timeline[:MAX_STAGES]:
        events.append({
            "timestamp": event.get("timestamp"),
            "stage": event.get("stage"),
            "title": event.get("title"),
            "summary": event.get("summary"),
            "description": event.get("description"),
            "user": event.get("user"),
            "target": event.get("target"),
            "mitre": event.get("mitre") or [],
            "evidence_count": len(event.get("evidence") or []),
        })

    return {
        "case_name": case_row["name"],
        "severity": analysis.get("severity", "Unknown"),
        "analysis_mode": analysis.get("analysis_mode"),
        "duration_seconds": analysis.get("duration_seconds"),
        "row_count": analysis.get("row_count"),
        "timeline": events,
    }


def ollama_json_request(url: str, payload: Optional[dict[str, Any]] = None, timeout: int = 120) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def choose_local_ollama_model() -> str:
    try:
        result = ollama_json_request("http://127.0.0.1:11434/api/tags", timeout=10)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Ollama is not reachable at http://127.0.0.1:11434. Open Ollama and try again.",
        ) from error

    names = [
        str(model.get("name") or model.get("model") or "").strip()
        for model in result.get("models", [])
    ]
    names = [name for name in names if name]

    if not names:
        raise HTTPException(
            status_code=503,
            detail="Ollama is running, but no local model is installed.",
        )

    preferred_prefixes = (
        "qwen2.5",
        "qwen3",
        "mistral",
        "gemma3",
        "phi4",
        "llama3.2",
        "llama3.1",
        "llama3",
    )

    for prefix in preferred_prefixes:
        for name in names:
            if name.lower().startswith(prefix):
                return name

    return names[0]



@app.get("/api/v1/cases/{case_id}/ai-summary")
def get_local_ai_incident_summary(case_id: str) -> dict[str, Any]:
    case_row = get_case_row(case_id)
    context = build_local_ai_case_context(case_row)

    model = choose_local_ollama_model()
    ollama_url = "http://127.0.0.1:11434/api/chat"

    system_prompt = (
        "You are a local digital-forensics analyst embedded in an incident replay prototype. "
        "Explain what happened in the reconstructed incident using only the supplied timeline and evidence-backed stage descriptions. "
        "Do not describe the user interface, the number of cards, or what is being displayed. "
        "Do not invent attacker identity, intent, malware, exfiltration, persistence, or causality unless the evidence explicitly supports it. "
        "Connect the observed events into a coherent chronological explanation and distinguish observations from interpretation. "
        "Write concise plain English for a mixed technical and non-technical audience. "
        "Return exactly these sections: Incident overview, What happened, Why it matters, Evidence caveat. "
        "Incident overview: 2-3 sentences summarising the apparent sequence. "
        "What happened: 3-6 chronological bullet points describing the most meaningful actions. "
        "Why it matters: one short paragraph explaining the security significance without overstating certainty. "
        "Evidence caveat: one short sentence saying the reconstruction should be validated against the underlying records."
    )

    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "Analyse what happened in this reconstructed incident:\n"
                           + json.dumps(context, ensure_ascii=False),
            },
        ],
        "options": {"temperature": 0.15},
    }

    try:
        result = ollama_json_request(ollama_url, payload, timeout=120)
    except urllib.error.HTTPError as error:
        try:
            details = error.read().decode("utf-8")
        except Exception:
            details = str(error)
        raise HTTPException(
            status_code=502,
            detail=f"Ollama rejected the incident-summary request: {details}",
        ) from error
    except urllib.error.URLError as error:
        raise HTTPException(
            status_code=503,
            detail="Ollama stopped responding while generating the incident summary.",
        ) from error
    except Exception as error:
        raise HTTPException(
            status_code=502,
            detail=f"Local AI incident-summary generation failed: {error}",
        ) from error

    summary = (
        result.get("message", {}).get("content")
        or result.get("response")
        or ""
    ).strip()

    if not summary:
        raise HTTPException(
            status_code=502,
            detail="The local AI returned an empty incident summary.",
        )

    return {
        "case_id": case_id,
        "summary": summary,
        "provider": f"Local AI via Ollama — {model}",
    }


@app.get("/api/v1/cases/{case_id}/ai-mitigation")
def get_local_ai_mitigation(case_id: str) -> dict[str, Any]:
    case_row = get_case_row(case_id)
    context = build_local_ai_case_context(case_row)

    model = choose_local_ollama_model()
    ollama_url = "http://127.0.0.1:11434/api/chat"

    system_prompt = (
        "You are a local defensive cybersecurity assistant embedded in a digital-forensics incident replay prototype. "
        "Use only the supplied reconstructed timeline and recommend defensive mitigation steps proportionate to the observed evidence. "
        "Do not invent attacker identity, intent, malware, exfiltration, persistence, or causality unless the evidence explicitly supports it. "
        "Do not claim that a mitigation has already been carried out. Do not recommend deleting evidence. "
        "Prioritise preserving evidence, containment, account and privilege review, validation, remediation, and monitoring. "
        "Return concise plain text with exactly these sections: "
        "Immediate containment, Priority remediation, Validation and monitoring, Investigator note. "
        "Immediate containment should contain 2-4 short bullet points. "
        "Priority remediation should contain 3-5 short bullet points. "
        "Validation and monitoring should contain 2-4 short bullet points. "
        "Investigator note should state what evidence should be confirmed before acting on assumptions."
    )

    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "Create defensive mitigation guidance from this reconstructed case:\n"
                           + json.dumps(context, ensure_ascii=False),
            },
        ],
        "options": {"temperature": 0.2},
    }

    try:
        result = ollama_json_request(ollama_url, payload, timeout=120)
    except urllib.error.HTTPError as error:
        try:
            details = error.read().decode("utf-8")
        except Exception:
            details = str(error)
        raise HTTPException(
            status_code=502,
            detail=f"Ollama rejected the mitigation request: {details}",
        ) from error
    except urllib.error.URLError as error:
        raise HTTPException(
            status_code=503,
            detail="Ollama stopped responding while generating mitigation guidance.",
        ) from error
    except Exception as error:
        raise HTTPException(
            status_code=502,
            detail=f"Local AI mitigation generation failed: {error}",
        ) from error

    mitigation = (
        result.get("message", {}).get("content")
        or result.get("response")
        or ""
    ).strip()

    if not mitigation:
        raise HTTPException(
            status_code=502,
            detail="The local AI returned empty mitigation guidance.",
        )

    return {
        "case_id": case_id,
        "mitigation": mitigation,
        "provider": f"Local AI via Ollama — {model}",
    }


@app.get("/api/v1/cases/{case_id}/notes")
def list_notes(case_id: str) -> list[dict[str, Any]]:
    get_case_row(case_id)
    connection = database_connection()
    try:
        rows = connection.execute(
            "SELECT id, case_id, text, created_at FROM notes WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,),
        ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


@app.post("/api/v1/cases/{case_id}/notes")
def create_note(case_id: str, text: str = Form(...)) -> dict[str, Any]:
    get_case_row(case_id)
    cleaned = text.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="The note cannot be empty.")
    note_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    connection = database_connection()
    try:
        connection.execute(
            "INSERT INTO notes (id, case_id, text, created_at) VALUES (?, ?, ?, ?)",
            (note_id, case_id, cleaned, created_at),
        )
        connection.commit()
    finally:
        connection.close()
    return {"id": note_id, "case_id": case_id, "text": cleaned, "created_at": created_at}


@app.delete("/api/v1/cases/{case_id}/notes/{note_id}")
def delete_note(case_id: str, note_id: str) -> dict[str, bool]:
    get_case_row(case_id)
    connection = database_connection()
    try:
        cursor = connection.execute("DELETE FROM notes WHERE id = ? AND case_id = ?", (note_id, case_id))
        connection.commit()
    finally:
        connection.close()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Note not found.")
    return {"deleted": True}
