from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd

from config import COLUMN_ALIASES


def clean_column_name(value: Any) -> str:
    text = str(value).strip()
    return re.sub(r"\s+", "_", text) if text else "unnamed_column"


def make_unique_columns(columns: list[Any]) -> list[str]:
    counts: dict[str, int] = {}
    result: list[str] = []
    for column in columns:
        base = clean_column_name(column)
        counts[base] = counts.get(base, 0) + 1
        result.append(base if counts[base] == 1 else f"{base}_{counts[base]}")
    return result


def safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, pd.Timestamp):
        return None if pd.isna(value) else value.isoformat()
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def normalise_text(value: Any) -> str | None:
    value = safe_value(value)
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in {"", "none", "null", "nan", "n/a", "-"} else text


def event_id_value(value: Any) -> str | None:
    text = normalise_text(value)
    if text is None:
        return None
    match = re.search(r"\d+", text)
    return match.group(0) if match else text


def find_column(dataframe: pd.DataFrame, alias_group: str) -> str | None:
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


def detect_timestamp(dataframe: pd.DataFrame) -> tuple[str | None, pd.Series | None]:
    preferred = find_column(dataframe, "timestamp")
    candidates = ([preferred] if preferred else []) + [
        column for column in dataframe.columns if column != preferred
    ]
    best_column = None
    best_series = None
    best_score = 0.0
    sample_size = min(2500, len(dataframe))

    for column in candidates:
        values = dataframe[column].head(sample_size)
        if pd.api.types.is_numeric_dtype(values):
            continue
        non_empty = values.dropna()
        if non_empty.empty:
            continue

        parsed = pd.to_datetime(non_empty, errors="coerce", utc=True)
        ratio = float(parsed.notna().mean())
        score = ratio + (0.35 if column == preferred else 0)

        if ratio >= 0.55 and score > best_score:
            best_column = column
            best_series = pd.to_datetime(dataframe[column], errors="coerce", utc=True)
            best_score = score

    return best_column, best_series


def _value(row: pd.Series, column: str | None) -> str | None:
    return normalise_text(row.get(column)) if column else None


def _numeric_value(row: pd.Series, column: str | None) -> float | None:
    if not column:
        return None
    value = row.get(column)
    try:
        if pd.isna(value):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def detect_schema(dataframe: pd.DataFrame) -> dict[str, str | None]:
    return {key: find_column(dataframe, key) for key in COLUMN_ALIASES}


def build_search_text(row: pd.Series, schema: dict[str, str | None]) -> str:
    # Deliberately excludes labels such as "stage_expected"; classification should
    # be based on forensic content, not ground-truth/test annotations.
    preferred_groups = (
        "action", "result", "message", "object", "source",
        "computer", "source_host", "target_host", "user"
    )
    values: list[str] = []
    seen_columns: set[str] = set()

    for group in preferred_groups:
        column = schema.get(group)
        if column and column not in seen_columns:
            value = normalise_text(row.get(column))
            if value:
                values.append(value)
            seen_columns.add(column)

    # Add remaining text columns for genuinely generic CSV support.
    ignored_tokens = ("stage_expected", "ground_truth", "label_expected", "rive_animation")
    for column in row.index:
        if column in seen_columns:
            continue
        lowered = column.lower()
        if any(token in lowered for token in ignored_tokens):
            continue
        value = normalise_text(row.get(column))
        if value and len(value) <= 1000:
            values.append(value)

    return " | ".join(values).lower()


def normalize_dataframe(
    dataframe: pd.DataFrame,
    timestamps: pd.Series,
) -> tuple[list[dict[str, Any]], dict[str, str | None]]:
    schema = detect_schema(dataframe)
    events: list[dict[str, Any]] = []

    for index, row in dataframe.iterrows():
        timestamp = timestamps.iloc[index]
        if pd.isna(timestamp):
            continue

        computer = _value(row, schema.get("computer"))
        source_host = _value(row, schema.get("source_host"))
        target_host = _value(row, schema.get("target_host")) or computer

        events.append({
            "row_number": int(index) + 1,
            "timestamp": timestamp,
            "event_id": event_id_value(row.get(schema["event_id"])) if schema.get("event_id") else None,
            "actor": _value(row, schema.get("user")),
            "computer": computer,
            "source_host": source_host,
            "target_host": target_host,
            "source_ip": _value(row, schema.get("source_ip")),
            "target_ip": _value(row, schema.get("target_ip")),
            "source": _value(row, schema.get("source")),
            "action": _value(row, schema.get("action")),
            "result": _value(row, schema.get("result")),
            "message": _value(row, schema.get("message")),
            "object": _value(row, schema.get("object")),
            "bytes_out": _numeric_value(row, schema.get("bytes_out")),
            "bytes_in": _numeric_value(row, schema.get("bytes_in")),
            "search_text": build_search_text(row, schema),
        })

    return events, schema
