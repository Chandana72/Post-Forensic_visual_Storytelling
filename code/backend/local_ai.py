from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from fastapi import HTTPException


def ollama_json_request(
    url: str,
    payload: dict[str, Any] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
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
        raise HTTPException(status_code=503, detail="Ollama is running, but no local model is installed.")

    preferred = ("qwen2.5", "qwen3", "mistral", "gemma3", "phi4", "llama3.2", "llama3.1", "llama3")
    for prefix in preferred:
        for name in names:
            if name.lower().startswith(prefix):
                return name
    return names[0]


def generate_with_ollama(system_prompt: str, user_prompt: str, temperature: float = 0.15) -> tuple[str, str]:
    model = choose_local_ollama_model()
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "options": {"temperature": temperature},
    }

    try:
        result = ollama_json_request("http://127.0.0.1:11434/api/chat", payload, timeout=120)
    except urllib.error.HTTPError as error:
        try:
            details = error.read().decode("utf-8")
        except Exception:
            details = str(error)
        raise HTTPException(status_code=502, detail=f"Ollama rejected the request: {details}") from error
    except urllib.error.URLError as error:
        raise HTTPException(status_code=503, detail="Ollama stopped responding.") from error
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Local AI generation failed: {error}") from error

    text = (result.get("message", {}).get("content") or result.get("response") or "").strip()
    if not text:
        raise HTTPException(status_code=502, detail="The local AI returned an empty response.")

    return text, f"Local AI via Ollama — {model}"
