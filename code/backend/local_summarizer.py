import re

MAX_WORDS = 18


def clean_summary(text: str) -> str:
    text = re.sub(r"\s+", " ", str(text)).strip()
    words = text.split()
    if len(words) > MAX_WORDS:
        text = " ".join(words[:MAX_WORDS]).rstrip(" ,;:")
    if text and not text.endswith((".", "!", "?")):
        text += "."
    return text


def summarise_stage(source_text: str, fallback: str) -> tuple[str, str]:
    # incident summary uses local Ollama.
    return clean_summary(fallback), "rule-based"
