"""Guardian boundary checks applied before prompts reach a provider adapter."""
import re

_BLOCK_PATTERNS = (
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"reveal\s+(the\s+)?system\s+prompt",
    r"show\s+(me\s+)?(the\s+)?api\s*key",
    r"dump\s+(all\s+)?credentials",
    r"access\s+(another|other)\s+(tenant|customer|workspace)",
    r"bypass\s+(guardian|permissions|approval|authentication)",
    r"disable\s+(guardian|audit|evidence)",
    r"override\s+(legal|financial)\s+intelligence",
    r"execute\s+cross[- ]tenant",
    r"delete\s+audit\s+history",
    r"skip\s+evidence",
    r"pretend\s+action\s+succeeded",
    r"expose\s+secrets",
)

_DISCUSSION_HINTS = (
    r"\b(explain|discuss|describe|analyse|analyze|what\s+is|how\s+does|why\s+does)\b",
    r"\b(legitimate discussion|security review question)\b",
)

_SECRET_RE = re.compile(
    r"(?i)((?:api[_-]?key|password|secret|bearer|private[_-]?key|smtp[_-]?password|reset[_-]?token)\s*[:=]\s*)([^\s]{6,})"
)


def _is_discussion(text: str, intent: str | None = None) -> bool:
    if (intent or "").lower() in {"discuss", "discussion", "analyse", "analyze", "advisory"}:
        return True
    lowered = text.lower()
    if any(re.search(p, lowered) for p in _DISCUSSION_HINTS) and not re.search(
        r"\b(now\s+execute|do\s+it\s+now|perform\s+this|carry\s+out)\b", lowered
    ):
        return True
    return False


def classify_boundary(prompt: str, intent: str | None = None) -> str:
    text = (prompt or "").strip()
    if not text:
        return "empty"
    lowered = text.lower()
    matched = any(re.search(pattern, lowered) for pattern in _BLOCK_PATTERNS)
    if not matched:
        return "clear"
    if _is_discussion(text, intent):
        return "discussion"
    return "blocked_execution"


def redact_secrets(text: str) -> tuple[str, bool]:
    raw = text or ""
    found = bool(_SECRET_RE.search(raw))
    redacted = _SECRET_RE.sub(r"\1[REDACTED]", raw)
    return redacted, found


def guardian_check(prompt: str, intent: str | None = None) -> str:
    text = (prompt or "").strip()
    if not text:
        raise ValueError("Prompt is required")
    if len(text) > 12000:
        raise ValueError("Prompt exceeds Gate 5 beta limit")
    state = classify_boundary(text, intent=intent)
    if state == "blocked_execution":
        raise PermissionError("Guardian blocked a prompt-injection or data-access attempt")
    return text
