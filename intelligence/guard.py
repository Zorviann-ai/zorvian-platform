"""Guardian boundary checks applied before prompts reach a provider adapter."""
import re

_BLOCK_PATTERNS = (
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"reveal\s+(the\s+)?system\s+prompt",
    r"show\s+(me\s+)?(the\s+)?api\s*key",
    r"dump\s+(all\s+)?credentials",
    r"access\s+(another|other)\s+(tenant|customer|workspace)",
    r"bypass\s+(guardian|permissions|approval|authentication)",
)


def guardian_check(prompt: str) -> str:
    text = (prompt or "").strip()
    if not text:
        raise ValueError("Prompt is required")
    if len(text) > 12000:
        raise ValueError("Prompt exceeds Gate 5 beta limit")
    lowered = text.lower()
    if any(re.search(pattern, lowered) for pattern in _BLOCK_PATTERNS):
        raise PermissionError("Guardian blocked a prompt-injection or data-access attempt")
    return text
