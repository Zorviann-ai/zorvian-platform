"""Fail-closed Gate 6 production-readiness checks."""
from dataclasses import asdict, dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    passed: bool
    detail: str


_REQUIRED_SMTP = ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM")
_FORBIDDEN_DB_ROOTS = ("/tmp", "/app", "/workspace")


def _set(name, env):
    return bool(str(env.get(name, "")).strip())


def persistent_database_configured(env=None):
    env = os.environ if env is None else env
    db_path = str(env.get("SQLITE_PATH", "")).strip()
    if not db_path:
        return False
    path = Path(db_path)
    if not path.is_absolute():
        return False
    value = str(path)
    return not any(value == root or value.startswith(root + "/") for root in _FORBIDDEN_DB_ROOTS)


def environment_isolated(env=None):
    env = os.environ if env is None else env
    name = str(env.get("ZORVIAN_ENV", "")).strip().lower()
    environment_id = str(env.get("ZORVIAN_ENVIRONMENT_ID", "")).strip()
    database_id = str(env.get("ZORVIAN_DATABASE_ID", "")).strip()
    return name in {"staging", "production"} and bool(environment_id and database_id)


def production_secrets_safe(env=None):
    env = os.environ if env is None else env
    pepper = str(env.get("GUARDIAN_HASH_PEPPER", "")).strip()
    adapter_key = str(env.get("ZORVIAN_AI_ADAPTER_KEY", "")).strip()
    return len(pepper) >= 32 and pepper != "change-me-in-railway" and len(adapter_key) >= 16


def readiness_report(env=None):
    env = os.environ if env is None else env
    checks = [
        ReadinessCheck("environment_isolation", environment_isolated(env), "Unique environment and database identifiers required."),
        ReadinessCheck("persistent_database", persistent_database_configured(env), "SQLite must use an attached persistent volume path."),
        ReadinessCheck("email_delivery", all(_set(x, env) for x in _REQUIRED_SMTP), "Verified SMTP configuration required."),
        ReadinessCheck("guardian_secrets", production_secrets_safe(env), "Guardian pepper and server-side AI adapter key required."),
        ReadinessCheck("ai_adapter", _set("ZORVIAN_AI_ADAPTER_URL", env), "Approved server-side provider adapter required."),
        ReadinessCheck("public_origin", _set("ALLOWED_ORIGINS", env), "Explicit origin allowlist required."),
    ]
    return {
        "gate": 6,
        "ready": all(item.passed for item in checks),
        "environment": str(env.get("ZORVIAN_ENV", "unknown")).lower(),
        "checks": [asdict(item) for item in checks],
    }
