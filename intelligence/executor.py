"""Server-side provider execution adapters for Gate 5.

Browser clients never receive provider credentials. A configurable remote adapter may
be enabled through environment variables; otherwise the controlled local beta engine
keeps the end-to-end Core path testable without pretending an external model ran.
"""
import json
import os
import urllib.request
import uuid

from .guard import guardian_check


def _local_beta(prompt, ctx):
    text = guardian_check(prompt)
    module = ctx.module
    guidance = {
        "receptionist": "Classify the enquiry, identify missing details, propose a concise response and a safe hand-off.",
        "zai-auto": "Compare the stated automotive requirements, flag missing commercial/compliance facts and propose the next authorised step.",
        "freshx": "Assess product, supply, market, evidence and readiness gaps without inventing certifications or buyer commitments.",
        "tenders": "Map requirements to evidence, identify gaps and prepare a controlled response plan using verified facts only.",
        "lead-intelligence": "Prioritise supplied business signals and explain next actions without inferring sensitive personal traits.",
        "document-studio": "Structure a professional draft from supplied facts and clearly mark assumptions or missing evidence.",
        "business-control": "Prioritise supplied operational items, conflicts and next actions within the user's permissions.",
        "route-intelligence": "Plan from supplied routing constraints and flag any live/safety information that requires a verified data source.",
    }[module]
    output = f"ZORVIAN CONNECTED BETA\n\nTask: {text}\n\nSpecialist direction: {guidance}\n\nControl: No external action has been executed. Human review is required for consequential use."
    return {"task_id": str(uuid.uuid4()), "output": output, "confidence": 0.72, "source_refs": (), "assumptions": ("Controlled local beta engine used; no external model provider configured.",)}


def _remote_adapter(provider_name, prompt, ctx):
    base = os.getenv("ZORVIAN_AI_ADAPTER_URL", "").strip()
    key = os.getenv("ZORVIAN_AI_ADAPTER_KEY", "").strip()
    model = os.getenv("ZORVIAN_AI_MODEL", "").strip()
    if not base or not key:
        raise RuntimeError("Remote Zorvian AI adapter is not configured")
    payload = json.dumps({
        "provider": provider_name,
        "model": model,
        "prompt": guardian_check(prompt),
        "context": ctx.for_audit(),
    }).encode("utf-8")
    req = urllib.request.Request(base, data=payload, method="POST", headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8"))
    return data


def execute_provider(provider_name, prompt, ctx):
    if provider_name == "zorvian-local-beta":
        return _local_beta(prompt, ctx)
    return _remote_adapter(provider_name, prompt, ctx)
