from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class EducationPortDenied(PermissionError):
    pass


class CurriculumImportPort(Protocol):
    provider_id: str

    def import_specification(self, payload: dict) -> dict:
        ...


class TextbookProviderPort(Protocol):
    provider_id: str

    def fetch_licensed_extract(self, source_id: str) -> dict:
        ...


class WhiteboardDevicePort(Protocol):
    adapter_id: str

    def execute(self, command: object) -> None:
        ...


class ClosedCurriculumImport:
    provider_id = "closed_curriculum_import"

    def import_specification(self, payload: dict) -> dict:
        raise EducationPortDenied("Curriculum import provider is closed in Stage 1")


class ClosedTextbookProvider:
    provider_id = "closed_textbook"

    def fetch_licensed_extract(self, source_id: str) -> dict:
        raise EducationPortDenied("Textbook provider is closed; no unlicensed ingest")


class ClosedWhiteboardDevice:
    adapter_id = "closed_whiteboard"

    def execute(self, command: object) -> None:
        raise EducationPortDenied("WhiteboardDevicePort is closed; no live classroom control")


@dataclass(frozen=True)
class PresenceSurface:
    kind: str  # web_avatar | classroom_display | interactive_whiteboard | holographic_presence
    live: bool = False
