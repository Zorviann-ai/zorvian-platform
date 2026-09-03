from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum

from .ports import ClosedTextbookProvider, TextbookProviderPort


class SourceType(str, Enum):
    SPECIFICATION = "specification"
    STATUTORY_GUIDANCE = "statutory_guidance"
    OPEN_RESOURCE = "open_resource"
    TEXTBOOK = "textbook"
    CLIENT_PACK = "client_pack"
    INTERNAL = "internal"


class SourceCategory(str, Enum):
    OFFICIAL_PUBLIC = "official_public"
    OPEN_LICENSED = "open_licensed"
    LICENSED_COMMERCIAL = "licensed_commercial"
    CLIENT_PROVIDED = "client_provided"
    INTERNAL_CAELOMERE = "internal_caelomere"
    RESTRICTED = "restricted"


class SourceDenied(PermissionError):
    pass


@dataclass(frozen=True)
class EducationSource:
    source_id: str
    title: str
    publisher: str
    source_type: SourceType
    subject: str
    qualification: str
    version_year: str
    category: SourceCategory
    licence_status: str
    permitted_uses: tuple[str, ...]
    attribution: str
    retrieval_reference: str
    effective_date: date
    review_date: date
    permission_present: bool = False


class SourceRegistry:
    def __init__(self, textbook_provider: TextbookProviderPort | None = None):
        self._sources: dict[str, EducationSource] = {}
        self.textbook_provider = textbook_provider or ClosedTextbookProvider()

    def register(self, source: EducationSource) -> EducationSource:
        self._sources[source.source_id] = source
        return source

    def get(self, source_id: str) -> EducationSource:
        return self._sources[source_id]

    def may_use(self, source: EducationSource, use: str) -> bool:
        if source.category in {SourceCategory.RESTRICTED, SourceCategory.LICENSED_COMMERCIAL} and not source.permission_present:
            return False
        return use in source.permitted_uses or "teach" in source.permitted_uses

    def require_use(self, source_id: str, use: str) -> EducationSource:
        source = self.get(source_id)
        if not self.may_use(source, use):
            raise SourceDenied(f"source {source_id} is not permitted for {use}")
        return source

    def fetch_extract(self, source_id: str) -> dict:
        source = self.require_use(source_id, "extract")
        return self.textbook_provider.fetch_licensed_extract(source.source_id)
