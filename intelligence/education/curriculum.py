from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Country(str, Enum):
    ENGLAND = "england"
    WALES = "wales"
    NORTHERN_IRELAND = "northern_ireland"
    SCOTLAND = "scotland"


class EducationSystem(str, Enum):
    ENGLAND_NATIONAL_CURRICULUM = "england_national_curriculum"


class AwardingBody(str, Enum):
    AQA = "aqa"
    PEARSON_EDEXCEL = "pearson_edexcel"
    OCR = "ocr"
    WJEC = "wjec"
    EDUQAS = "eduqas"
    DFE = "dfe"
    OTHER = "other"


class Qualification(str, Enum):
    PRIMARY = "primary"
    KS1 = "ks1"
    KS2 = "ks2"
    KS3 = "ks3"
    KS4 = "ks4"
    GCSE = "gcse"
    AS_LEVEL = "as_level"
    A_LEVEL = "a_level"
    POST16 = "post16"


class KeyStage(str, Enum):
    KS1 = "ks1"
    KS2 = "ks2"
    KS3 = "ks3"
    KS4 = "ks4"
    KS5 = "ks5"


@dataclass(frozen=True)
class CurriculumNode:
    node_id: str
    country: Country
    system: EducationSystem
    awarding_body: AwardingBody
    qualification: Qualification
    key_stage: KeyStage
    subject: str
    specification_code: str
    specification_version: str
    topic: str
    learning_objective: str
    lesson_unit: str
    assessment_objective: str
    source_id: str


class CurriculumDenied(ValueError):
    pass


@dataclass
class CurriculumCatalogue:
    nodes: list[CurriculumNode] = field(default_factory=list)

    def register(self, node: CurriculumNode) -> CurriculumNode:
        self.nodes.append(node)
        return node

    def lookup(self, *, awarding_body: AwardingBody, specification_code: str, subject: str | None = None):
        matches = [n for n in self.nodes if n.awarding_body is awarding_body and n.specification_code == specification_code]
        if subject:
            matches = [n for n in matches if n.subject.lower() == subject.lower()]
        return matches

    def assert_mapping(self, *, awarding_body: AwardingBody, specification_code: str, subject: str) -> CurriculumNode:
        matches = self.lookup(awarding_body=awarding_body, specification_code=specification_code, subject=subject)
        if not matches:
            raise CurriculumDenied(f"no curriculum node for {awarding_body.value} {specification_code} {subject}")
        return matches[0]

    def reject_cross_board(self, node: CurriculumNode, claimed_body: AwardingBody) -> None:
        if node.awarding_body is not claimed_body:
            raise CurriculumDenied("invalid cross-board curriculum mapping")
