from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LessonMode(str, Enum):
    LEARN = "learn"
    PRACTICE = "practice"
    REVISION = "revision"
    MOCK_EXAM = "mock_exam"


class AssessmentDenied(PermissionError):
    pass


@dataclass(frozen=True)
class QuestionItem:
    question_id: str
    prompt: str
    marks: int
    assessment_objective: str
    official_past_paper: bool
    source_id: str | None


@dataclass(frozen=True)
class OfficialExamSource:
    source_id: str
    title: str
    authorised: bool


@dataclass(frozen=True)
class QuestionPaper:
    paper_id: str
    title: str
    time_limit_seconds: int
    items: tuple[QuestionItem, ...]
    mark_scheme_ref: str
    official: bool = False


@dataclass(frozen=True)
class ExamAttempt:
    paper_id: str
    student_id: str
    answers: dict[str, str]
    submitted: bool
    help_allowed: bool


class AssessmentService:
    def __init__(self, authorised_sources: tuple[OfficialExamSource, ...] = ()):
        self.authorised_sources = {s.source_id: s for s in authorised_sources if s.authorised}

    def start_mock(self, paper: QuestionPaper, student_id: str) -> ExamAttempt:
        if paper.official and not paper.mark_scheme_ref:
            raise AssessmentDenied("official paper requires an authorised mark scheme reference")
        if paper.official:
            for item in paper.items:
                self.label_generated(item)
        return ExamAttempt(paper.paper_id, student_id, {}, False, False)

    def hint_during_exam(self, attempt: ExamAttempt) -> None:
        if not attempt.help_allowed:
            raise AssessmentDenied("strict mock exam mode does not allow help")

    def label_generated(self, item: QuestionItem) -> str:
        if not item.official_past_paper:
            return "generated_practice_not_an_official_past_paper"
        if not item.source_id:
            raise AssessmentDenied("official past-paper label requires a source_id")
        source = self.authorised_sources.get(item.source_id)
        if source is None or not source.authorised:
            raise AssessmentDenied("official past-paper label requires a validated authorised source")
        return "authorised_source"
