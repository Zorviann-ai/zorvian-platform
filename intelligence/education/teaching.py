from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .curriculum import CurriculumNode
from .languages import LanguagePreference
from .sources import EducationSource

CELESTE_TEACHER_ID = "celeste-teacher"


class TeachingStyle(str, Enum):
    CONCISE = "concise"
    DETAILED = "detailed"
    VISUAL = "visual"
    VERBAL = "verbal"
    FORMAL = "formal"
    FRIENDLY = "friendly"
    SOCRATIC = "socratic"
    STEP_BY_STEP = "step_by_step"
    EXAM_FOCUSED = "exam_focused"
    REVISION = "revision"


class LearnerRequest(str, Enum):
    SIMPLER = "simpler"
    ANOTHER_WAY = "another_way"
    EXAMPLE = "example"
    TEST_ME = "test_me"
    TRANSLATE = "translate"


@dataclass(frozen=True)
class TeacherProfile:
    teacher_id: str = CELESTE_TEACHER_ID
    display_name: str = "Celeste"
    identity_locked: bool = True


@dataclass(frozen=True)
class SubjectContext:
    subject: str
    qualification: str
    awarding_body: str
    specification_code: str


@dataclass(frozen=True)
class LearningObjective:
    objective_id: str
    text: str


@dataclass(frozen=True)
class StudentLessonContext:
    student_id: str
    tenant_id: str
    age_or_level: str
    difficulty: str
    style: tuple[TeachingStyle, ...]
    language: LanguagePreference
    subject: SubjectContext


@dataclass(frozen=True)
class Explanation:
    simple: str
    method: str
    working: str
    conclusion: str
    key_points: tuple[str, ...]
    alternative: str = ""


@dataclass(frozen=True)
class WorkedExample:
    prompt: str
    working: str
    answer: str


@dataclass(frozen=True)
class PracticeQuestion:
    question_id: str
    prompt: str
    marks: int = 1


@dataclass(frozen=True)
class Hint:
    text: str
    level: int = 1


@dataclass(frozen=True)
class Correction:
    misconception: str
    correction: str


@dataclass(frozen=True)
class LessonSummary:
    text: str
    next_step: str


@dataclass(frozen=True)
class LessonOutput:
    answer: str
    explanation: Explanation
    worked_example: WorkedExample | None
    key_points: tuple[str, ...]
    provenance: tuple[str, ...]
    comprehension_check: str
    practice: PracticeQuestion
    hints: tuple[Hint, ...]
    correction: Correction | None
    summary: LessonSummary
    teacher_id: str = CELESTE_TEACHER_ID
    subject: str = ""
    evidence_basis: str = "GENERAL_EXPLANATION"


@dataclass
class TeachingSession:
    session_id: str
    teacher: TeacherProfile
    context: StudentLessonContext
    outputs: list[LessonOutput] = field(default_factory=list)


class CelesteTeacher:
    def __init__(self) -> None:
        self.profile = TeacherProfile()

    def switch_subject(self, context: StudentLessonContext, subject: SubjectContext) -> StudentLessonContext:
        return StudentLessonContext(
            student_id=context.student_id,
            tenant_id=context.tenant_id,
            age_or_level=context.age_or_level,
            difficulty=context.difficulty,
            style=context.style,
            language=context.language,
            subject=subject,
        )

    def teach(self, context, objective: LearningObjective, node: CurriculumNode, source: EducationSource, adaptation: LearnerRequest | None = None, knowledge=None) -> LessonOutput:
        simple = f"{objective.text} explained for {context.age_or_level}."
        if adaptation is LearnerRequest.SIMPLER:
            simple = f"Easier version: {objective.text}."
        alternative = "Another route through the same idea." if adaptation is LearnerRequest.ANOTHER_WAY else ""
        lang_note = f" Respond in {context.language.spoken.value} ({context.language.script.value})." if adaptation is LearnerRequest.TRANSLATE else ""
        practice_prompt = "Short check: apply the method without notes." if adaptation is LearnerRequest.TEST_ME else "Try this question."
        evidence_basis = "GENERAL_EXPLANATION"
        extra_prov: tuple[str, ...] = ()
        if knowledge is not None:
            evidence_basis = getattr(knowledge.evidence_basis, "value", str(knowledge.evidence_basis))
            extra_prov = (knowledge.provenance_summary,)
            reason = getattr(knowledge, "retrieval_reason", None)
            if evidence_basis == "SOURCE_BACKED":
                simple = f"Based on the approved curriculum source: {simple}"
            elif reason == "METADATA_ONLY_REFERENCE":
                simple = (
                    "An approved curriculum reference is available, but its body text is not "
                    f"ingested in the governed vault. General explanation: {simple}"
                )
            elif reason == "STALE_SOURCE":
                simple = (
                    "The available curriculum source requires revalidation and cannot currently "
                    f"be treated as verified. General explanation: {simple}"
                )
            elif evidence_basis == "PROFESSIONAL_REVIEW_REQUIRED":
                simple = f"Professional review required. General explanation: {simple}"
            elif evidence_basis == "NO_RELEVANT_SOURCE_MATCH":
                simple = f"General explanation only (no approved source match): {simple}"
        return LessonOutput(
            answer=simple + lang_note,
            explanation=Explanation(simple, "Named method for this objective", "Student-facing steps, not hidden chain-of-thought.", "Close the idea and check it.", (objective.text, node.assessment_objective), alternative),
            worked_example=WorkedExample("Example prompt", "Step 1 → Step 2", "result"),
            key_points=(objective.text, node.topic),
            provenance=(source.source_id, source.retrieval_reference, node.specification_version) + extra_prov,
            comprehension_check="Can you say the method in your own words?",
            practice=PracticeQuestion("q1", practice_prompt),
            hints=(Hint("Look at the first given."),),
            correction=None,
            summary=LessonSummary("Covered the objective.", "Recommended next topic from mastery model."),
            teacher_id=self.profile.teacher_id,
            subject=context.subject.subject,
            evidence_basis=evidence_basis,
        )
