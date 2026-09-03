from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EventKind(str, Enum):
    ATTEMPT = "attempt"
    HINT = "hint"
    LESSON = "lesson"


@dataclass(frozen=True)
class LearningEvent:
    event_id: str
    student_id: str
    tenant_id: str
    topic_id: str
    kind: EventKind
    correct: bool | None
    confidence: float | None
    hint_used: bool
    duration_seconds: int
    created_at: datetime


@dataclass
class TopicMastery:
    topic_id: str
    attempts: int = 0
    correct: int = 0
    hint_uses: int = 0
    time_spent: int = 0
    estimate: float = 0.0


@dataclass
class StudentLearningProfile:
    student_id: str
    tenant_id: str
    topics: dict[str, TopicMastery] = field(default_factory=dict)
    events: list[LearningEvent] = field(default_factory=list)
    misconceptions: list[str] = field(default_factory=list)
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)

    def record(self, event: LearningEvent) -> TopicMastery:
        if event.tenant_id != self.tenant_id or event.student_id != self.student_id:
            raise PermissionError("learning event tenant/student mismatch")
        self.events.append(event)
        mastery = self.topics.setdefault(event.topic_id, TopicMastery(event.topic_id))
        if event.kind is EventKind.ATTEMPT:
            mastery.attempts += 1
            if event.correct:
                mastery.correct += 1
        if event.hint_used:
            mastery.hint_uses += 1
        mastery.time_spent += event.duration_seconds
        if mastery.attempts:
            mastery.estimate = mastery.correct / mastery.attempts
        if event.correct is False:
            self.weaknesses.append(event.topic_id)
        elif event.correct is True:
            self.strengths.append(event.topic_id)
        return mastery

    def recommend_next(self, ordered_topics: tuple[str, ...]) -> str | None:
        for topic in ordered_topics:
            mastery = self.topics.get(topic)
            if mastery is None or mastery.estimate < 0.8:
                return topic
        return ordered_topics[-1] if ordered_topics else None


@dataclass(frozen=True)
class TeacherParentReport:
    student_id: str
    strengths: tuple[str, ...]
    weaknesses: tuple[str, ...]
    recent_topics: tuple[str, ...]
    recommended_next: str | None
    sessions: int
    safeguarding_placeholder: str = "none"


def build_report(profile: StudentLearningProfile, recommended: str | None) -> TeacherParentReport:
    return TeacherParentReport(
        student_id=profile.student_id,
        strengths=tuple(dict.fromkeys(profile.strengths)),
        weaknesses=tuple(dict.fromkeys(profile.weaknesses)),
        recent_topics=tuple(e.topic_id for e in profile.events[-8:]),
        recommended_next=recommended,
        sessions=len(profile.events),
    )
