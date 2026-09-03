from __future__ import annotations

from dataclasses import dataclass

from .ports import PresenceSurface
from .whiteboard import WhiteboardCommand


@dataclass(frozen=True)
class SpeechSegment:
    text: str
    started_at_ms: int
    duration_ms: int
    expression_ref: str = "speaking"
    gesture_ref: str = "idle"


@dataclass(frozen=True)
class TimelineBeat:
    speech: SpeechSegment
    board_commands: tuple[WhiteboardCommand, ...]
    pause_for_question: bool = False
    learner_prompt: str | None = None


@dataclass(frozen=True)
class LessonTimeline:
    session_id: str
    beats: tuple[TimelineBeat, ...]
    surface: PresenceSurface

    def live_drive(self) -> None:
        if self.surface.live:
            raise PermissionError("lesson timeline cannot drive live hologram or whiteboard hardware")
