from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import uuid

from .ports import ClosedWhiteboardDevice, WhiteboardDevicePort


class BoardAction(str, Enum):
    CLEAR = "clear_board"
    WRITE_TEXT = "write_text"
    WRITE_EQUATION = "write_equation"
    DRAW_LINE = "draw_line"
    DRAW_SHAPE = "draw_shape"
    DRAW_GRAPH = "draw_graph"
    PLOT_POINTS = "plot_points"
    SHOW_AXIS = "show_axis"
    HIGHLIGHT = "highlight"
    UNDERLINE = "underline"
    CIRCLE = "circle"
    ANNOTATE = "annotate"
    ADD_IMAGE_REF = "add_image_reference"
    ADD_DIAGRAM = "add_diagram"
    ADD_TABLE = "add_table"
    ADD_TIMELINE = "add_timeline"
    ADD_MAP_REF = "add_map_reference"
    ADD_QUESTION = "add_question"
    REVEAL_ANSWER = "reveal_answer"
    ERASE = "erase_object"
    STEP_WORKING = "step_by_step_working"
    REPLAY = "replay_explanation"


@dataclass(frozen=True)
class Layout:
    x: float = 0.0
    y: float = 0.0
    width: float = 1.0
    height: float = 1.0


@dataclass(frozen=True)
class WhiteboardCommand:
    command_id: str
    session_id: str
    sequence: int
    created_at: datetime
    action: BoardAction
    content: str
    layout: Layout
    purpose: str
    narration_at_ms: int
    reversible: bool = True


@dataclass
class WhiteboardScene:
    session_id: str
    commands: list[WhiteboardCommand] = field(default_factory=list)

    def add(self, action: BoardAction, content: str, *, purpose: str, narration_at_ms: int, layout: Layout | None = None) -> WhiteboardCommand:
        cmd = WhiteboardCommand(
            command_id=str(uuid.uuid4()),
            session_id=self.session_id,
            sequence=len(self.commands) + 1,
            created_at=datetime.now(timezone.utc),
            action=action,
            content=content,
            layout=layout or Layout(),
            purpose=purpose,
            narration_at_ms=narration_at_ms,
            reversible=True,
        )
        self.commands.append(cmd)
        return cmd


class WhiteboardRoute:
    def __init__(self, device: WhiteboardDevicePort | None = None):
        self.device = device or ClosedWhiteboardDevice()
        self.scenes: dict[str, WhiteboardScene] = {}

    def scene(self, session_id: str) -> WhiteboardScene:
        return self.scenes.setdefault(session_id, WhiteboardScene(session_id))

    def present(self, command: WhiteboardCommand) -> None:
        self.device.execute(command)
