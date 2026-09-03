import ast
from pathlib import Path
import pytest
from intelligence.education.ports import ClosedWhiteboardDevice, PresenceSurface
from intelligence.education.timeline import LessonTimeline, SpeechSegment, TimelineBeat
from intelligence.education.whiteboard import BoardAction, WhiteboardRoute


def test_internal_commands_and_closed_device():
    route = WhiteboardRoute()
    assert route.device.adapter_id == "closed_whiteboard"
    cmd = route.scene("lesson-1").add(BoardAction.WRITE_EQUATION, "y = mx + c", purpose="definition", narration_at_ms=400)
    assert cmd.reversible is True
    with pytest.raises(PermissionError):
        route.present(cmd)
    with pytest.raises(PermissionError):
        ClosedWhiteboardDevice().execute(cmd)


def test_timeline_cannot_drive_live_surfaces():
    cmd = WhiteboardRoute().scene("s").add(BoardAction.WRITE_TEXT, "hello", purpose="intro", narration_at_ms=0)
    timeline = LessonTimeline("s", (TimelineBeat(SpeechSegment("Hello", 0, 800), (cmd,), True, "?"),), PresenceSurface("holographic_presence", True))
    with pytest.raises(PermissionError):
        timeline.live_drive()


def test_education_package_does_not_touch_stage4g_engine():
    root = Path(__file__).resolve().parents[1] / "intelligence" / "education"
    forbidden_mods = {"intelligence.execution_production_webhook", "intelligence.execution_pilot_dispatch"}
    forbidden_names = {"_claimed_production_submit", "execute_once", "submit_production_pilot"}
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported, names = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                names.add(node.func.id)
            if isinstance(node, ast.Attribute):
                names.add(node.attr)
        assert not (imported & forbidden_mods), path.name
        assert not (names & forbidden_names), path.name
