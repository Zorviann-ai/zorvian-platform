from datetime import datetime, timezone
import pytest
from intelligence.education.assessment import AssessmentDenied, AssessmentService, OfficialExamSource, QuestionItem, QuestionPaper
from intelligence.education.learning import EventKind, LearningEvent, StudentLearningProfile, build_report


def test_mastery_and_next_topic():
    profile = StudentLearningProfile("stu", "t1")
    now = datetime.now(timezone.utc)
    profile.record(LearningEvent("e1", "stu", "t1", "algebra", EventKind.ATTEMPT, True, 0.8, False, 30, now))
    profile.record(LearningEvent("e2", "stu", "t1", "algebra", EventKind.ATTEMPT, False, 0.4, True, 20, now))
    assert profile.topics["algebra"].attempts == 2
    report = build_report(profile, profile.recommend_next(("algebra", "graphs")))
    assert report.student_id == "stu"


def test_mock_exam_blocks_help_and_does_not_fake_official_papers():
    paper = QuestionPaper("p1", "Generated practice", 3600, (QuestionItem("q1", "Solve", 2, "AO1", False, None),), "internal-ms", False)
    service = AssessmentService()
    attempt = service.start_mock(paper, "stu")
    with pytest.raises(AssessmentDenied):
        service.hint_during_exam(attempt)
    assert service.label_generated(paper.items[0]) == "generated_practice_not_an_official_past_paper"


def test_official_past_paper_requires_validated_source():
    service = AssessmentService(authorised_sources=(OfficialExamSource("aqa-8300-p1", "AQA 8300 Paper 1", True),))
    with pytest.raises(AssessmentDenied):
        service.label_generated(QuestionItem("q1", "Solve", 2, "AO1", True, None))
    with pytest.raises(AssessmentDenied):
        service.label_generated(QuestionItem("q1", "Solve", 2, "AO1", True, "unknown-source"))
    assert service.label_generated(QuestionItem("q1", "Solve", 2, "AO1", False, None)) == "generated_practice_not_an_official_past_paper"
    assert service.label_generated(QuestionItem("q1", "Solve", 2, "AO1", True, "aqa-8300-p1")) == "authorised_source"
