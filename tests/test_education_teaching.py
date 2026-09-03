from datetime import date
from intelligence.education.curriculum import AwardingBody, Country, CurriculumNode, EducationSystem, KeyStage, Qualification
from intelligence.education.languages import Formality, LanguagePreference, ScriptPreference, SpokenLanguage
from intelligence.education.sources import EducationSource, SourceCategory, SourceType
from intelligence.education.teaching import CELESTE_TEACHER_ID, CelesteTeacher, LearnerRequest, LearningObjective, StudentLessonContext, SubjectContext, TeachingStyle


def test_structured_lesson_and_subject_switch_keeps_identity():
    teacher = CelesteTeacher()
    node = CurriculumNode("n1", Country.ENGLAND, EducationSystem.ENGLAND_NATIONAL_CURRICULUM, AwardingBody.AQA, Qualification.GCSE, KeyStage.KS4, "Mathematics", "8300", "2015", "Algebra", "Solve linear equations", "U1", "AO1", "src")
    source = EducationSource("src", "AQA 8300", "AQA", SourceType.SPECIFICATION, "Mathematics", "GCSE", "2015", SourceCategory.OFFICIAL_PUBLIC, "public", ("teach",), "AQA", "https://example.invalid/spec", date(2015, 1, 1), date(2027, 1, 1), True)
    start = StudentLessonContext("stu", "t1", "KS4", "standard", (TeachingStyle.STEP_BY_STEP,), LanguagePreference(SpokenLanguage.ENGLISH, SpokenLanguage.ENGLISH, ScriptPreference.LATIN, "standard", Formality.FRIENDLY), SubjectContext("Mathematics", "GCSE", "aqa", "8300"))
    switched = teacher.switch_subject(start, SubjectContext("English", "GCSE", "aqa", "8700"))
    assert teacher.profile.teacher_id == CELESTE_TEACHER_ID
    assert switched.subject.subject == "English"
    lesson = teacher.teach(start, LearningObjective("o1", "Solve linear equations"), node, source, LearnerRequest.SIMPLER)
    assert lesson.teacher_id == CELESTE_TEACHER_ID
    assert lesson.explanation.method and lesson.provenance and lesson.practice.prompt
    assert "Easier version" in lesson.answer
