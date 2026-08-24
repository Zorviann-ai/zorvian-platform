# Zorvian Australian Education Tutor

## Scope

Production target: all school students across Australia, with no age restriction. The platform covers Foundation/Kindergarten through Year 12 and routes learning by state/territory, school year/stage, subject and senior-secondary pathway where applicable.

## Core behaviour

1. Identify state or territory.
2. Identify school year/stage or learning level.
3. Identify subject, course and topic.
4. Retrieve the relevant approved curriculum or senior-secondary syllabus context.
5. Answer at the student's actual learning level rather than assuming ability from age.
6. Explain the method, not just the final answer.
7. Offer a simpler explanation, worked example, hint, quiz, revision or exam-style practice.
8. Keep parent/teacher reporting separate from the student experience.

## Curriculum source hierarchy

- Australian Curriculum Version 9.0 (ACARA) is the national baseline for Foundation-Year 10.
- Senior secondary routes use the relevant state/territory curriculum and assessment authority, course or certificate framework for Years 11-12.
- State and territory curriculum authorities override or contextualise where their implementation differs.
- NSW routes through NESA syllabuses and stages from Kindergarten through Year 12, including Stage 6.
- Victoria routes through Victorian Curriculum F-10 and VCAA senior-secondary study designs/pathways.
- Queensland, Western Australia, South Australia, Tasmania, ACT and Northern Territory each have their own authority/implementation registry entries, including senior-secondary pathways.

## Learning coverage

The platform is not restricted to eight primary learning areas. It must support the full subject and course catalogue offered by each Australian jurisdiction, including English, Mathematics, Science, Humanities and Social Sciences, Health and Physical Education, The Arts, Technologies, Languages, VET and senior-secondary specialist/elective courses.

## Required production services

- Curriculum and syllabus ingestion service
- Senior-secondary course/study-design ingestion
- Source versioning and update checker
- Search/retrieval index by jurisdiction, year/stage, subject/course, strand, outcome and achievement standard
- Zorvian Core education endpoint
- Student-safe response policy
- Parent progress dashboard
- Question/session history with privacy controls
- Teacher/admin curriculum audit view
- Revision, assessment and exam-practice mode

## Response contract

Every tutor response should internally carry:

- jurisdiction
- curriculum/syllabus source and version
- year/stage/learning level
- subject/course
- topic/strand/outcome
- source references used
- response difficulty
- confidence

If curriculum context cannot be verified, the tutor must say so internally and use the appropriate verified national or jurisdictional fallback rather than inventing a syllabus requirement.

## UI

Bright white page. Rainbow accent colours used for controls and subject cards. Large readable typography, rounded controls and minimal clutter. Student-facing controls include Explain simply, Worked example, Give me a hint, Quiz me, Revision, Exam practice and Ask Tutor. The interface adapts to primary, secondary and senior-secondary students without imposing an age label.

## Coverage principle

No Australian student is excluded because of age, school sector or location. The jurisdiction selector covers every Australian state and territory, while the curriculum layer is designed to support government, Catholic, independent, distance and home-education users wherever they follow recognised Australian curriculum or senior-secondary requirements.

## Next build layer

The current repository contains the curriculum registry and front-end portal. The next implementation layer is the live education API and curriculum/syllabus ingestion and indexing pipeline, followed by full source loading and automated curriculum-version checks across Foundation/Kindergarten-Year 12.
