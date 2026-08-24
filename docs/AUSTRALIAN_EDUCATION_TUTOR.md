# Zorvian Australian Education Tutor

## Scope

Initial production target: children aged 6–12 across Australia, with curriculum routing by state/territory, school year/stage and subject.

## Core behaviour

1. Identify state or territory.
2. Identify school year/stage.
3. Identify subject and topic.
4. Retrieve the relevant approved curriculum context.
5. Answer at the child's learning level.
6. Explain the method, not just the final answer.
7. Offer a simpler explanation, worked example, hint or quiz.
8. Keep parent/teacher reporting separate from the child experience.

## Curriculum source hierarchy

- Australian Curriculum Version 9.0 (ACARA) is the national baseline.
- State and territory curriculum authorities override or contextualise where their implementation differs.
- NSW routes through NESA syllabuses and stages.
- Victoria routes through Victorian Curriculum achievement levels and learning continuum.
- Queensland, WA, SA, Tasmania, ACT and NT each have their own authority/implementation registry entries.

## Learning areas

English; Mathematics; Science; Health and Physical Education; Humanities and Social Sciences; The Arts; Technologies; Languages.

## Required production services

- Curriculum ingestion service
- Source versioning and update checker
- Search/retrieval index by jurisdiction, year, subject, strand and achievement standard
- Zorvian Core education endpoint
- Child-safe response policy
- Parent progress dashboard
- Question/session history with privacy controls
- Teacher/admin curriculum audit view

## Response contract

Every tutor response should internally carry:

- jurisdiction
- curriculum source/version
- year/stage
- subject
- topic/strand
- source references used
- response difficulty
- confidence

If curriculum context cannot be verified, the tutor must say so internally and fall back to the Australian Curriculum baseline rather than inventing a syllabus requirement.

## UI

Bright white page. Rainbow accent colours used for controls and subject cards. Large readable typography, rounded controls and minimal clutter. Child-facing controls include Explain simply, Worked example, Give me a hint, Quiz me and Ask Tutor.

## Next build layer

The current repository contains the curriculum registry and front-end portal. The next implementation layer is the live education API and curriculum ingestion/indexing pipeline, followed by full source loading and automated curriculum-version checks.
