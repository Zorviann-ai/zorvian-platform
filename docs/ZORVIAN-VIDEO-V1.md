# Zorvian Video v1

## Product goal

Zorvian Video is a first-class AI video workspace inside the Zorvian platform. Users describe an outcome; Zorvian plans, generates, assembles and stores an editable video project. The product must remain model-provider independent.

## v1 product promise

1. Prompt to a persistent video project.
2. AI-generated storyboard containing 1-12 scenes.
3. Each scene is generated independently.
4. A provider router selects the best eligible generation provider.
5. Failed scene jobs can retry or route to another provider without restarting the project.
6. Actual and estimated costs are recorded at job level.
7. Scenes can be regenerated individually.
8. A final render joins successful scenes into an MP4.
9. Failed provider generations should not be billed to the user's Zorvian credit balance.

## Architecture

```text
/video UI
   |
Zorvian Worker API
   |
Video Orchestrator
   |---- Storyboard planner (Workers AI)
   |---- Provider router
   |---- Cost estimator
   |---- Job state machine
   |
Generation queue
   |---- Provider adapter A
   |---- Provider adapter B
   |---- future Zorvian-hosted model
   |
Asset storage
   |
Render worker / FFmpeg service
   |
Persistent Zorvian Video Project
```

The Zorvian application must call internal provider interfaces rather than vendor-specific APIs directly from routes or UI code.

## Core data model

`video_projects` is the durable project record. `video_scenes` represents the editable storyboard/timeline. `video_jobs` records every generation attempt and its cost. `video_assets` stores references to source/generated media. `video_renders` records assembled outputs.

All records are tenant scoped through the parent project. Provider request/response details belong in jobs so routing and pricing can be audited later.

## Job lifecycle

```text
queued -> running -> succeeded
                  -> failed -> retrying -> running
                           -> exhausted
```

Project lifecycle:

```text
draft -> planning -> ready -> generating -> assembling -> complete
                          \-> failed
```

A scene failure must not mark an entire project failed while an automatic retry remains available.

## Provider abstraction

Each provider adapter should implement the logical contract below, regardless of vendor API shape.

```js
{
  key,
  capabilities,
  estimate(request),
  submit(request),
  status(providerJobId),
  cancel(providerJobId),
  normalizeResult(result)
}
```

Initial capabilities:

- `text_to_video`
- `image_to_video`
- `presenter`
- `render`

The router receives capability, user preference (`balanced`, `quality`, `cost`, `speed`), estimated price, reliability, latency and quality scores. No UI component should depend on provider names.

## API surface for first implementation

```text
POST /api/video/projects
GET  /api/video/projects
GET  /api/video/projects/:id
POST /api/video/projects/:id/plan
POST /api/video/projects/:id/generate
POST /api/video/projects/:id/scenes/:sceneId/regenerate
GET  /api/video/projects/:id/jobs
POST /api/video/projects/:id/render
```

Every endpoint requires the existing Zorvian session and must verify the project's `tenant_id` matches the authenticated user.

## First vertical slice

The first working milestone is intentionally narrow:

1. User enters a prompt and target duration.
2. API creates a project.
3. Workers AI produces a structured storyboard.
4. Storyboard is persisted as scenes.
5. A mock provider adapter accepts generation jobs and exercises routing/state transitions without spending external credits.
6. The UI displays the project and scene statuses.
7. Cost accounting is visible in the project record.

After that works end-to-end, connect two real video providers behind the same adapter contract.

## Next capabilities

After the vertical slice: R2 asset storage, Cloudflare Queues, webhooks/polling for provider completion, scene preview assets, FFmpeg render service, narration/voice, captions, music, image-to-video, presenters, brand kits, reusable identities, and automated quality scoring.

## Non-negotiable engineering rules

- Never hardwire the product to one video vendor.
- Never expose provider secrets to browser code.
- Record provider cost per attempt.
- Keep generation asynchronous.
- Preserve successful scenes when another scene fails.
- Make retries idempotent where possible.
- Tenant-scope every query.
- Do not charge user credits for a failed provider attempt unless an upstream provider has actually incurred a non-refundable cost and product policy explicitly allows it.
